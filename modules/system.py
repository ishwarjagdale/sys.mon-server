import os
import time
from concurrent.futures import ThreadPoolExecutor

from flask import current_app
from flask_login import current_user
from flask_restful import Resource, reqparse, output_json, abort, request
from sqlalchemy.exc import SQLAlchemyError
from websocket import WebSocketApp

from database import Systems, ActivityLogs, db
from modules.auth import login_required
from modules.smtp_email import send_mail

connection_pool = dict()
exe = ThreadPoolExecutor()


class Sock:
    def __init__(self):
        self.app = None
        self.re_conn = False
        self.system = None
        self.ws = None

    def run(self, system=None, app=None):
        self.system = system if system else self.system
        self.app = app if app else self.app

        if self.system and self.app:
            with self.app.app_context():
                self.ws = WebSocketApp(f"ws://{self.system.ip_addr}",
                                       on_open=self.on_open,
                                       on_close=self.alert_user if self.re_conn else self.on_close,
                                       on_error=self.on_error,
                                       keep_running=True)
                self.ws.run_forever()

    def on_open(self, *args):
        print(f'[ WEBSOCK < {self.system.ip_addr} >: OPEN ]', self.system.name)
        self.re_conn = False

    def on_close(self, *args):
        print(f'[ WEBSOCK < {self.system.ip_addr} >: RECONNECTING ]', self.system.name)
        time.sleep(10)
        query = ActivityLogs.query.filter(ActivityLogs.system_id == self.system.sys_id) \
            .order_by(db.desc(ActivityLogs.date_happened)).first()
        if query and query.type in ["SHUTDOWN", "DOWN"]:
            print(f'[ WEBSOCK < {self.system.ip_addr} >: DESTRUCT ]', self.system.name)
            self.destruct()
        else:
            system = Systems.get_system(sys_id=self.system.sys_id, v_token=self.system.verification_token)
            if system and system.enable_mon:
                self.re_conn = True
                self.run(system)

    def on_error(self, *args):
        print(f'[ WEBSOCK < {self.system.ip_addr} >: ERROR ]', self.system.name)

    def alert_user(self, ws, close_status_code, close_msg):
        if os.environ["FLASK_ENV"] == "development":
            print(f"SYSTEM DOWN | {self.system.name} | {close_status_code} | {close_msg}")
            return True
        query = ActivityLogs.query.filter(ActivityLogs.system_id == self.system.sys_id) \
            .order_by(db.desc(ActivityLogs.date_happened)).first()
        if query and query.type not in ["SHUTDOWN", "DOWN"]:
            ActivityLogs.new(self.system.sys_id, "DOWN",
                             "can't connect to the system, reason unknown", "system unreachable")
        send_mail(to=self.system.user.email_addr, subject='SYSTEM DOWN!', message=f"""
        {close_status_code}: {close_msg}
        """)

        self.destruct()

    def destruct(self):
        try:
            self.ws.close()
        except Exception as e:
            print(e)
        connection_pool.pop(self.system.sys_id)


class System(Resource):
    get_sys = reqparse.RequestParser()
    get_sys.add_argument('sys_id', type=str, required=False, help="missing system id")

    post_sys = reqparse.RequestParser()
    post_sys.add_argument('sys_name', type=str, required=True, help="missing system name")
    post_sys.add_argument('os', type=str, required=True, help="missing os")

    patch_sys = reqparse.RequestParser()
    patch_sys.add_argument('v_token', type=str, required=True, help="missing verification token")
    patch_sys.add_argument('sys_id', type=str, required=True, help="missing sys_id")
    patch_sys.add_argument('port', type=int, required=True, help="missing port number")

    put_sys = reqparse.RequestParser()
    put_sys.add_argument('sys_id', type=str, required=True, help="missing system id")
    put_sys.add_argument('payload', type=dict, required=True, help="missing update values")

    @login_required
    def get(self):
        if 'id' in request.args:
            system = Systems.get_system(sys_id=request.args['id'], user_id=current_user.user_id)
            if system:
                print(f"{current_user.email_addr} system: ", system)
                return output_json(system.to_dict(), 200)
            return abort(404, message="system not found")
        systems = Systems.get_systems(current_user.user_id)
        print(f"{current_user.email_addr} system: ", systems)
        return output_json(systems, 200)

    @login_required
    def post(self):
        args = System.post_sys.parse_args()
        try:
            system = Systems.add_system(name=args['sys_name'], os=args['os'],
                                        user_id=current_user.user_id)
        except SQLAlchemyError as e:
            return abort(400, message=str(e))
        if system:
            temp = system.to_dict()
            temp['v_token'] = system.verification_token
            return output_json(temp, 200)
        return abort(400, message="something went wrong")

    @login_required
    def put(self):
        args = self.put_sys.parse_args()
        system = Systems.get_system(args['sys_id'], user_id=current_user.user_id)
        if system:
            payload = args['payload']
            if 'enable_mon' in payload:
                system.enable_mon = bool(payload['enable_mon'])
            if 'alert' in payload:
                system.alert = bool(payload['alert'])
            if 'name' in payload:
                system.name = payload['name']
            db.session.commit()
            return output_json(system.to_dict(), 200)
        return 404

    def patch(self):
        args = self.patch_sys.parse_args()
        print(args)
        sys_id, v_token = args['sys_id'], args['v_token']
        addr = request.environ['HTTP_X_FORWARDED_FOR'] if 'HTTP_X_FORWARDED_FOR' in request.environ else \
            request.environ['REMOTE_ADDR']
        port = args['port']
        system = Systems.get_system(sys_id=sys_id, v_token=v_token)
        system.ip_addr = f"{addr}:{port}"
        print(addr, port)
        db.session.commit()
        ActivityLogs.new(system.sys_id, "PATCH", "mon's ip address changed", "mon restarted!")

        if system.sys_id not in connection_pool:
            exe.submit(Sock().run, system, current_app._get_current_object())

        return 200

    @login_required
    def delete(self):
        if 'id' in request.args:
            system = Systems.get_system(sys_id=request.args['id'], user_id=current_user.user_id)
            if system:
                db.session.delete(system)
                db.session.commit()
                return 200
            return 404
        return 400
