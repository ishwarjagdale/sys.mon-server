import time
from modules.email import send_mail
from flask import current_app
from flask_login import current_user
from flask_restful import Resource, reqparse, output_json, abort, request
from sqlalchemy.exc import SQLAlchemyError
from websocket import WebSocketApp
from threading import Thread
from database import Systems, ActivityLogs, db
from modules.auth import login_required

conns = dict()


class Sock:
    def __init__(self, system=None):
        self.re_conn = False
        self.app = None
        self.system = system
        self.ws = None
        self.conn()

    def conn(self, system=None):
        if system:
            self.system = system
        if self.system:
            self.ws = WebSocketApp(f"wss://{self.system.ip_addr}",
                                   on_open=self.on_open,
                                   on_close=self.on_close if not self.re_conn else self.alert_user,
                                   on_error=lambda wes, err: print(wes, err), keep_running=True)

    def run(self, **kwargs):
        if 'app' in kwargs:
            self.app = kwargs['app']
        self.ws.run_forever()

    def on_open(self, ws):
        self.re_conn = False
        print(f'[ WEBSOCK < {self.system.ip_addr} >: OPEN ]', self.system.name)
        conns[f"{self.system.sys_id}"] = self

    def on_close(self, ws, close_status_code, close_msg):
        print(f'[ WEBSOCK < {self.system.ip_addr} >: CLOSED ]', self.system.name, "reconnecting after 10 sec...")
        time.sleep(10)
        with self.app.app_context():
            query = ActivityLogs.query.filter(ActivityLogs.system_id == self.system.sys_id) \
                .order_by(db.desc(ActivityLogs.date_happened)).first()

            if query and query.type in ["SHUTDOWN", "DOWN"]:
                if self.system.sys_id in conns:
                    conns.pop(self.system.sys_id)
            else:
                system = Systems.get_system(sys_id=self.system.sys_id, v_token=self.system.verification_token)
                if system and system.enable_mon:
                    self.re_conn = True
                    self.conn(system)
                    self.run()

    def on_error(self):
        pass

    def alert_user(self, ws, close_status_code, close_msg):
        with self.app.app_context():
            query = ActivityLogs.query.filter(ActivityLogs.system_id == self.system.sys_id) \
                .order_by(db.desc(ActivityLogs.date_happened)).first()
            if query and query.type not in ["SHUTDOWN", "DOWN"]:
                ActivityLogs.new(self.system.sys_id, "DOWN",
                                 "can't connect to the system, reason unknown", "system unreachable")
            send_mail(to=self.system.user.email_addr, subject='SYSTEM DOWN!', message=f"""
            {close_status_code}: {close_msg}
            """)
            conns.pop(self.system.sys_id)
            print("need attention", self.system.name)


# async def connect(system, recur=True):
#     try:
#         ws = Sock(system)
#         Thread(target=ws.run).start()
#         print('hi')
#         app.config['conns'][system.sys_id] = ws
#     except ConnectionError or ConnectionRefusedError or Exception as e:
#         print(e)
#         if recur:
#             print('sleeping for 10 sec')
#             time.sleep(10)
#             system = Systems.query.filter(Systems.sys_id == system.sys_id).first()
#             await connect(system, recur=False)
#         else:
#             print("I'm gonna tell ur owner 😑")
#
#             print(ActivityLogs.query.filter(ActivityLogs.system_id == system.sys_id).order_by(
#                 db.desc(ActivityLogs.date_happened)).first())
#             # send_mail(to=Users.query.filter(Users.user_id == system.user_id).first().email_addr,
#             #           subject="system down!",
#             #           message=f"Following System have gone boom boom\n{json.dumps(system.to_dict(), indent=4)}")


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

    # @staticmethod
    # def get_user():
    #     return session.get(request.cookies.get('token'))

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

    @staticmethod
    def patch():
        args = System.patch_sys.parse_args()
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

        if system.sys_id not in conns:
            Thread(target=Sock(system).run, kwargs={'app': current_app._get_current_object()}).start()

        return 200
