from flask_restful import Resource, reqparse, request, output_json, abort
from database import Systems, db, ActivityLogs, Rules
from flask import current_app
from modules.system import connection_pool, exe, Sock


class MonView(Resource):
    patch_sys = reqparse.RequestParser()
    patch_sys.add_argument('v_token', type=str, required=True, help="missing verification token")
    patch_sys.add_argument('sys_id', type=str, required=True, help="missing sys_id")
    patch_sys.add_argument('port', type=int, required=True, help="missing port number")

    get_sys = reqparse.RequestParser()
    get_sys.add_argument('v_token', type=str, required=True, help="missing verification token")
    get_sys.add_argument('sys_id', type=str, required=True, help="missing sys_id")

    def get(self):
        args = self.get_sys.parse_args()
        system = Systems.get_system(sys_id=args['sys_id'], v_token=args['v_token'])
        if system:
            rules = Rules.get(sys_id=system.sys_id)
            system = system.to_dict()
            system['rules'] = rules
            return output_json(system, 200)
        return abort(400, message="system not found")

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