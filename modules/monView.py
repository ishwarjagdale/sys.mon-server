import datetime
from flask_restful import Resource, reqparse, request, output_json, abort
from database import Systems, db, ActivityLogs, Rules, Users
from flask import current_app
from modules.smtp_email import send_mail
from sock_pool import connections, runner


class MonView(Resource):
    patch_sys = reqparse.RequestParser()
    patch_sys.add_argument('v_token', type=str, required=True, help="missing verification token")
    patch_sys.add_argument('sys_id', type=str, required=True, help="missing sys_id")
    patch_sys.add_argument('port', type=int, required=True, help="missing port number")

    post_sys = reqparse.RequestParser()
    post_sys.add_argument('v_token', type=str, required=True, help="missing verification token")
    post_sys.add_argument('sys_id', type=str, required=True, help="missing sys_id")
    post_sys.add_argument('report', type=dict, required=True, help="missing report")

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

    def post(self):
        args = self.post_sys.parse_args()
        system = Systems.get_system(sys_id=args['sys_id'], v_token=args['v_token'])
        if system:
            query = ActivityLogs.query.join(Systems).filter(ActivityLogs.system_id == Systems.sys_id) \
                .order_by(db.desc(ActivityLogs.date_happened)).first()
            if query:
                print(query.type, query.message)
                if query.type == "RULE_VIOLATE":
                    if args['report']['activity']['resource'] in query.message:
                        print((datetime.datetime.now() - query.date_happened).total_seconds())
                        if (datetime.datetime.now() - query.date_happened).total_seconds() < 3600:
                            return 200

            ActivityLogs.new(system.sys_id, act_type="RULE_VIOLATE", desc=str(args['report']['stats']),
                             message=args['report']['activity']['message'])
            if system.alert:
                user = Users.get_user(user_id=system.user_id)
                send_mail(to=user.email_addr,
                          subject=f"{system.name} crossed {args['report']['activity']['resource']} rule",
                          message=f"{args['report']['activity']['message']}\n{str(args['report']['stats'])}"
                          )

            return 200
        return abort(404, message="system not found")

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

        if system.sys_id not in connections:
            runner.add_system(system, current_app._get_current_object())

        return 200
