from flask_restful import Resource, reqparse, request, output_json, abort
from database import ActivityLogs, Systems
from flask_login import login_required, current_user


class ActivityView(Resource):
    post_args = reqparse.RequestParser()
    post_args.add_argument('sys_id', type=str, required=True, help="sys_id: system id missing")
    post_args.add_argument('v_token', type=str, required=True, help="v_token: verification token missing")
    post_args.add_argument('activity', type=str, required=True, action='append',
                           help="activity: [type, description, message] missing")

    @login_required
    def get(self):
        if "id" in request.args:
            logs = ActivityLogs.get(user_id=current_user.user_id, sys_id=request.args["id"])
            if logs:
                return output_json({f"{request.args['id']}": logs}, 200)
        return abort(400, message="missing sys_id in arguments")

    def post(self):
        args = self.post_args.parse_args()
        system = Systems.get_system(sys_id=args['sys_id'], v_token=args['v_token'])
        if system:
            print(*args['activity'])
            act_type, description, message = args['activity']
            ActivityLogs.new(system.sys_id, act_type, description, message)
            return 200
        return abort(404, message="system not found")
