from flask_restful import Resource, reqparse
from database import ActivityLogs, Systems


class Activity(Resource):
    post_args = reqparse.RequestParser()
    post_args.add_argument('sys_id', type=str, required=True, help="sys_id: system id missing")
    post_args.add_argument('v_token', type=str, required=True, help="v_token: verification token missing")
    post_args.add_argument('activity', type=str, required=True, action='append',
                           help="activity: [type, description, message] missing")

    def post(self):
        args = self.post_args.parse_args()
        system = Systems.get_system(sys_id=args['sys_id'], v_token=args['v_token'])
        if system:
            print(*args['activity'])
            act_type, description, message = args['activity']
            ActivityLogs.new(system.sys_id, act_type, description, message)
            return 200
        return 404
