from websocket import _exceptions
from flask_restful import Resource, request, output_json, abort, reqparse
from flask_login import login_required, current_user
from database import Rules, Systems, db
from modules.system import connection_pool


class RulesView(Resource):
    post_args = reqparse.RequestParser()
    post_args.add_argument('sys_id', required=True, type=str, help="missing sys_id")
    post_args.add_argument('resource', required=True, type=str, help="missing resource")
    post_args.add_argument('max_limit', required=True, type=int, help="missing max_limit")
    post_args.add_argument('percent', required=True, type=bool, help="missing percent")

    @login_required
    def get(self):
        if 'id' in request.args:
            print(request.args['id'])
            rules = Rules.get(sys_id=request.args['id'])
            return output_json(rules, 200)
        return abort(400, message='missing id in arguments')

    @login_required
    def post(self):
        args = self.post_args.parse_args()
        system = Systems.get_system(sys_id=args['sys_id'], user_id=current_user.user_id)
        if system:
            Rules.new(sys_id=args['sys_id'], resource=args['resource'], max_limit=args['max_limit'],
                      percent=args['percent'])
            rules = Rules.get(sys_id=args['sys_id'])
            try:
                if system.sys_id in connection_pool:
                    ws = connection_pool[system.sys_id].ws
                    if ws:
                        ws.send('update_mon')
            except _exceptions.WebSocketException as e:
                print(system.sys_id, e)
            return output_json(rules, 200)
        return abort(404, message="system not found")

    @login_required
    def delete(self):
        print(request.args)
        if 'id' in request.args and 'resource' in request.args:

            system = Systems.get_system(sys_id=request.args['id'], user_id=current_user.user_id)
            if system:
                rule = Rules.get(sys_id=request.args['id'], resource=request.args['resource'])
                if rule:
                    db.session.delete(rule)
                    db.session.commit()
                    rules = Rules.get(sys_id=request.args['id'])
                    try:
                        if system.sys_id in connection_pool:
                            ws = connection_pool[system.sys_id].ws
                            if ws:
                                ws.send('update_mon')
                    except websockets.exceptions.WebSocketException as e:
                        print(system.sys_id, e)
                    return output_json(rules, 200)
                return abort(404, message="rule doesn't exist")
            return abort(404, message="system not found")
        return abort(400, message="missing id or resource in arguments")
