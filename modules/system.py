from flask_login import current_user
from flask_restful import Resource, reqparse, output_json, abort, request
from sqlalchemy.exc import SQLAlchemyError

from database import Systems, db
from modules.auth import login_required


class SystemView(Resource):
    get_sys = reqparse.RequestParser()
    get_sys.add_argument('sys_id', type=str, required=False, help="missing system id")

    post_sys = reqparse.RequestParser()
    post_sys.add_argument('sys_name', type=str, required=True, help="missing system name")
    post_sys.add_argument('os', type=str, required=True, help="missing os")

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
        args = SystemView.post_sys.parse_args()
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
