from flask_restful import Resource, reqparse, request, output_json, abort
from flask import session
from modules.auth import login_required
from database import Systems
from sqlalchemy.exc import SQLAlchemyError


class System(Resource):
    get_sys = reqparse.RequestParser()
    get_sys.add_argument('sys_id', type=str, required=True, help="missing system id")

    post_sys = reqparse.RequestParser()
    post_sys.add_argument('sys_name', type=str, required=True, help="missing system name")
    post_sys.add_argument('ipv4', type=str, required=True, help="missing ip address")

    @staticmethod
    def get_user():
        return session.get(request.cookies.get('token'))

    @login_required
    def get(self):
        user = System.get_user()
        if not user:
            return abort(401, message="invalid session, need re-authentication")
        systems = Systems.get_systems(user['user_id'])
        print(f"{user['user']} system: ", systems)
        return output_json(systems, 200)

    @login_required
    def post(self):
        args = System.post_sys.parse_args()
        user = System.get_user()
        try:
            system = Systems.add_system(args['sys_name'], args['ipv4'], user['user_id'])
        except SQLAlchemyError as e:
            return abort(400, message=str(e))
        if system:
            return output_json(system.to_dict(), 200)
        return abort(400, message="something went wrong")
