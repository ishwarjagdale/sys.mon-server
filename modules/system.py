from flask_login import current_user
from flask_restful import Resource, reqparse, output_json, abort
from sqlalchemy.exc import SQLAlchemyError

from database import Systems
from modules.auth import login_required


class System(Resource):
    get_sys = reqparse.RequestParser()
    get_sys.add_argument('sys_id', type=str, required=True, help="missing system id")

    post_sys = reqparse.RequestParser()
    post_sys.add_argument('sys_name', type=str, required=True, help="missing system name")
    post_sys.add_argument('ipv4', type=str, required=True, help="missing ip address")

    # @staticmethod
    # def get_user():
    #     return session.get(request.cookies.get('token'))

    @login_required
    def get(self):
        systems = Systems.get_systems(current_user.user_id)
        print(f"{current_user.email_addr} system: ", systems)
        return output_json(systems, 200)

    @login_required
    def post(self):
        args = System.post_sys.parse_args()
        try:
            system = Systems.add_system(args['sys_name'], args['ipv4'], current_user.user_id)
        except SQLAlchemyError as e:
            return abort(400, message=str(e))
        if system:
            return output_json(system.to_dict(), 200)
        return abort(400, message="something went wrong")
