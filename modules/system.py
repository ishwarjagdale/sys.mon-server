from flask_login import current_user
from flask_restful import Resource, reqparse, output_json, abort, request
from sqlalchemy.exc import SQLAlchemyError

from database import Systems, db
from modules.auth import login_required


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
        addr = request.environ['HTTP_X_FORWARDED_FOR'] if 'HTTP_X_FORWARDED_FOR' in request.environ else request.environ['REMOTE_ADDR']
        port = args['port']
        system = Systems.get_system(sys_id=sys_id, v_token=v_token)
        system.ip_addr = f"{addr}:{port}"
        print(addr, port)
        db.session.commit()
        return 200
