import hashlib
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session
from flask_restful import Resource, reqparse, abort, output_json, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from database import Users, db

login_args = reqparse.RequestParser(bundle_errors=True)
login_args.add_argument('email', type=str, required=True, help="missing email")
login_args.add_argument('password', type=str, required=True, help="missing password")

register_args = reqparse.RequestParser(bundle_errors=True)
register_args.add_argument('name', type=str, required=True, help="missing name")
register_args.add_argument('email', type=str, required=True, help="missing email")
register_args.add_argument('password', type=str, required=True, help="missing password")

login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    return Users.get_user(user_id=user_id)


#
# class Authorized:
#     def __init__(self):
#         self.session = dict()


# def login_required(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         token = request.cookies.get('token')
#         print("Found token", token, end=' ')
#         if token:
#             curr = session[token]
#             print(curr)
#             if curr and datetime.now(tz=timezone.utc) < curr['expires']:
#                 return func(*args, **kwargs)
#
#         abort(401, message="Unauthorized Access")
#
#     return wrapper


class Login(Resource):

    @login_required
    def get(self):
        # user_session = session[request.cookies.get('token')]
        # print("Log in check :", user_session)
        # if user_session:
        #     user = Users.get_user(user_id=user_session['user_id'])
        #     return output_json(user.to_dict(), 200)
        # return abort(401, message="Unauthorized Access")
        return output_json(current_user.to_dict(), 200)

    # @staticmethod
    # def generate_session(user):
    #     res = output_json(user.to_dict(), 200)
    #     token = user.generate_token()
    #     res.set_cookie('token', token, httponly=True, secure=True, samesite="None", max_age=3600 * 24)
    #     session[token] = {"user_id": user.user_id, "user": user.email_addr,
    #                       "expires": datetime.now(tz=timezone.utc) + timedelta(1)}
    #     print(session.__dict__)
    #     return res

    def post(self):
        args = login_args.parse_args()
        print(args)
        email = args['email']
        password = args['password']

        user = Users.get_user(email)
        if not user:
            return abort(404, message="user doesn't exist")

        if user.check_password(password):
            # return self.generate_session(user)
            login_user(user, remember=True)
            return output_json(user.to_dict(), 200)
        else:
            return abort(401, message="invalid credentials")


class Register(Resource):
    @staticmethod
    def post():
        args = register_args.parse_args()
        name = args['name']
        email = args['email']
        password = args['password']

        if Users.get_user(email):
            return abort(409, message="user exists")
        d_now = datetime.now()
        user = Users(name=name, email_addr=email,
                     password=hashlib.sha256(
                         bytes(str(d_now.timestamp()).replace(".", password), encoding='utf-8')
                     ).hexdigest(),
                     date_created=d_now)
        db.session.add(user)
        db.session.commit()

        if Users.get_user(user.email_addr):
            # return Login.generate_session(user)
            login_user(user, remember=True)
            return output_json(user.to_dict(), 200)
        return abort(400, status_code=400, message="Something went wrong")


class Logout(Resource):
    @login_required
    def get(self):
        # session.pop(request.cookies.get('token'))
        # print(session)
        # res = output_json({"message": "logged out"}, 200)
        # res.delete_cookie('token')
        logout_user()
        return 200


class ResetPassword(Resource):
    @staticmethod
    def get():
        return 200
