import hashlib
import json
from functools import wraps
from flask import make_response, request
from flask_restful import Resource, reqparse, abort
from datetime import datetime, timedelta
from database import Users, db

login_args = reqparse.RequestParser(bundle_errors=True)
login_args.add_argument('email', type=str, required=True, help="missing email")
login_args.add_argument('password', type=str, required=True, help="missing password")

register_args = reqparse.RequestParser(bundle_errors=True)
register_args.add_argument('name', type=str, required=True, help="missing name")
register_args.add_argument('email', type=str, required=True, help="missing email")
register_args.add_argument('password', type=str, required=True, help="missing password")


class Authorized:
    def __init__(self):
        self.session = dict()


authorized = Authorized()


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        print("Found token", token)
        if token:
            print("FIRST HERE")
            curr = authorized.session.get(token)
            print(curr, "SECOND HERE")
            if curr and datetime.now() < curr['expires']:
                print("GOT HERE")
                return func(*args, **kwargs)

        abort(401, message="Unauthorized Access")
    return wrapper


class Login(Resource):

    @staticmethod
    def generate_session(user):
        res = make_response(json.dumps({"message": "success"}), 200)
        token = user.generate_token()
        res.set_cookie('token', token, httponly=True, secure=True, samesite="None", max_age=3600 * 24)
        authorized.session[token] = {"user": user.email_addr, "expires": datetime.now() + timedelta(1)}
        print(*authorized.session.items())
        return res

    def post(self):
        args = login_args.parse_args()
        email = args['email']
        password = args['password']

        user = Users.get_user(email)
        if not user:
            return abort(404, message="user doesn't exist")

        if user.check_password(password):
            return self.generate_session(user)
        return 401


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
            return Login.generate_session(user)
        return abort(400, status_code=400, message="Something went wrong")


class Logout(Resource):
    @login_required
    def get(self):
        authorized.session.pop(request.cookies.get('token'))
        res = make_response(json.dumps({"message": "logged out"}), 200)
        res.delete_cookie('token')
        return res


class ResetPassword(Resource):
    def get(self):
        return 200
