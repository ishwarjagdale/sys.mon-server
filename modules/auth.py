import hashlib
from datetime import datetime

from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_restful import Resource, reqparse, abort, output_json
from modules.smtp_email import send_mail
from database import Users, db, VerificationTokens


login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    return Users.get_user(user_id=user_id)


class Login(Resource):
    login_args = reqparse.RequestParser(bundle_errors=True)
    login_args.add_argument('email', type=str, required=True, help="missing email")
    login_args.add_argument('password', type=str, required=True, help="missing password")

    @login_required
    def get(self):
        return output_json(current_user.to_dict(), 200)

    def post(self):
        args = self.login_args.parse_args()
        print(args)
        email = args['email']
        password = args['password']

        user = Users.get_user(email)
        if not user:
            return abort(404, message="user doesn't exist")

        if user.check_password(password):
            if user.is_authenticated:
                if login_user(user):
                    return output_json(user.to_dict(), 200)
                return abort(400, message="something went wrong")
            return abort(403, message="needs authentication")
        else:
            return abort(401, message="invalid credentials")


class Register(Resource):
    register_args = reqparse.RequestParser(bundle_errors=True)
    register_args.add_argument('name', type=str, required=True, help="missing name")
    register_args.add_argument('email', type=str, required=True, help="missing email")
    register_args.add_argument('password', type=str, required=True, help="missing password")

    def post(self):
        args = self.register_args.parse_args()
        name = args['name']
        email = args['email']
        password = args['password']

        if Users.get_user(email):
            return abort(409, message="user exists")
        d_now = datetime.now()
        user = Users(name=name, email_addr=email,
                     password=hashlib.sha256(
                         bytes(str(d_now.timestamp()).replace(".", password), encoding='utf-8')).hexdigest(),
                     date_created=d_now)
        db.session.add(user)
        db.session.commit()

        user = Users.get_user(user.email_addr)
        if user:
            tkn = VerificationTokens.new(user_id=user.user_id, cat='auth')
            print(tkn)
            send_mail(user.email_addr, "Account Verification", str(tkn))
            return output_json(user.to_dict(), 200)
        return abort(400, status_code=400, message="Something went wrong")


class Logout(Resource):
    @login_required
    def get(self):
        logout_user()
        return 200


class ResetPassword(Resource):
    recover_args = reqparse.RequestParser(bundle_errors=True)
    recover_args.add_argument('email', type=str, required=False, help='missing email')
    recover_args.add_argument('token', type=str, required=False, help='missing token')
    recover_args.add_argument('password', type=str, required=False, help="missing password")

    def post(self):
        args = self.recover_args.parse_args(strict=True)
        print(args)
        if args['token']:
            tkn = VerificationTokens.get(args['token'])
            if tkn:
                if not tkn.used and tkn.cat == 'rcvr':
                    user = Users.get_user(user_id=tkn.user_id)
                    if user:
                        user.password = hashlib.sha256(bytes(str(user.date_created.timestamp()).
                                                             replace(".", args['password']), encoding='utf-8')). \
                            hexdigest()
                        db.session.commit()
                        tkn.consume()
                        send_mail(user.email_addr, "Password Changed!",
                                  f"Your sys.mon account password has been changed, if not done by you please "
                                  f"reply to this email.\nToken: {tkn.token}")
                        if login_user(user):
                            return output_json(user.to_dict(), 200)
                        return 200

            return abort(400, message='unauthorized request')

        else:
            email_addr = args['email']
            user = Users.get_user(email=email_addr)
            if user:
                tkn = VerificationTokens.new(user_id=user.user_id, cat='rcvr')
                send_mail(user.email_addr, "Reset Password",
                          f"https://sys-mon.pages.dev/forgot-password/{str(tkn['token'])}")
                print(tkn)
                return 200
            return abort(404, message='user not found')


class AuthUser(Resource):
    get_verification_args = reqparse.RequestParser(bundle_errors=True)
    get_verification_args.add_argument('email', type=str, required=True, help='missing email')

    verification_args = reqparse.RequestParser(bundle_errors=True)
    verification_args.add_argument('token', type=str, required=True, help='missing token')

    def get(self):
        args = self.get_verification_args.parse_args()
        user = Users.get_user(email=args['email'])
        if user:
            if not user.authenticated:
                tkn = VerificationTokens.new(user.user_id, cat="auth")
                send_mail(user.email_addr, "Account Verification", str(tkn))
                print(tkn)
                return 200
            return abort(400, message="user already authenticated")
        return abort(404, message="user not found")

    def post(self):
        args = self.verification_args.parse_args()
        print(args['token'])
        tkn = VerificationTokens.get(args['token'])
        if tkn.cat == 'auth' and not tkn.used:
            user = Users.get_user(user_id=tkn.user_id)
            if user:
                if user.authenticate():
                    tkn.consume()
                    if login_user(user):
                        return output_json({'message': 'authentication successful'}, 200)
                    return abort(500, message="Login failed")
                return abort(500, message="Authentication Failed")
        return abort(404, message="Invalid Request")
