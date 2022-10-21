import smtplib

from flask import Flask
from flask_cors import CORS
from flask_restful import Api, Resource

from database import db
from modules.auth import Login, Register, Logout, ResetPassword, AuthUser, login_manager
from modules.system import System
from modules.email import server

app = Flask(__name__)
app.config.from_pyfile('config.py')
api = Api(app)
cors = CORS(app, supports_credentials=True)

with app.app_context():
    print(app.config.get("SMTP_USER"), app.config.get('SMTP_PASSWORD'))
    try:
        if server.login(user=app.config.get("SMTP_USER"), password=app.config.get('SMTP_PASSWORD')) == 235:
            print('SMTP SERVER SET UP SUCCESSFUL')
    except smtplib.SMTPAuthenticationError or TimeoutError as e:
        print('SMTP SERVER SET UP FAILED :: ', e)
    login_manager.init_app(app)
    db.init_app(app)
    db.create_all()


class HelloWorld(Resource):
    @staticmethod
    def get():
        return {'hello': 'world'}


api.add_resource(HelloWorld, '/')

# Authentication
api.add_resource(Login, '/auth/login')
api.add_resource(Register, '/auth/get-started')
api.add_resource(Logout, '/auth/logout')
api.add_resource(ResetPassword, '/auth/reset-password')
api.add_resource(AuthUser, '/auth/verification')

# System
api.add_resource(System, '/api/system')

if __name__ == "__main__":
    try:
        app.run('localhost', port=5000, debug=True)
    except Exception as e:
        print(e)
        db.session.rollback()
