from threading import Thread

from flask import Flask, current_app
from flask_cors import CORS
from flask_restful import Api, Resource

from database import db, Systems
from modules.activity import ActivityView
from modules.auth import Login, Register, Logout, ResetPassword, AuthUser, login_manager, UserUpdates
from modules.system import SystemView
from modules.rules import RulesView
from modules.monView import MonView
from sock_pool import runner

app = Flask(__name__)
app.config.from_pyfile('config.py')
api = Api(app)
cors = CORS(app, supports_credentials=True)

with app.app_context():
    login_manager.init_app(app)
    db.init_app(app)
    db.create_all()
    runner.init_app(app)


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
api.add_resource(SystemView, '/api/system')

# User
api.add_resource(UserUpdates, '/api/user')

# Activity
api.add_resource(ActivityView, '/api/system/activity')

# Rules
api.add_resource(RulesView, '/api/system/rules')

# Mon
api.add_resource(MonView, '/api/system/mon')

if __name__ == "__main__":
    try:
        app.run('0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(e)
        db.session.rollback()
