from flask import Flask
from flask_cors import CORS
from flask_restful import Api, Resource

from database import db, Systems
from modules.auth import Login, Register, Logout, ResetPassword, AuthUser, login_manager
from modules.system import System

app = Flask(__name__)
app.config.from_pyfile('config.py')
api = Api(app)
cors = CORS(app, supports_credentials=True)

with app.app_context():
    login_manager.init_app(app)
    db.init_app(app)
    db.create_all()

    # s_queue = Systems.query.filter(enable_mon=True, Systems.ip_addr.not_(None)).all()


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
        app.run('0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(e)
        db.session.rollback()
