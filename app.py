from threading import Thread

from flask_cors import CORS
from flask_restful import Api, Resource
from flask import Flask, current_app
from database import db, Systems
from modules.auth import Login, Register, Logout, ResetPassword, AuthUser, login_manager
from modules.system import System, Sock
from modules.activity import Activity

app = Flask(__name__)
app.config.from_pyfile('config.py')
api = Api(app)
cors = CORS(app, supports_credentials=True)


def start_binding():
    with app.app_context():
        s_queue = Systems.query.filter(Systems.enable_mon == 'true', Systems.ip_addr != 'null').all()
        for s in s_queue:
            Thread(target=Sock(s).run, kwargs={'app': current_app._get_current_object()}, name=s.sys_id).start()


with app.app_context():
    login_manager.init_app(app)
    db.init_app(app)
    db.create_all()
    Thread(target=start_binding, name='websocks').start()


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

# Activity
api.add_resource(Activity, '/api/system/activity')

if __name__ == "__main__":
    try:
        app.run('0.0.0.0', port=5000, debug=True)
    except Exception as e:
        print(e)
        db.session.rollback()
