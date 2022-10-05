import os

from flask import Flask
from flask_restful import Api, Resource
from database import db
from flask_cors import CORS
from flask_session import Session
from modules.auth import Login, Register, Logout, ResetPassword
from modules.system import System
from os import environ

app = Flask(__name__)
app.secret_key = environ['SECRET_KEY']
app.config["SESSION_TYPE"] = 'filesystem'
api = Api(app)
cors = CORS(app, supports_credentials=True)
Session(app)

with app.app_context():
    app.config.from_pyfile('config.py')
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

# System
api.add_resource(System, '/api/system')


if __name__ == "__main__":
    try:
        app.run('localhost', port=5000, debug=True)
    except Exception as e:
        print(e)
        db.session.rollback()
