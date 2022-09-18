from flask import Flask
from flask_restful import Api, Resource
from database import db
from flask_cors import CORS
from auth.auth import Login, Register, Logout, ResetPassword, Authorized

app = Flask(__name__)
app.config.from_pyfile('config.py')
api = Api(app)
cors = CORS(app, supports_credentials=True)

with app.app_context():
    app.authorized = Authorized()
    db.init_app(app)
    db.create_all()


class HelloWorld(Resource):
    @staticmethod
    def get():
        return {'hello': 'world'}


api.add_resource(HelloWorld, '/')
api.add_resource(Login, '/auth/login')
api.add_resource(Register, '/auth/get-started')
api.add_resource(Logout, '/auth/logout')
api.add_resource(ResetPassword, '/auth/reset-password')

if __name__ == "__main__":
    try:
        app.run('localhost', port=5000, debug=True)
    except Exception as e:
        print(e)
        db.session.rollback()
