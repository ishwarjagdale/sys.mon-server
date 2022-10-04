from datetime import datetime
import hashlib
from flask import current_app
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Users(db.Model):
    __table_name__ = "users"

    user_id = db.Column(db.INTEGER, primary_key=True)
    email_addr = db.Column(db.VARCHAR, unique=True, nullable=False)
    password = db.Column(db.VARCHAR, nullable=False)
    name = db.Column(db.VARCHAR, default="unnamed", nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    authenticated = db.Column(db.BOOLEAN, default=False, nullable=False)

    @staticmethod
    def get_user(email):
        return Users.query.filter_by(email_addr=email).first()

    def check_password(self, password):
        return hashlib.sha256(bytes(str(self.date_created.timestamp()).replace(".", password), encoding='utf-8')). \
                   hexdigest() == self.password

    def generate_token(self):
        return hashlib.sha256(bytes(
            f"{current_app.config['SECRET_KEY']}.{self.email_addr}.{datetime.now().timestamp()}",
            encoding='utf-8')
        ).hexdigest()


def generate_sys_id(context):
    return hashlib.sha256(bytes(str(context.get_current_parameters()['user_id']) +
                                str(context.get_current_parameters()['date_added']), encoding='utf-8')).hexdigest()


class Systems(db.Model):
    __table_name__ = "systems"

    sys_id = db.Column(db.VARCHAR, primary_key=True, default=generate_sys_id)
    name = db.Column(db.VARCHAR(200), default=generate_sys_id, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    user_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship("Users", backref='users', lazy=True)
    ip_addr = db.Column(db.VARCHAR)

    @staticmethod
    def get_system(sys_id, user_id):
        return Systems.query.filter_by(sys_id=sys_id, user_id=user_id).first()

    @staticmethod
    def add_system(name, ip, user_id):
        system = Systems(name=name, user_id=user_id, ip_addr=ip)
        db.session.add(system)
        db.session.commit()

        return Systems.get_system(system.sys_id, system.user_id)

    def to_dict(self):
        return {
            "sys_id": self.sys_id,
            "name": self.name,
            'user_id': self.user_id
        }
