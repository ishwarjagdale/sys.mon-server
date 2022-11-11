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
    name = db.Column(db.VARCHAR, default="anonymous", nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    authenticated = db.Column(db.BOOLEAN, default=False, nullable=False)

    @property
    def is_active(self):
        return self.authenticated

    @property
    def is_authenticated(self):
        return self.is_active

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.user_id)

    def __eq__(self, other):
        if isinstance(other, Users):
            return self.get_id() == other.get_id()

    def __ne__(self, other):
        return not self.__eq__(other)

    @staticmethod
    def get_user(email=None, user_id=None):
        if email:
            return Users.query.filter_by(email_addr=email).first()
        if user_id:
            return Users.query.filter_by(user_id=user_id).first()
        return False

    def check_password(self, password):
        return hashlib.sha256(bytes(str(self.date_created.timestamp()).replace(".", password), encoding='utf-8')). \
                   hexdigest() == self.password

    def generate_token(self):
        return hashlib.sha256(bytes(
            f"{current_app.config['SECRET_KEY']}.{self.email_addr}.{datetime.now().timestamp()}",
            encoding='utf-8')
        ).hexdigest()

    def authenticate(self):
        try:
            self.authenticated = True
            db.session.commit()
        except Exception as e:
            print(e)
            return False
        return self.authenticated

    def to_dict(self):
        return {
            'user_id': self.user_id,
            'name': self.name,
            'email': self.email_addr
        }


def generate_sys_id(context):
    return hashlib.sha256(bytes(str(context.get_current_parameters()['user_id']) +
                                str(datetime.now()), encoding='utf-8')).hexdigest()


def gen_token():
    return hashlib.sha256(bytes(str(datetime.now()), encoding='utf-8')).hexdigest()


class Systems(db.Model):
    __table_name__ = "systems"

    sys_id = db.Column(db.VARCHAR, primary_key=True, default=generate_sys_id)
    name = db.Column(db.VARCHAR(200), default=generate_sys_id, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    user_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship("Users", backref='users', lazy=True)
    ip_addr = db.Column(db.VARCHAR)
    verification_token = db.Column(db.VARCHAR, default=gen_token, nullable=False)
    enable_mon = db.Column(db.BOOLEAN, default=True, nullable=False)
    os = db.Column(db.VARCHAR, nullable=False)

    @staticmethod
    def get_system(sys_id, user_id=None, v_token=None):
        if user_id:
            return Systems.query.filter_by(sys_id=sys_id, user_id=user_id).first()
        return Systems.query.filter_by(sys_id=sys_id, verification_token=v_token).first()

    @staticmethod
    def add_system(name, user_id, os):
        system = Systems(name=name, user_id=user_id, os=os)
        db.session.add(system)
        db.session.commit()

        return Systems.get_system(system.sys_id, system.user_id)

    @staticmethod
    def get_systems(user_id):
        return [x.to_dict() for x in Systems.query.filter_by(user_id=user_id).all()]

    def to_dict(self):
        return {
            "sys_id": self.sys_id,
            "name": self.name,
            "user_id": self.user_id,
            "ip_addr": self.ip_addr,
            "os": self.os,
            "enable_mon": self.enable_mon
        }


class VerificationTokens(db.Model):
    __table_name__ = "VerificationTokens"

    token = db.Column(db.VARCHAR, primary_key=True)
    user_id = db.Column(db.INTEGER, db.ForeignKey('users.user_id'), nullable=False)
    # user = db.relationship("Users", backref='users', lazy=True)
    date_generated = db.Column(db.DateTime, nullable=False, default=datetime.now())
    cat = db.Column(db.VARCHAR, nullable=False)
    used = db.Column(db.BOOLEAN, default=False, nullable=False)

    def to_dict(self):
        return {
            'token': self.token,
            'user_id': self.user_id,
            'date_generated': self.date_generated,
            'cat': self.cat,
            'used': self.used
        }

    @staticmethod
    def get(tkn):
        return VerificationTokens.query.filter_by(token=tkn).first()

    @staticmethod
    def new(user_id, cat):
        tkn = VerificationTokens(token=gen_token(), user_id=user_id, cat=cat)
        db.session.add(tkn)
        db.session.commit()
        return tkn.to_dict()

    def consume(self):
        self.used = True
        db.session.commit()
        print("Token consumed:", self.token)
        return self.used


class Rules(db.Model):
    __table_name__ = "Rules"
    system_id = db.Column(db.VARCHAR, db.ForeignKey('systems.sys_id'))
    resource = db.Column(db.VARCHAR, primary_key=True)
    max_limit = db.Column(db.INTEGER, nullable=False)
    percent = db.Column(db.BOOLEAN, default=True, nullable=False)


class ActivityLogs(db.Model):
    __table_name__ = "ActivityLogs"
    system_id = db.Column(db.VARCHAR, db.ForeignKey('systems.sys_id'))
    activity_id = db.Column(db.INTEGER, primary_key=True)
    date_happened = db.Column(db.DateTime, nullable=False, default=datetime.now())
    type = db.Column(db.VARCHAR, nullable=False)
    description = db.Column(db.VARCHAR, nullable=False)
    read = db.Column(db.BOOLEAN, default=False, nullable=False)
    priority = db.Column(db.INTEGER, default=1, nullable=False)
    message = db.Column(db.VARCHAR, nullable=False)
