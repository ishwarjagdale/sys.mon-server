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
