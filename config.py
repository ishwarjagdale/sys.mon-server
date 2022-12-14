import datetime
from os import environ

FLASK_ENV = environ.get("FLASK_ENV")
SQLALCHEMY_DATABASE_URI = environ.get("DATABASE_URL") if environ.get("DATABASE_URL").startswith('postgresql') else \
    'postgresql' + environ.get("DATABASE_URL")[8:]
FLASK_DEBUG = environ.get("FLASK_DEBUG")
SQLALCHEMY_TRACK_MODIFICATIONS = environ.get("SQLALCHEMY_TRACK_MODIFICATIONS")
SECRET_KEY = environ.get("SECRET_KEY")
SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
PERMANENT_SESSION_LIFETIME = datetime.timedelta(days=30)
REMEMBER_COOKIE_SAMESITE = "None"
REMEMBER_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_SECURE = True
SMTP_USER = environ.get('SMTP_USER')
SMTP_PASSWORD = environ.get('SMTP_PASSWORD')
