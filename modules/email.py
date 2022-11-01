import smtplib
import ssl
from flask import current_app as app

smtp_server = 'smtp.gmail.com'
port = 465

context = ssl.create_default_context()
server = smtplib.SMTP_SSL(smtp_server, port, context=context)


def create_connection():
    try:
        if server.login(user=app.config.get("SMTP_USER"), password=app.config.get('SMTP_PASSWORD')) == 235:
            print('SMTP SERVER SET UP SUCCESSFUL')
    except smtplib.SMTPAuthenticationError or TimeoutError or Exception as e:
        print('SMTP SERVER SET UP FAILED :: ', e)


def send_mail(to, message, recur=False):
    try:
        print(f"Email to {to}:", server.sendmail(app.config.get('SMTP_USER'), to, message))
    except smtplib.SMTPException:
        create_connection()
        if not recur:
            send_mail(to, message, recur=True)
