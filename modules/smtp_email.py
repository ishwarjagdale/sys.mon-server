import smtplib
import ssl
from config import SMTP_USER, SMTP_PASSWORD

smtp_server = 'smtp.gmail.com'
port = 465


def send_mail(to, subject, message, recur=False):
    try:
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL(smtp_server, port, context=context)
        if server.login(user=SMTP_USER, password=SMTP_PASSWORD)[0] == 235:
            recep = server.sendmail(from_addr=SMTP_USER, to_addrs=[to],
                                    msg=f"""From: {SMTP_USER}
To: {", ".join(to) if type(to) == list else to}
Subject: {subject}

{message}""")
            print(f"Email to {to}:", len(recep) == 0)
            server.close()
            return len(recep) == 0
        if not recur:
            send_mail(to, subject, message, recur=True)
    except smtplib.SMTPException or TimeoutError or Exception as e:
        print('SMTP SERVER SET UP FAILED :: ', e)
        if not recur:
            send_mail(to, subject, message, recur=True)

    return False


def email_exists(email):
    try:
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL(smtp_server, port, context=context)
        exists = server.verify(email)
        print(exists)
        return server.verify(email)[0] == 250
    except smtplib.SMTPException or TimeoutError or Exception as e:
        print(e)
    return None
