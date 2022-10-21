import smtplib
import ssl

smtp_server = 'smtp.gmail.com'
port = 465

context = ssl.create_default_context()
server = smtplib.SMTP_SSL(smtp_server, port, context=context)
