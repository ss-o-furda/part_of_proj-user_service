import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sender_email = 'mail'
password = 'pass'
port = 465
smtp_server = 'smtp.gmail.com'


class EmailException(Exception):
    pass


def send_mail(subject, receiver, body):
    message = MIMEMultipart('alternative')
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = receiver
    message.attach(MIMEText(body, 'html'))
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver, message.as_bytes())
    except EmailException:
        pass
