import smtplib
import imaplib
import os
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64

def send_signed_email(from_email, to_email, subject, message, private_key_path):
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    body = message
    msg.attach(MIMEText(body, 'plain'))

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    filename = "signature.bin"
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(signature)
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', f'attachment; filename={filename}')
    msg.attach(attachment)

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(from_email, session['password'])  # Use password from session
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

# Rest of the code remains the same
