import base64
import email
import imaplib
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask import session
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def send_signed_email(from_email, to_email, subject, message, private_key_path, recipient_public_key_pem):
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    encrypted_message = encrypt_message(message, recipient_public_key_pem)
    encrypted_message_base64 = base64.b64encode(encrypted_message).decode()

    msg.attach(MIMEText(encrypted_message_base64, 'plain'))

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

def retrieve_emails(email_address, password, mailbox='INBOX', limit=10):
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email_address, password)
    mail.select(mailbox)

    result, data = mail.search(None, 'ALL')
    email_ids = data[0].split()
    email_ids = email_ids[-min(limit, len(email_ids)):]  # Get the last 'limit' emails

    emails = []
    for e_id in email_ids:
        _, msg_data = mail.fetch(e_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                emails.append(msg)

    return emails

def encrypt_message(message, public_key_pem):
    public_key = load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message
