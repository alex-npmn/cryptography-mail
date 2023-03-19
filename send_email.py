import os
import requests
import json
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from flask import session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from auth import dict_to_creds

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def sign_message(message, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    message_bytes = message.encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def send_encrypted_signed_email(from_email, to_email, subject, message, private_key_path, public_key_path):
    signature = sign_message(message, private_key_path)

    msg = MIMEMultipart("mixed")
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["X-Signature"] = base64.b64encode(signature).decode('utf-8')

    # Attach the plain text message
    msg.attach(MIMEText(message, "plain"))

    # Attach the public key
    with open(public_key_path, "rb") as f:
        public_key_data = f.read()
        public_key_attachment = MIMEBase("application", "octet-stream")
        public_key_attachment.set_payload(public_key_data)
        encoders.encode_base64(public_key_attachment)
        public_key_attachment.add_header("Content-Disposition", f"attachment; filename={public_key_path}")
        msg.attach(public_key_attachment)

    # Send the email
    try:
        creds = dict_to_creds(session["credentials"])
        access_token = creds.token
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        api_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"

        # Prepare the email message for the API
        raw_msg = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        payload = {"raw": raw_msg}
        response = requests.post(api_url, headers=headers, data=json.dumps(payload))

        if response.status_code == 200:
            print("Email sent successfully")
        else:
            print(f"Failed to send email: {response.text}")
    except Exception as e:
        print("Failed to send email:", str(e))

