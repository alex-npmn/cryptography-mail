import os
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
import requests
import json
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.urandom(24)

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

def get_google_auth_flow():
    flow = InstalledAppFlow.from_client_secrets_file(
        "client_secrets.json",
        scopes=[
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
    )
    flow.redirect_uri = "http://localhost:5003/oauth2callback"
    return flow


@app.route('/')
def index():
    is_logged_in = "credentials" in session
    return render_template('index.html', is_logged_in=is_logged_in)


@app.route('/send_signed_email', methods=['POST'])
def send_signed_email():
    recipient_email = request.form['recipient_email']
    subject = request.form['subject']
    message = request.form['message']

    send_encrypted_signed_email(session['email'], recipient_email, subject, message, 'private_key.pem')

    return render_template('index.html', message="Email sent!")


@app.route('/authorize')
def authorize():
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(prompt='consent', access_type='offline',
                                                      include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/logout')
def logout():
    # Clear the user's session data
    session.clear()
    # Redirect the user back to the index page
    return redirect(url_for('index'))

from googleapiclient.discovery import build

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get("state")
    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=request.url, include_granted_scopes='true')

    creds = flow.credentials
    session["credentials"] = creds_to_dict(creds)

    # Fetch the user's email address
    service = build("oauth2", "v2", credentials=creds)
    user_info = service.userinfo().get().execute()
    session["email"] = user_info["email"]

    return redirect(url_for("index"))

def creds_to_dict(creds):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }


def dict_to_creds(creds_dict):
    return Credentials.from_authorized_user_info(info=creds_dict)

import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def sign_message(message, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashlib.sha256()
    )

    return base64.b64encode(signature).decode()


def send_encrypted_signed_email(from_email, to_email, subject, message, private_key_path):
    signature = sign_message(message, private_key_path)

    msg = MIMEMultipart("mixed")
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["X-Signature"] = signature

    # Attach the plain text message
    msg.attach(MIMEText(message, "plain"))

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

from cryptography.exceptions import InvalidSignature

@app.route('/received_emails')
def received_emails():
    # Fetch received emails here
    pass

@app.route('/verify_email_signature', methods=['POST'])
def verify_email_signature():
    email_id = request.form['email_id']
    public_key_path = request.form['public_key_path']

    # Fetch the email by email_id
    email = fetch_email_by_id(email_id)

    signature = email['X-Signature']
    message = email['body']

    try:
        verify_signature(message, signature, public_key_path)
        return "Signature is valid."
    except InvalidSignature:
        return "Signature is not valid."

def fetch_email_by_id(email_id):
    # Fetch the email by email_id here
    pass

def verify_signature(message, signature, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    signature_bytes = base64.b64decode(signature.encode())

    public_key.verify(
        signature_bytes,
        message.encode(),
        padding.PKCS1v15(),
        hashlib.sha256()
    )



if __name__ == '__main__':
    app.run(debug=True, port=5003)
