import os

from flask import Flask, render_template, request, redirect, url_for, session

from auth import get_google_auth_flow, oauth2callback, logout
from flask_session import Session
from send_email import send_encrypted_signed_email
from verify_email import received_emails, verify_email_signature

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.urandom(24)

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)


@app.route('/')
def index():
    is_logged_in = "credentials" in session
    return render_template('index.html', is_logged_in=is_logged_in)

# @app.route('/login')
# def login():
#     return render_template('login.html')

@app.route('/authorize')
def authorize():
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(prompt='consent', access_type='offline',
                                                      include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from flask import send_file
import zipfile
import os
import io

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

    # Create a zip file containing private_key.pem and public_key.pem
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('private_key.pem', private_pem)
        zf.writestr('public_key.pem', public_pem)

    # Set the buffer's position to the beginning of the file
    zip_buffer.seek(0)

    # Clean up generated files
    os.remove('private_key.pem')
    os.remove('public_key.pem')

    return send_file(zip_buffer, as_attachment=True, attachment_filename='keys.zip', mimetype='application/zip', cache_timeout=0)

@app.route('/send_email')
def send_email():
    is_logged_in = "credentials" in session
    return render_template('send_email.html', is_logged_in=is_logged_in)

@app.route("/send_signed_email", methods=["POST"])
def handle_send_signed_email():
    recipient_email = request.form["to"]
    subject = request.form["subject"]
    message = request.form["message"]
    private_key_file = request.files["private_key"]
    public_key_file = request.files["public_key"]

    # Save the private key and public key files temporarily
    private_key_path = "temp_private_key.pem"
    public_key_path = "temp_public_key.pem"

    with open(private_key_path, "wb") as f:
        f.write(private_key_file.read())

    with open(public_key_path, "wb") as f:
        f.write(public_key_file.read())

    send_encrypted_signed_email(session['email'], recipient_email, subject, message, private_key_path, public_key_path)

    # Remove the temporary private and public key files after sending the email
    os.remove(private_key_path)
    os.remove(public_key_path)

    return redirect(url_for("send_email"))



app.add_url_rule('/authorize', 'authorize', authorize)
app.add_url_rule('/logout', 'logout', logout)
app.add_url_rule('/oauth2callback', 'oauth2callback', oauth2callback)


@app.route('/received_emails')
def handle_received_emails():
    return received_emails(session["credentials"])

@app.route('/verify_email_signature', methods=['POST'])
def handle_verify_email_signature():
    email_id = request.form['email_id']
    public_key_path = request.form['public_key_path']

    result = verify_email_signature(email_id, public_key_path, session["credentials"])

    return render_template('index.html', message=result)


if __name__ == '__main__':
    app.run(debug=True, port=5003)
