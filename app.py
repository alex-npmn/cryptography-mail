import os
import tempfile
import google.oauth2.credentials
from flask import Flask, session, jsonify, flash
from flask import request, redirect, url_for
from flask_session import Session
from auth import get_google_auth_flow, oauth2callback, logout
from send_email import send_encrypted_signed_email
from verify_email import received_emails, verify_email_signature, get_email, download_attachment_file, \
    verify_signature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from flask import send_file
import zipfile
import io

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

@app.route('/authorize')
def authorize():
    flow = get_google_auth_flow()
    authorization_url, state = flow.authorization_url(prompt='consent', access_type='offline',
                                                      include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

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

    return send_file(zip_buffer, as_attachment=True, download_name='keys.zip', mimetype='application/zip')

from flask import render_template

@app.route('/view_emails')
def view_emails():
    if 'credentials' not in session:
        return redirect('authorize')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])

    print(creds)

    emails = received_emails(creds)

    return render_template('view_emails.html', emails=emails or [])

@app.route('/view_email/<email_id>', methods=['GET', 'POST'])
def view_email(email_id):
    if 'credentials' not in session:
        return redirect('authorize')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])

    email = get_email(email_id)
    print(f"Email data: {email}")
    is_verified = None

    if request.method == 'POST':
        public_key_file = request.files['public_key']
        if public_key_file:
            public_key_file.save('temp_public_key.pem')
            print("Saved public key file: temp_public_key.pem")
            is_verified = verify_email_signature(email_id, 'temp_public_key.pem', creds)
            os.remove('temp_public_key.pem')
        else:
            is_verified = False

    return render_template('view_email.html', email=email, email_id=email_id, is_verified=is_verified)

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

    flash("Your email has been sent and signed successfully", "success")

    return redirect(url_for("send_email"))

app.add_url_rule('/authorize', 'authorize', authorize)
app.add_url_rule('/logout', 'logout', logout)
app.add_url_rule('/oauth2callback', 'oauth2callback', oauth2callback)

@app.route('/received_emails')
def handle_received_emails():
    return received_emails(session["credentials"])

@app.route('/verify_email_signature_by_id/<email_id>/<attachment_id>', methods=['GET'])
def verify_email_signature_by_id(email_id, attachment_id):
    # Download the public key and store it in a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as public_key_file:
        # Read the contents of the file here before it's closed
        # public_key_pem_contents = public_key_file.read()

        # Now you can use public_key_pem_contents outside the context manager
        print("verify_email_signature_by_id case")
        print(public_key_file)

        # Read the downloaded attachment and write it to the temporary file
        with open(public_key_file.name, 'rb') as attachment_file:
            attachment_data = attachment_file.read()
            public_key_file.write(attachment_data)
            public_key_file.flush()

    print(f"Public key file: {public_key_file}")
    # Pass the path of the downloaded public key to the verify_signature function
    result = verify_signature(email_id)

    # Remove the temporary file after using it
    os.remove(public_key_file.name)

    return jsonify(result)

@app.route('/download_attachment/<email_id>/<attachment_id>')
def download_attachment(email_id, attachment_id):
    attachment_file, attachment_filename = download_attachment_file(email_id, attachment_id)

    if attachment_file is None:
        return "Error downloading attachment", 400

    return send_file(attachment_file, download_name="test", as_attachment=True)

app.config['UPLOAD_FOLDER'] = 'uploads'

if __name__ == '__main__':
    app.run(debug=True, port=5003)