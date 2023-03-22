import email
import io
import os

import google
import google.oauth2.credentials
import googleapiclient
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import redirect, session
from googleapiclient.discovery import build

def fetch_email_by_id(email_id, creds):
    service = build("gmail", "v1", credentials=creds)
    message = service.users().messages().get(userId='me', id=email_id, format='raw').execute()
    msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
    msg = email.message_from_bytes(msg_str)
    return msg

def verify_signature(email_id):
    # Load the public key from the email attachment
    email_data = get_email(email_id)
    print(f"Here is email data {email_data}")
    attachments = email_data['attachments']
    public_key_pem = None
    for attachment in attachments:
        if attachment['filename'] == 'temp_public_key.pem':
            attachment_id = attachment['id']
            creds = google.oauth2.credentials.Credentials(**session['credentials'])
            service = googleapiclient.discovery.build('gmail', 'v1', credentials=creds)
            attachment = service.users().messages().attachments().get(userId='me', messageId=email_data['id'],
                                                                      id=attachment_id).execute()
            public_key_pem = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
            break

    if not public_key_pem:
        print("Public key not found in email attachments")
        return False

    public_key = serialization.load_pem_public_key(public_key_pem)

    # Verify the signature
    try:
        public_key.verify(
            base64.b64decode(email_data['X-Signature'].encode('utf-8')),
            email_data['body'].encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

def decrypt_with_temp_key(encrypted_data, email_data):
    attachments = email_data['attachments']

    temp_key_id = None
    for attachment in attachments:
        if attachment['filename'] == 'temp_public_key.pem':
            temp_key_id = attachment['id']
            break

    if not temp_key_id:
        print("Temp public key not found in email attachments")
        return None

    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    service = googleapiclient.discovery.build('gmail', 'v1', credentials=creds)

    attachment = service.users().messages().attachments().get(userId='me', messageId=email_data['id'], id=temp_key_id).execute()
    temp_public_key_pem = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))

    # Load the public key
    temp_public_key = RSA.import_key(temp_public_key_pem)

    # Decrypt the encrypted_data using the temporary public key
    cipher_rsa = PKCS1_OAEP.new(temp_public_key)
    decrypted_data = cipher_rsa.decrypt(base64.b64decode(encrypted_data))

    return decrypted_data

from googleapiclient.discovery import build


def get_message(email_id, credentials):
    try:
        creds = google.oauth2.credentials.Credentials(**credentials)
        service = build('gmail', 'v1', credentials=creds)
        message = service.users().messages().get(userId='me', id=email_id).execute()
        return message
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def get_attachment(email_id, attachment_id, credentials):
    try:
        creds = google.oauth2.credentials.Credentials(**credentials)
        service = build('gmail', 'v1', credentials=creds)
        attachment = service.users().messages().attachments().get(userId='me', messageId=email_id, id=attachment_id).execute()
        return attachment
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def save_attachment(email_message, attachment_id):
    for part in email_message.walk():
        if part.get_content_disposition() == 'attachment' and part.get('Content-ID') == attachment_id:
            file_data = part.get_payload(decode=True)
            filename = part.get_filename()
            with open(filename, 'wb') as f:
                f.write(file_data)
            return os.path.abspath(filename)
    return None
# def verify_email_signature_by_id(email_id, attachment_id):
#     # Fetch email by email_id
#     creds = google.oauth2.credentials.Credentials(**session['credentials'])
#     email_data = fetch_email_by_id(email_id, creds)
#     email_message = BytesParser().parsebytes(email_data)
#
#     # Save the attachment and get its file path
#     public_key_path = save_attachment(email_message, attachment_id)
#     print(f'Public key path: {public_key_path}')
#
#     if public_key_path is None:
#         # Handle the case when the attachment is not found
#         return "Attachment not found"
#
#     # Extract the message and signature from the email
#     message = extract_message(email_message)
#     signature = extract_signature(email_message)
#
#     print(f'Message: {message}')  # Added print
#     print(f'Signature: {signature}')  # Added print
#
#     # Call the verify_signature function with the correct arguments
#     result = verify_signature(message, signature, public_key_path)
#
#     # Remove the public key file after verification
#     os.remove(public_key_path)
#
#     return result

def extract_message(email_message):
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload()
    else:
        return email_message.get_payload()

def extract_signature(email_message):
    return email_message['X-Signature']

def verify_email_signature(email_id, public_key_path, creds):
    email = fetch_email_by_id(email_id, creds)

    signature = email['X-Signature']
    message = email.get_payload()

    try:
        verify_signature(message, signature, public_key_path)
        return True
    except InvalidSignature:
        return False


def received_emails(creds):
    try:
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])

        emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            email_data = {
                'id': msg['id'],
                'subject': '',
                'from': '',
            }
            for header in msg['payload']['headers']:
                if header['name'] == 'Subject':
                    email_data['subject'] = header['value']
                if header['name'] == 'From':
                    email_data['from'] = header['value']

            emails.append(email_data)

        return emails
    except HttpError as error:
        print(f"An error occurred: {error}")
        return None

from googleapiclient.errors import HttpError

import base64

def get_email(email_id):
    """Fetch email details using the email_id."""
    if 'credentials' not in session:
        return redirect('authorize')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    try:
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=creds)
        message = service.users().messages().get(userId='me', id=email_id).execute()
        payload = message['payload']
        headers = payload['headers']
        print(f"Here is all heaedrs {headers}")

        email_data = {
            'id': email_id,
            'snippet': message['snippet'],
            'date': '',
            'subject': '',
            'from': '',
            'to': '',
            'body': '',
            'attachments': []
        }

        for header in headers:
            name = header['name']
            value = header['value']
            if name == 'From':
                email_data['from'] = value
            elif name == 'To':
                email_data['to'] = value
            elif name == 'Subject':
                email_data['subject'] = value
            elif name == 'Date':
                email_data['date'] = value
            elif name == 'Raw':
                email_data['raw'] = value
            elif name == 'X-Signature':
                email_data['X-Signature'] = value

        if 'parts' in payload:
            parts = payload['parts']
            for part in parts:
                if 'text/plain' == part['mimeType']:
                    data = part['body']['data']
                    decoded_data = base64.urlsafe_b64decode(data.encode('UTF-8')).decode('utf-8')
                    email_data['body'] = decoded_data.replace('\n', '<br>')

                # Fetch attachments
                if 'filename' in part and part['filename']:
                    attachment_id = part['body'].get('attachmentId')
                    attachment = {
                        'id': attachment_id,
                        'filename': part['filename']
                    }
                    email_data['attachments'].append(attachment)

        return email_data

    except HttpError as error:
        print(f"An error occurred: {error}")
        return None


def download_attachment_file(email_id, attachment_id):
    print(f"download_attachment_file called with email_id: {email_id}, attachment_id: {attachment_id}")
    if 'credentials' not in session:
        return redirect('authorize')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])
    service = build('gmail', 'v1', credentials=creds)

    try:
        message = service.users().messages().get(
            userId='me',
            id=email_id
        ).execute()

        # attachment_filename = None
        for part in message['payload']['parts']:
            print(f"Checking part: {part}")
            if part.get('filename') and part['body'].get('attachmentId') == attachment_id:
                attachment_filename = part['filename']

                # Retrieve attachment using Gmail API
                attachment = service.users().messages().attachments().get(
                    userId='me', messageId=email_id, id=attachment_id).execute()

                attachment_data = attachment.get('data')
                if attachment_data is None:
                    print("Attachment data not found")
                    return None, None

                attachment_file = base64.urlsafe_b64decode(attachment_data.encode('UTF-8'))

                print(f"Found attachment: {attachment_filename}, {attachment_file}")
                return attachment_file, attachment_filename

        # if attachment_filename is None:
        #     print("Attachment filename not found")
        #     return attachment_file, None

    except HttpError as error:
        print(f'An error occurred: {error}')
        return None, None

def verify_email_with_key_file(email_id, attachment_id):
    if 'credentials' not in session:
        return redirect('authorize')

    creds = google.oauth2.credentials.Credentials(**session['credentials'])

    attachment_file, attachment_filename = download_attachment_file(email_id, attachment_id)
    if attachment_file is None:
        return False

    try:
        public_key_pem = attachment_file.read()
        public_key = load_pem_public_key(public_key_pem)
        is_verified = verify_email_signature(email_id, public_key, creds)

        return is_verified

    except Exception as error:
        print(f'An error occurred: {error}')
        return False

