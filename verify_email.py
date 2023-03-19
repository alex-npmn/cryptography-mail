import base64
import email
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from googleapiclient.discovery import build

def fetch_email_by_id(email_id, creds):
    service = build("gmail", "v1", credentials=creds)
    message = service.users().messages().get(userId='me', id=email_id, format='raw').execute()
    msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
    msg = email.message_from_bytes(msg_str)
    return msg

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

def verify_email_signature(email_id, public_key_path, creds):
    email = fetch_email_by_id(email_id, creds)

    signature = email['X-Signature']
    message = email.get_payload()

    try:
        verify_signature(message, signature, public_key_path)
        return True
    except InvalidSignature:
        return False

from googleapiclient.errors import HttpError

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
