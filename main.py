from email_tools import send_signed_email, retrieve_emails

email_address = 'you@gmail.com'
password = 'your_password'
to_email = 'recipient@example.com'
subject = 'Test email with signature'
message = 'This is a test email with an attached signature.'

private_key_path = 'private_key.pem'
public_key_path = 'public_key.pem'

# Sending signed email
send_signed_email(email_address, to_email, subject, message, private_key_path)

# Retrieving emails and verifying signatures
retrieve_emails(email_address, password, public_key_path)

