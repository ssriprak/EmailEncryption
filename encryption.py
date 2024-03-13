import smtplib
import imaplib
import email
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import sqlite3


# Set up the SQLite database with keys and email addresses
db_conn = sqlite3.connect('email_keys_database.db')
db_cursor = db_conn.cursor()

# Executing the SQL statement
db_cursor.execute('''CREATE TABLE IF NOT EXISTS email_keys (email TEXT PRIMARY KEY, Key_Public TEXT, Key_Private TEXT)''')
db_conn.commit()


# Create or import a pair  of RSA keys for the user
def generate_or_load_keys(email_address):
    db_cursor.execute('SELECT Key_Public, Key_Private FROM email_keys WHERE email = ?', (email_address,))
    row1 = db_cursor.fetchone()
    if row1:
        Key_Public = serialization.load_pem_public_key(row1[0].encode(), backend=default_backend())
        Key_Private = serialization.load_pem_private_key(row1[1].encode(), password=None, backend=default_backend())
    else:
        Key_Private = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        Key_Public = Key_Private.public_key()
        db_cursor.execute('INSERT INTO email_keys (email, Key_Public, Key_Private) VALUES (?, ?, ?)',
                       (email_address, Key_Public.public_bytes(encoding=serialization.Encoding.PEM,
                                                                format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                        Key_Private.private_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                   encryption_algorithm=serialization.NoEncryption()).decode()))
        db_conn.commit()
    return Key_Public, Key_Private


# Use the public key of the recipient to encrypt  a text file.
def encryption_of_file(attachment_to_send, recipient_public_key):
    with open(attachment_to_send, 'rb') as input_file:
        attachment_data = input_file.read()

    encrypted_attachment_data = recipient_public_key.encrypt(attachment_data,
                                                       padding.OAEP(
                                                           mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                           algorithm=hashes.SHA256(),
                                                           label=None))
    return encrypted_attachment_data

# Use the user's private key to decrypt an encrypted text file that is an incoming email attachment.
def decryption_of_file(encrypted_data, user_private_key):
    decrypted_file_data = user_private_key.decrypt(encrypted_data,
                                                   padding.OAEP(
                                                       mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                       algorithm=hashes.SHA256(),
                                                       label=None))
    
    with open('decrypted_file.txt', 'wb') as output_file:
        output_file.write(decrypted_file_data)
    

# Send an email with encrypted file
def send_encrypted_email_with_attachment(sender_email, sender_password, recipient_email, subject_of_email, attachment_to_send):
    # SMTP server connection
    SMTPserver = smtplib.SMTP('smtp.gmail.com', 587)
    SMTPserver.starttls()
    SMTPserver.login(sender_email, sender_password)


    # Create or import the key pair for the sender
    sender_public_key, sender_private_key = generate_or_load_keys(sender_email)

    # Encrypt the text file attached
    encrypted_data = encryption_of_file(attachment_to_send, sender_public_key)


    # Email message body
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Subject'] = subject_of_email


    # Use MIMEBase to attach the encrypted file
    attachment1 = MIMEBase('application', 'octet-stream')
    attachment1.set_payload(encrypted_data)
    email.encoders.encode_base64(attachment1)
    attachment1.add_header('Content-Disposition', 'attachment', filename='encrypted_file.txt')
    message.attach(attachment1)


    # Sending  email
    SMTPserver.sendmail(sender_email, recipient_email, message.as_string())
    print("Email is sent from", user_email)
    decryption_of_file(encrypted_data,generate_or_load_keys(user_email)[1])

    # Close the connection
    SMTPserver.quit()


# Retrieve received email and decryption of attached file
def receive_and_decrypt_emails_with_attachment(user_email, user_password):
    # IMAP server connection
    IMAPserver = imaplib.IMAP4_SSL('imap.gmail.com', 993)
    IMAPserver.login(user_email, user_password)
    IMAPserver.select('INBOX')


    # Search the email
    status1, email_id = IMAPserver.search(None, 'ALL')
    for email_id in email_id[0].split():
        status1, data_email = IMAPserver.fetch(email_id, '(RFC822)')
        raw_email_data = data_email[0][1]
        message = email.message_from_bytes(raw_email_data)


        # Check for the attachment
        if message.get_content_maintype() == 'multipart' and message.get_content_subtype() == 'octet-stream':
            sender_email = message['From']
            db_cursor.execute('SELECT Key_Public, Key_Private FROM email_keys WHERE email = ?', (sender_email,))
            row1 = db_cursor.fetchone()

            if row1:
                sender_public_key = serialization.load_pem_public_key(row1[0].encode(), backend=default_backend())
                user_private_key = generate_or_load_keys(user_email)[1]

                # Decrytion of file
                encrypted_file_data = message.get_payload(decode=True)
                decrypted_file_path = 'decrypted_file.txt'
                decryption_of_file(encrypted_file_data, user_private_key, decrypted_file_path)
    
    print(f'Email is received by {recipient_email} and file is decrypted')


# Main function
if __name__ == '__main__':
    user_email = 'ift520project@gmail.com'
    user_password = 'fmkb cuyr eryp okiy'

    recipient_email = 'group1.520project@gmail.com'
    recipient_password = 'xpso unvp ohhn fdfq'

    subject_of_email = 'Encrypted File'
    attachment_to_send = r'file.txt'

    # Send an encrypted email with an attached text file
    send_encrypted_email_with_attachment(user_email, user_password, recipient_email, subject_of_email, attachment_to_send)

    # Call to function for retrieving received email and decrypting attached file
    receive_and_decrypt_emails_with_attachment(recipient_email, recipient_password)
