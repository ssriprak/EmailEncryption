# Asymmetric Email Encryption Application

This project implements an Asymmetric Email Encryption Application using Python. The application aims to enhance email security and privacy by encrypting email attachments using RSA encryption.

## Features

- **Key Generation**: Generates or loads RSA key pairs for users to facilitate encryption and decryption.
- **File Encryption**: Encrypts text files using the recipient's public key before attaching them to an email.
- **File Decryption**: Decrypts encrypted email attachments using the recipient's private key.
- **Email Sending**: Sends emails with encrypted attachments using SMTP.
- **Email Receiving**: Retrieves received emails and decrypts attached files using IMAP.

## Requirements

- Python 3.x
- `cryptography` library
- `smtplib` module
- `imaplib` module
- `email` module

## Usage

1. Set up a Gmail account for both the sender and the recipient.
2. Enable access to less secure apps for the sender's Gmail account.
3. Run the script and provide necessary credentials and file paths.
4. Check the console output for status messages and any decrypted files.

## Code Organization

- `email_keys_database.db`: SQLite database to store email addresses and corresponding RSA key pairs.
- `email_encryption.py`: Python script containing functions for key generation, file encryption, decryption, email sending, and receiving.

## Usage Example

```python
python email_encryption.py
