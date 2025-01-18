import os
import pickle
import random
import re
import smtplib
from email.mime.text import MIMEText

from flask import logging


# Load logging
def log_action(action, details):
    logging.info(f"{action}: {details}")


def validate_password(password):
    """Ensure the password is strong."""
    if (len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'[0-9]', password) and
            re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return True
    return False


def generate_voter_id():
    """Generate a random 12-character voter ID."""
    return ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=12))


def send_email_voter_id(to_email, subject, message):
    """Send an email."""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = os.getenv("SENDER_EMAIL", "umarcheema1372@gmail.com")  # Replace with your default email if necessary
    sender_password = os.getenv("SENDER_PASSWORD", "ydaz memg dnow jrgb")  # Retrieve password from environment variables
    if not sender_password:
        return "Error: Sender password is not set in environment variables."
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        return "Email sent successfully."
    except smtplib.SMTPAuthenticationError:
        return "Error: Failed to authenticate with the SMTP server. Check your credentials."
    except Exception as e:
        return f"Error occurred during sending OTP: {e}"


def load_public_key():
    """Load the public key."""
    with open("public_key.pem", "rb") as f:
        return pickle.load(f)


def load_private_key():
    """Load the private key."""
    with open("private_key.pem", "rb") as f:
        return pickle.load(f)


def send_email_otp(to_email, subject, message):
    """Send an email."""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = os.getenv("SENDER_EMAIL", "umarcheema1372@gmail.com")  # Replace with your default email if necessary
    sender_password = os.getenv("SENDER_PASSWORD", "ydaz memg dnow jrgb")  # Retrieve password from environment variables

    if not sender_password:
        return "Error: Sender password is not set in environment variables."

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        return "Email sent successfully."
    except smtplib.SMTPAuthenticationError:
        return "Error: Failed to authenticate with the SMTP server. Check your credentials."
    except Exception as e:
        return f"Error occurred during sending OTP: {e}"
