import bcrypt
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

# Connect to the voters database
conn_voters = sqlite3.connect("voters.db")
cursor_voters = conn_voters.cursor()

# Create the voters table if it doesn't exist
cursor_voters.execute('''CREATE TABLE IF NOT EXISTS voters (
                            voter_id TEXT PRIMARY KEY,
                            password BLOB,
                            salt BLOB,
                            email TEXT,
                            otp TEXT,
                            otp_expiry TIMESTAMP
                        )''')
conn_voters.commit()

def generate_voter_id():
    """Generate a random 12-character alphanumeric voter ID."""
    return ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=12))

def generate_otp():
    """Generate a 6-digit OTP."""
    return ''.join(random.choices("0123456789", k=6))

def send_email(to_email, otp):
    """Send an OTP via email."""
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "umarcheema1372@gmail.com"
    sender_password = "ydaz memg dnow jrgb"  # App Password

    message = MIMEText(f"Your OTP for voter registration is: {otp}")
    message["Subject"] = "Voter Registration OTP"
    message["From"] = sender_email
    message["To"] = to_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, message.as_string())
        print(f"OTP sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        raise

def register_voter():
    """Register a voter with OTP verification."""
    email = input("Enter your email: ")
    password = input("Choose your password: ")
    confirm_password = input("Confirm your password: ")
    
    if password != confirm_password:
        print("Passwords do not match. Please try again.")
        return

    # Generate and send OTP
    otp = generate_otp()
    otp_expiry = datetime.now() + timedelta(minutes=5)
    try:
        send_email(email, otp)
    except:
        print("Unable to send OTP. Please check your email settings.")
        return

    print("An OTP has been sent to your email. Please verify it.")
    entered_otp = input("Enter the OTP: ")

    # Verify OTP
    if entered_otp != otp or datetime.now() > otp_expiry:
        print("Invalid or expired OTP. Please try again.")
        return

    # Generate salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    # Generate voter ID
    voter_id = generate_voter_id()

    # Insert voter details into the database
    cursor_voters.execute("INSERT INTO voters (voter_id, password, salt, email, otp, otp_expiry) VALUES (?, ?, ?, ?, ?, ?)",
                          (voter_id, hashed_password, salt, email, otp, otp_expiry))
    conn_voters.commit()

    print(f"Registration successful! Your Voter ID is: {voter_id}")

if __name__ == "__main__":
    register_voter()
