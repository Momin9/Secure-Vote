import logging
import os
import pickle
import random
from datetime import datetime, timedelta

import bcrypt
from phe import paillier

from app.utils import log_action, load_public_key

# Initialize logging
logging.basicConfig(filename='voting_system.log', level=logging.INFO, format='%(asctime)s - %(message)s')


# Load the private key for decryption
def load_private_key():
    """Load the private key from file."""
    with open("private_key.pem", "rb") as f:
        return pickle.load(f)


def initialize_db():
    """Set up the database tables."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    # Create admins table
    cursor.execute('''CREATE TABLE IF NOT EXISTS admins (
                        admin_id TEXT PRIMARY KEY,
                        password BLOB NOT NULL,
                        salt BLOB NOT NULL
                    )''')
    # Create elections table
    cursor.execute('''CREATE TABLE IF NOT EXISTS elections (
                        election_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        description TEXT,
                        start_date DATE,
                        end_date DATE
                    )''')

    # Create candidates table with election_id
    cursor.execute('''CREATE TABLE IF NOT EXISTS candidates (
                        candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        party TEXT NOT NULL,
                        election_id INTEGER NOT NULL,
                        FOREIGN KEY (election_id) REFERENCES elections (election_id)
                    )''')

    # Create voters table
    cursor.execute('''CREATE TABLE IF NOT EXISTS voters (
                        voter_id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password BLOB NOT NULL,
                        salt BLOB NOT NULL,
                        otp TEXT,
                        otp_expiry TIMESTAMP
                    )''')

    # Create votes table
    cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                        vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        voter_id TEXT NOT NULL,
                        candidate_id INTEGER NOT NULL,
                        election_id INTEGER NOT NULL,
                        encrypted_vote BLOB NOT NULL,
                        FOREIGN KEY (voter_id) REFERENCES voters (voter_id),
                        FOREIGN KEY (candidate_id) REFERENCES candidates (candidate_id),
                        FOREIGN KEY (election_id) REFERENCES elections (election_id)
                    )''')

    # Create admin logs table
    cursor.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        admin_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')

    conn.commit()
    conn.close()


def register_voter(voter_id, email, password):
    """Register a new voter."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    try:
        conn = sqlite3.connect("voting_system.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO voters (voter_id, email, password, salt) VALUES (?, ?, ?, ?)",
                       (voter_id, email, hashed_password, salt))
        conn.commit()
        conn.close()
        log_action("REGISTER_VOTER", f"Voter registered with ID {voter_id}.")
    except sqlite3.IntegrityError as e:
        log_action("REGISTER_ERROR", f"Failed to register voter: {e}")


def authenticate_voter(voter_id, password):
    """Authenticate a voter's credentials."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password, salt FROM voters WHERE voter_id = ?", (voter_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        stored_password, salt = result
        return bcrypt.checkpw(password.encode(), stored_password)
    return False


def generate_otp():
    """Generate a 6-digit numeric OTP."""
    otp = ''.join(random.choices('0123456789', k=6))
    print(f"Generated OTP: {otp}")
    return otp


def save_otp(voter_id, otp, email=None):
    """Save the OTP and expiry time for a voter."""
    expiry_time = (datetime.now() + timedelta(minutes=10)).isoformat()

    try:
        conn = sqlite3.connect("voting_system.db")
        cursor = conn.cursor()

        # Insert or update OTP
        cursor.execute(
            """INSERT INTO voters (voter_id, email, otp, otp_expiry, password, salt) 
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(voter_id) DO UPDATE SET otp = ?, otp_expiry = ?""",
            (
                voter_id, email, otp, expiry_time,
                bcrypt.hashpw("placeholder".encode(), bcrypt.gensalt()), bcrypt.gensalt(),
                otp, expiry_time
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_action("OTP_SAVE_ERROR", f"Error saving OTP for voter {voter_id}: {e}")


def validate_otp(voter_id, otp):
    """Validate the OTP for a voter."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT otp, otp_expiry FROM voters WHERE voter_id = ?",
        (voter_id,)
    )
    result = cursor.fetchone()
    conn.close()

    if result:
        saved_otp, expiry_time = result
        if otp == saved_otp and datetime.now() < datetime.fromisoformat(expiry_time):
            return True
    return False


def get_email_by_voter_id(voter_id):
    """Retrieve a voter's email by voter ID."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM voters WHERE voter_id = ?", (voter_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


def list_candidates(election_id=None):
    """Retrieve all candidates or candidates for a specific election."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    if election_id:
        cursor.execute("SELECT * FROM candidates WHERE election_id = ?", (election_id,))
    else:
        cursor.execute("""SELECT * FROM candidates
        LEFT JOIN elections ON elections.election_id = candidates.election_id
        """)  # Fetch all candidates

    candidates = cursor.fetchall()
    conn.close()
    return candidates


def list_elections():
    """Retrieve all candidates or candidates for a specific election."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM elections")

    elections = cursor.fetchall()
    conn.close()
    return elections


def get_election_id(candidate_id):
    """Retrieve all candidates or candidates for a specific election."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    cursor.execute("SELECT election_id FROM candidates WHERE candidate_id = ?", (candidate_id,))

    election_id = cursor.fetchall()
    conn.close()
    return election_id


def get_election_data(candidate_id):
    """Retrieve all candidates or candidates for a specific election."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    cursor.execute("""SELECT * FROM elections
    LEFT JOIN candidates ON candidates.election_id = elections.election_id
    WHERE candidates.candidate_id = ?""", (candidate_id,))

    election_data = cursor.fetchall()
    conn.close()
    return election_data


def add_candidate(name, party, election_id):
    """Add a new candidate to an election."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO candidates (name, party, election_id) VALUES (?, ?, ?)", (name, party, election_id))
    conn.commit()
    conn.close()


def delete_candidate(candidate_id):
    """Delete a candidate by their ID."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM candidates WHERE candidate_id = ?", (candidate_id,))
    conn.commit()
    conn.close()


def create_election(name, description, start_date, end_date):
    """Add a new election."""
    try:
        conn = sqlite3.connect("voting_system.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO elections (name, description, start_date, end_date) VALUES (?, ?, ?, ?)",
            (name, description, start_date, end_date)
        )
        conn.commit()
        conn.close()
        return True
    except:
        return False


def cast_vote(voter_id, candidate_id, election_id):
    """Cast a vote for a candidate."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    # Check if voter has already voted in the election
    cursor.execute("SELECT * FROM votes WHERE voter_id = ? AND election_id = ?", (voter_id, election_id))
    if cursor.fetchone():
        print("VOTE_DENIED", f"Voter '{voter_id}' attempted to vote twice in election '{election_id}'.")
        return False

    # Encrypt the vote
    public_key = load_public_key()
    encrypted_vote = public_key.encrypt(1).ciphertext()

    # Convert encrypted vote to bytes
    encrypted_vote_blob = encrypted_vote.to_bytes((encrypted_vote.bit_length() + 7) // 8, byteorder="big")

    # Insert the vote into the database
    cursor.execute(
        "INSERT INTO votes (voter_id, candidate_id, election_id, encrypted_vote) VALUES (?, ?, ?, ?)",
        (voter_id, candidate_id, election_id, encrypted_vote_blob)
    )
    conn.commit()
    conn.close()
    print("VOTE_CAST", f"Voter '{voter_id}' cast a vote for candidate '{candidate_id}' in election '{election_id}'.")
    return True


def tally_votes():
    """Decrypt and tally votes."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    # Load keys
    public_key = load_public_key()
    private_key = load_private_key()

    # Retrieve all candidates
    cursor.execute("SELECT candidate_id, name, party FROM candidates")
    candidates = cursor.fetchall()

    # Initialize tally dictionary
    tally = {candidate[0]: 0 for candidate in candidates}

    # Retrieve all votes
    cursor.execute("SELECT candidate_id, encrypted_vote FROM votes")
    votes = cursor.fetchall()

    # Decrypt and count votes
    for candidate_id, encrypted_vote_blob in votes:
        encrypted_vote_int = int.from_bytes(encrypted_vote_blob, byteorder="big")
        encrypted_vote = paillier.EncryptedNumber(public_key, encrypted_vote_int)
        decrypted_vote = private_key.decrypt(encrypted_vote)

        if decrypted_vote == 1:  # Valid vote
            tally[candidate_id] += 1

    conn.close()
    return {candidate_id: (name, party, tally[candidate_id]) for candidate_id, name, party in candidates}


import sqlite3


def reset_databases():
    """Reset the database by preserving the admins table and resetting other tables."""
    db_file = "voting_system.db"

    if os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Drop all tables except admins
        tables_to_reset = ["elections", "candidates", "voters", "votes", "admin_logs"]
        for table in tables_to_reset:
            cursor.execute(f"DROP TABLE IF EXISTS {table}")

        # Recreate the dropped tables
        cursor.execute('''CREATE TABLE IF NOT EXISTS elections (
                            election_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            description TEXT,
                            start_date DATE,
                            end_date DATE
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS candidates (
                            candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            party TEXT NOT NULL,
                            election_id INTEGER NOT NULL,
                            FOREIGN KEY (election_id) REFERENCES elections (election_id)
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS voters (
                            voter_id TEXT PRIMARY KEY,
                            email TEXT UNIQUE NOT NULL,
                            password BLOB NOT NULL,
                            salt BLOB NOT NULL,
                            otp TEXT,
                            otp_expiry TIMESTAMP
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                            vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            voter_id TEXT NOT NULL,
                            candidate_id INTEGER NOT NULL,
                            election_id INTEGER NOT NULL,
                            encrypted_vote BLOB NOT NULL,
                            FOREIGN KEY (voter_id) REFERENCES voters (voter_id),
                            FOREIGN KEY (candidate_id) REFERENCES candidates (candidate_id),
                            FOREIGN KEY (election_id) REFERENCES elections (election_id)
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
                            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            admin_id TEXT NOT NULL,
                            action TEXT NOT NULL,
                            details TEXT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')

        conn.commit()
        conn.close()
        print("Database reset complete. Admins table has been preserved.")
    else:
        print(f"{db_file} does not exist. Initializing database.")
        initialize_db()


def log_admin_action(admin_id, action, details):
    """Log an admin action to the database."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    # Create admin_logs table if not exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        admin_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        details TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')

    # Insert the log entry
    cursor.execute(
        "INSERT INTO admin_logs (admin_id, action, details) VALUES (?, ?, ?)",
        (admin_id, action, details)
    )
    conn.commit()
    conn.close()


def get_admin_logs():
    """Retrieve all admin logs."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()
    return logs


def authenticate_admin(identifier, password):
    """Authenticate an admin's credentials using admin_id or email."""
    conn = sqlite3.connect("voting_system.db")
    cursor = conn.cursor()

    # Try to find admin using either admin_id or email
    cursor.execute("""
        SELECT password, salt FROM admins 
        WHERE admin_id = ? OR email = ?
    """, (identifier, identifier))

    result = cursor.fetchone()
    conn.close()

    if result:
        return True

    return False
