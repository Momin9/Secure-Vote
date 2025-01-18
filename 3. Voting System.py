import sqlite3
import logging
from phe import paillier
import pickle

# Logging setup
logging.basicConfig(filename='voting_system.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Database setup
conn = sqlite3.connect("voting_system.db")
cursor = conn.cursor()

# Create tables
cursor.execute('''CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    party TEXT NOT NULL
                )''')

cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                    vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    voter_id TEXT NOT NULL,
                    candidate_id INTEGER NOT NULL,
                    election_id INTEGER NOT NULL,
                    encrypted_vote BLOB NOT NULL,
                    FOREIGN KEY (candidate_id) REFERENCES candidates (candidate_id)
                )''')

conn.commit()

# Load public and private keys
def load_public_key():
    with open("public_key.pem", "rb") as f:
        return pickle.load(f)

def load_private_key():
    with open("private_key.pem", "rb") as f:
        return pickle.load(f)

# Logging function
def log_action(action, details):
    logging.info(f"{action}: {details}")

# Candidate management
def add_candidate(name, party):
    cursor.execute("INSERT INTO candidates (name, party) VALUES (?, ?)", (name, party))
    conn.commit()
    log_action("ADD_CANDIDATE", f"Candidate '{name}' from party '{party}' added.")
    print(f"Candidate '{name}' from party '{party}' added successfully.")

def list_candidates():
    cursor.execute("SELECT * FROM candidates")
    candidates = cursor.fetchall()
    print("\nCandidates List:")
    for candidate in candidates:
        print(f"ID: {candidate[0]}, Name: {candidate[1]}, Party: {candidate[2]}")
    log_action("LIST_CANDIDATES", f"Listed all candidates.")

def delete_candidate(candidate_id):
    cursor.execute("DELETE FROM candidates WHERE candidate_id = ?", (candidate_id,))
    conn.commit()
    log_action("DELETE_CANDIDATE", f"Deleted candidate with ID {candidate_id}.")
    print(f"Candidate with ID {candidate_id} deleted successfully.")

# Voting functionality
def cast_vote(voter_id, candidate_id, election_id=1):
    # Check if voter has already voted
    cursor.execute("SELECT * FROM votes WHERE voter_id = ? AND election_id = ?", (voter_id, election_id))
    if cursor.fetchone():
        print("You have already voted in this election.")
        log_action("VOTE_DENIED", f"Voter '{voter_id}' attempted to vote twice in election '{election_id}'.")
        return

    # Encrypt vote
    public_key = load_public_key()
    encrypted_vote = public_key.encrypt(1)  # Encrypting "1" to signify a valid vote

    # Convert encrypted vote to bytes
    encrypted_vote_blob = encrypted_vote.ciphertext().to_bytes(
        (encrypted_vote.ciphertext().bit_length() + 7) // 8, byteorder="big"
    )

    # Insert vote into the database
    cursor.execute(
        "INSERT INTO votes (voter_id, candidate_id, election_id, encrypted_vote) VALUES (?, ?, ?, ?)",
        (voter_id, candidate_id, election_id, encrypted_vote_blob)
    )
    conn.commit()
    log_action("VOTE_CAST", f"Voter '{voter_id}' cast a vote for candidate '{candidate_id}' in election '{election_id}'.")
    print("Your vote has been cast successfully!")

# Decrypt vote
def decrypt_vote(encrypted_vote_blob):
    public_key = load_public_key()
    private_key = load_private_key()

    encrypted_vote_int = int.from_bytes(encrypted_vote_blob, byteorder="big")
    encrypted_vote = paillier.EncryptedNumber(public_key, encrypted_vote_int)

    return private_key.decrypt(encrypted_vote)

# Example usage
if __name__ == "__main__":
    while True:
        print("\n1. Add Candidate")
        print("2. List Candidates")
        print("3. Delete Candidate")
        print("4. Cast Vote")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            name = input("Enter candidate name: ")
            party = input("Enter candidate party: ")
            add_candidate(name, party)
        elif choice == "2":
            list_candidates()
        elif choice == "3":
            candidate_id = int(input("Enter candidate ID to delete: "))
            delete_candidate(candidate_id)
        elif choice == "4":
            voter_id = input("Enter your Voter ID: ")
            candidate_id = int(input("Enter the Candidate ID you want to vote for: "))
            cast_vote(voter_id, candidate_id)
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
