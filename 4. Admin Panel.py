# Admin_Panel.py
import sqlite3
import pickle
from phe import paillier

# Admin credentials
ADMIN_ID = "admin"
ADMIN_PASSWORD = "admin123"

# Load the public key
def load_public_key():
    with open("public_key.pem", "rb") as f:
        public_key = pickle.load(f)
    return public_key

# Load the private key for decryption
def load_private_key():
    with open("private_key.pem", "rb") as f:
        private_key = pickle.load(f)
    return private_key

# Tally votes by decrypting and counting
def tally_votes():
    conn = sqlite3.connect('votes.db')
    cursor = conn.cursor()

    public_key = load_public_key()
    private_key = load_private_key()

    # Retrieve the encrypted tallies
    cursor.execute("SELECT candidate_a_tally, candidate_b_tally FROM encrypted_tally")
    candidate_a_tally_blob, candidate_b_tally_blob = cursor.fetchone()

    # Convert blobs to integers for decryption
    candidate_a_tally_enc = int.from_bytes(candidate_a_tally_blob, byteorder='big')
    candidate_b_tally_enc = int.from_bytes(candidate_b_tally_blob, byteorder='big')

    # Decrypt the tallies
    candidate_a_tally = private_key.decrypt(paillier.EncryptedNumber(public_key, candidate_a_tally_enc))
    candidate_b_tally = private_key.decrypt(paillier.EncryptedNumber(public_key, candidate_b_tally_enc))

    # Display the tally
    print("\nVote Tally:")
    print(f"Candidate A: {candidate_a_tally} votes")
    print(f"Candidate B: {candidate_b_tally} votes")

    conn.close()

# Main function for admin authentication and tally
def main():
    admin_id = input("Enter admin ID: ")
    admin_password = input("Enter admin password: ")

    # Check admin credentials
    if admin_id == ADMIN_ID and admin_password == ADMIN_PASSWORD:
        tally_votes()
    else:
        print("Invalid admin credentials.")

if __name__ == "__main__":
    main()
