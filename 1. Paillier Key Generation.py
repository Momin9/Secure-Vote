# 1. PHE_Key_Generation.py
from phe import paillier
import pickle

def generate_paillier_keys():
    # Generate Paillier key pair
    public_key, private_key = paillier.generate_paillier_keypair()

    # Save the public key to a file
    with open("public_key.pem", "wb") as pub_file:
        pickle.dump(public_key, pub_file)
    
    # Save the private key to a file
    with open("private_key.pem", "wb") as priv_file:
        pickle.dump(private_key, priv_file)

    print("Paillier keys generated and saved as public_key.pem and private_key.pem.")

generate_paillier_keys()
