import hashlib
import os
import csv
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from bcrypt import hashpw, gensalt
from argon2 import PasswordHasher

def encrytion(user,Password):
    # Step 1: Key Generation and Exchange
    # ECC Key Pair
    ecc_key = ECC.generate(curve='P-256')

    # RSA Key Pair
    rsa_key = RSA.generate(2048)
    rsa_public_key = rsa_key.publickey()

    # Diffie-Hellman Shared Secret (simulated here as a random key for simplicity)
    shared_secret = os.urandom(32)

    # Encrypt shared secret with RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_shared_secret = cipher_rsa.encrypt(shared_secret)

    # Step 2: Symmetric Encryption
    # Derive AES key from shared secret
    aes_key = hashlib.sha256(shared_secret).digest()
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(Password)

    # Apply ChaCha20 encryption
    chacha20_key = hashlib.sha256(aes_key).digest()
    cipher_chacha20 = ChaCha20.new(key=chacha20_key)
    ciphertext_chacha20 = cipher_chacha20.encrypt(ciphertext)

    # Step 3: Data Integrity and Authentication
    # SHA-256 Hash of original data
    data_hash = hashlib.sha256(Password).hexdigest()

    # Hash AES, ChaCha20 keys with bcrypt
    bcrypt_hashed_keys = hashpw(aes_key + chacha20_key, gensalt())

    # Hash final ciphertext with Argon2
    ph = PasswordHasher()
    argon2_hashed_ciphertext = ph.hash(ciphertext_chacha20)

    # Output the results
    data_list=[user,encrypted_shared_secret.hex(),
                ciphertext_chacha20.hex(), 
                data_hash, bcrypt_hashed_keys, 
                argon2_hashed_ciphertext]
    data_storage(data_list=data_list)

def data_storage(data_list):
    file_path = 'data_file.csv'
    # Write numbers to CSV file
    with open(file_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for add_data in data_list:
            writer.writerow([add_data]) 
    print("Data added successfull")
    
# User data input
user = input("Enter user name: ")
password = input("Enter password ").encode('utf-8')
encrytion(user=user,Password=password)
a=input("end: ")
