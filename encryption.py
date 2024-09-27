import hashlib
import os
import csv
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from bcrypt import hashpw, gensalt
from argon2 import PasswordHasher

# Function to generate ECC and RSA key pairs
def generate_key_pairs():
    ecc_key = ECC.generate(curve='P-256')
    rsa_key = RSA.generate(2048)
    return ecc_key, rsa_key

# Function to encrypt the shared secret with RSA
def rsa_encrypt_shared_secret(rsa_public_key, shared_secret):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    return cipher_rsa.encrypt(shared_secret)

# Function to perform AES encryption
def aes_encrypt(aes_key, data):
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return ciphertext, tag

# Function to perform ChaCha20 encryption
def chacha20_encrypt(chacha20_key, data):
    cipher_chacha20 = ChaCha20.new(key=chacha20_key)
    return cipher_chacha20.encrypt(data)

# Function to hash data using bcrypt and Argon2
def hash_with_bcrypt_and_argon2(aes_key, chacha20_key, ciphertext_chacha20):
    bcrypt_hashed_keys = hashpw(aes_key + chacha20_key, gensalt())
    ph = PasswordHasher()
    argon2_hashed_ciphertext = ph.hash(ciphertext_chacha20)
    return bcrypt_hashed_keys, argon2_hashed_ciphertext

# Function to perform the encryption process
def encryption_process(user, password):
    try:
        # Step 1: Key Generation and Exchange
        ecc_key, rsa_key = generate_key_pairs()
        rsa_public_key = rsa_key.publickey()

        # Simulated Diffie-Hellman Shared Secret
        shared_secret = os.urandom(32)

        # Encrypt shared secret with RSA
        encrypted_shared_secret = rsa_encrypt_shared_secret(rsa_public_key, shared_secret)

        # Step 2: Symmetric Encryption (AES and ChaCha20)
        aes_key = hashlib.sha256(shared_secret).digest()
        ciphertext, _ = aes_encrypt(aes_key, password)

        # Apply ChaCha20 encryption
        chacha20_key = hashlib.sha256(aes_key).digest()
        ciphertext_chacha20 = chacha20_encrypt(chacha20_key, ciphertext)

        # Step 3: Data Integrity and Authentication
        data_hash = hashlib.sha256(password).hexdigest()
        bcrypt_hashed_keys, argon2_hashed_ciphertext = hash_with_bcrypt_and_argon2(aes_key, chacha20_key, ciphertext_chacha20)

        # Save encrypted data
        data_list = [user, encrypted_shared_secret.hex(), ciphertext_chacha20.hex(), data_hash, bcrypt_hashed_keys.decode('utf-8'), argon2_hashed_ciphertext]
        data_storage(data_list)

    except Exception as e:
        print(f"An error occurred during encryption: {e}")

# Function to store encrypted data in CSV
def data_storage(data_list):
    file_path = 'data_file.csv'
    try:
        # Write encrypted data to CSV file
        with open(file_path, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(data_list)
        print("Data added successfully.")
    except Exception as e:
        print(f"An error occurred while saving data: {e}")

# Main function for user interaction
def main():
    print("Welcome to the Secure Encryption Tool")
    user = input("Enter user name: ").strip()
    
    if not user:
        print("Username cannot be empty.")
        return
    
    password = input("Enter password: ").encode('utf-8')
    if not password:
        print("Password cannot be empty.")
        return
    
    encryption_process(user=user, password=password)

if __name__ == "__main__":
    main()
#code is under development 
