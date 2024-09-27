# 🔐 **Secure Encryption Tool**

Welcome to the **Secure Encryption Tool** — a Python-based utility designed to encrypt sensitive information using state-of-the-art cryptographic algorithms. This tool leverages **RSA**, **AES**, **ChaCha20**, **bcrypt**, and **Argon2** to ensure your data remains protected and tamper-proof.

---

## 🚀 **Features**

- **ECC & RSA Key Generation**: Generate elliptic curve (ECC) and RSA key pairs for robust encryption.
- **Symmetric Encryption with AES & ChaCha20**: Encrypt data using **AES** and further protect it with **ChaCha20**.
- **Multiple Layers of Hashing**:
  - **bcrypt**: Securely hash encryption keys.
  - **Argon2**: Hash the final ciphertext for added protection.
- **Data Integrity**: Uses **SHA-256** to ensure the integrity of the original data.
- **CSV Storage**: Encrypted data is stored securely in a CSV file.

---

## 🛠️ **How It Works**

### 🔑 Key Generation & Encryption
1. **ECC & RSA Keys**: The tool generates ECC and RSA key pairs.
2. **Shared Secret**: A simulated Diffie-Hellman shared secret is generated.
3. **RSA Encryption**: The shared secret is encrypted with RSA for secure key exchange.
4. **AES & ChaCha20**: Data is first encrypted with **AES** (GCM mode) and then further encrypted with **ChaCha20**.

### 🔒 Data Integrity & Hashing
- The encrypted data is hashed with **SHA-256** to ensure it hasn't been tampered with.
- The encryption keys are hashed using **bcrypt**, while the final ciphertext is hashed with **Argon2**, providing two layers of cryptographic security.

### 📝 Secure Storage
- The tool stores the encrypted data and related information in a **CSV file** for secure logging and future access.

---

## 💻 **Usage**

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/secure-encryption-tool.git
   cd secure-encryption-tool
   ```

2. **Install the Dependencies**:
   Make sure to have Python installed and run the following command:
   ```bash
   pip install pycryptodome bcrypt argon2-cffi
   ```

3. **Run the Script**:
   Simply run the Python script:
   ```bash
   python encryption_tool.py
   ```

---

## 🧑‍💻 **How to Use the Tool**

1. **Run the script** and follow the prompts:
   - Enter your **username**.
   - Enter the **password** (this will be encrypted).

2. The tool will:
   - Generate encryption keys.
   - Encrypt the password with **AES** and **ChaCha20**.
   - Hash the keys using **bcrypt**.
   - Hash the encrypted data with **Argon2**.

3. Your encrypted data will be saved in a CSV file for secure storage:
   - **Encrypted shared secret** (RSA).
   - **Double-encrypted password** (AES + ChaCha20).
   - **Hash of original data** (SHA-256).
   - **bcrypt hash of keys**.
   - **Argon2 hash of ciphertext**.

---

## 🔐 **Security Overview**

### Key Features:
- **AES (GCM)**: Used for fast, secure encryption with authentication tags.
- **ChaCha20**: Adds another layer of encryption, providing resistance against timing attacks.
- **RSA Encryption**: Secures the shared secret for key exchange.
- **bcrypt & Argon2**: Top-tier password hashing algorithms to safeguard your keys and encrypted data.
- **SHA-256**: Provides a cryptographic hash to verify data integrity.

### Why It’s Secure:
- The **combination of RSA for key exchange** and **AES + ChaCha20 for encryption** ensures that your sensitive data is protected from a wide range of cryptographic attacks.
- The **use of bcrypt and Argon2** strengthens key protection and defends against brute-force attacks.
- The tool uses **multiple layers of hashing** and encryption, making it difficult for attackers to access your data even if they compromise a single layer.

---

## 📁 **CSV Data Storage Format**

Encrypted data is stored in a CSV file with the following format:

```plaintext
[username, encrypted_shared_secret, encrypted_password, data_hash, bcrypt_hashed_keys, argon2_hashed_ciphertext]
```

Example entry:
```csv
alice, abc1234deadbeef..., abc4567encrypted..., d2f24530fa45..., $2b$12$hashedkeydata, $argon2id$v=19...
```

---

## 🔧 **Future Enhancements**

- **Decryption Feature**: Implement the ability to decrypt data using the stored RSA private key.
- **Multi-User Support**: Extend to support multiple user profiles with independent key pairs.
- **Key Management**: Add the ability to export and import encryption keys securely.
- **Detailed Logging**: Implement advanced logging for tracking encryption events.

---

## 🛡️ **Disclaimer**

This tool is intended for educational purposes and basic encryption tasks. It should not be used in high-security environments without additional review and enhancement. Always ensure that you handle encryption keys and sensitive data responsibly.

---

## ✨ **Contributions & Support**

Feel free to contribute to the project or report any issues via GitHub. Contributions, bug reports, and suggestions are always welcome!

---
