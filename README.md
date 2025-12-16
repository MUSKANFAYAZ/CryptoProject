#  AES-256 File Vault (GCM Mode)

This is a Python script that provides secure, authenticated file encryption and decryption using the Advanced Encryption Standard (AES) with a 256-bit key in Galois/Counter Mode (GCM). The script is designed to process files located in a designated `secret` folder and securely deletes the original file immediately after successful processing (either encryption or decryption).

## ✨ Features

* **AES-256 GCM:** Uses a highly secure, authenticated encryption mode (GCM) which ensures both confidentiality and integrity.
* **Key Derivation:** Uses **Scrypt** to securely derive the 256-bit encryption key from a user password, protecting against brute-force attacks.
* **File Handling:** Encrypts and decrypts entire files (`.txt`, `.pdf`, `.jpg`, etc.).
* **Secure Deletion:** Overwrites the original file with random data before deletion to prevent simple data recovery.
* **Dedicated Commands:** Uses separate command-line arguments for encryption and decryption.

## ⚙️ Setup and Installation

### 1. Prerequisites

You must have Python 3.8+ installed on your system.

### 2. Install Dependencies

This project requires the `pycryptodome` library. Open your terminal in the project directory and run:

```bash
pip install pycryptodome
```
### 3. 🔑 Encryption
To encrypt a plaintext file (e.g., my_plans.txt) located in the secret folder.

Command:

```Bash

#### General Syntax:
python fileVault.py encrypt <filename>

#### Example (Assuming your working Python is in your PATH):
python fileVault.py encrypt my_plans.txt
```
### 4.🔓 Decryption
To decrypt a ciphertext file (e.g., my_plans.txt.enc) located in the secret folder.

Command:

```Bash

#### General Syntax:
python fileVault.py decrypt <filename.enc>

#### Example:
python fileVault.py decrypt my_plans.txt.enc
```
