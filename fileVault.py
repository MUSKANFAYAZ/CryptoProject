import hashlib
import os
from pathlib import Path
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad # Required for unpadding if we used CBC, but good practice

# Configuration
KEY_LENGTH = 32 # 256 bits

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit private key from a user password and a salt using Scrypt.
    """
    return hashlib.scrypt(
        password.encode(), 
        salt=salt, 
        n=2**14, 
        r=8, 
        p=1, 
        dklen=KEY_LENGTH
    )

def secure_delete(file_path: Path):
    """
    Deletes the file and overwrites it first for basic security.
    NOTE: For high-security environments, a dedicated secure deletion tool
    should be used (like shred or sdelete). This function provides basic
    file wiping before deletion.
    """
    try:
        size = file_path.stat().st_size
        # Overwrite with zeros
        with open(file_path, 'wb') as f:
            f.write(os.urandom(size)) # Overwrite with random data
        
        # Now delete the file
        os.remove(file_path)
        print(f"✅ Securely deleted: {file_path.name}")
    except Exception as e:
        print(f"⚠️ Error during secure deletion of {file_path.name}: {e}")

def encrypt_file(input_filepath: Path, password: str) -> Path:
    """
    Encrypts the content of the input file and saves it with a .enc extension.
    It then securely deletes the original file.
    """
    # 1. Generate salt and derive the 256-bit key
    salt = get_random_bytes(AES.block_size)
    private_key = derive_key(password, salt)
    
    # 2. Create Cipher and generate Nonce
    cipher = AES.new(private_key, AES.MODE_GCM)
    nonce = cipher.nonce
    
    # 3. Read file content
    try:
        with open(input_filepath, 'rb') as f:
            plaintext_data = f.read()
    except FileNotFoundError:
        print(f"🛑 Error: Input file not found at {input_filepath}")
        return None
    
    # 4. Encrypt and generate Tag
    ciphertext_data, tag = cipher.encrypt_and_digest(plaintext_data)
    
    # 5. Assemble all components for the output file
    # We combine Salt, Nonce, Tag, and Ciphertext into the output file
    encrypted_file_content = salt + nonce + tag + ciphertext_data
    
    # 6. Write to output file
    output_filepath = input_filepath.with_suffix(input_filepath.suffix + '.enc')
    with open(output_filepath, 'wb') as f:
        f.write(encrypted_file_content)
    
    # 7. DELETE the original file (as requested)
    secure_delete(input_filepath)
    
    print(f"✅ File encrypted successfully!")
    print(f"   Original size: {len(plaintext_data)} bytes")
    print(f"   Ciphertext saved to: {output_filepath.name}")
    return output_filepath

def decrypt_file(input_filepath: Path, password: str) -> Path:
    """
    Decrypts the content of the input file (.enc) and saves it as the original file.
    It then securely deletes the ciphertext file.
    """
    # 1. Read encrypted file content
    try:
        with open(input_filepath, 'rb') as f:
            encrypted_file_content = f.read()
    except FileNotFoundError:
        print(f"🛑 Error: Ciphertext file not found at {input_filepath}")
        return None

    # 2. Separate components from the file content
    salt = encrypted_file_content[:AES.block_size] # First 16 bytes (AES.block_size)
    nonce = encrypted_file_content[AES.block_size:AES.block_size + AES.block_size] # Next 16 bytes
    tag = encrypted_file_content[2 * AES.block_size:3 * AES.block_size] # Next 16 bytes
    ciphertext_data = encrypted_file_content[3 * AES.block_size:] # The rest is ciphertext
    
    # 3. Derive the 256-bit key
    private_key = derive_key(password, salt)
    
    # 4. Create Cipher
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    
    # 5. Decrypt and Verify
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext_data, tag)
    except ValueError:
        print("🛑 Decryption FAILED! Wrong password or corrupted file.")
        return None
        
    # 6. Write to output file (remove the last '.enc' suffix)
    # We assume the file was saved with '.enc' as the LAST suffix
    original_suffix = input_filepath.suffix # Example: '.enc'
    original_filename = input_filepath.stem # Example: 'secret_file.txt'
    original_filepath = input_filepath.parent / original_filename
    
    with open(original_filepath, 'wb') as f:
        f.write(decrypted_data)

    # 7. DELETE the ciphertext file (as requested)
    secure_delete(input_filepath)
    
    print(f"✅ File decrypted successfully!")
    print(f"   Plaintext restored to: {original_filepath.name}")
    return original_filepath

# --- Command Line Interface ---

def main():
    """
    The main function to handle command line arguments for encrypt/decrypt.
    """
    import sys
    
    # Configuration
    SECRET_FOLDER = Path(__file__).parent / "secret"
    PASSWORD = "mySuperSecretPassword123"

    # Ensure the 'secret' directory exists
    SECRET_FOLDER.mkdir(exist_ok=True)
    
    print(f"\n--- AES-256 File Vault ---")
    print(f"Using secret directory: {SECRET_FOLDER}")
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  To encrypt: python fileVault.py encrypt <filename.ext>")
        print("  To decrypt: python fileVault.py decrypt <filename.ext.enc>")
        print("\nNote: Files must be inside the 'secret' folder.")
        return

    command = sys.argv[1].lower()
    filename = sys.argv[2]
    
    input_filepath = SECRET_FOLDER / filename
    
    if command == 'encrypt':
        print(f"\n🔑 Initiating ENCRYPTION for {filename}...")
        encrypt_file(input_filepath, PASSWORD)
        
    elif command == 'decrypt':
        print(f"\n🔓 Initiating DECRYPTION for {filename}...")
        decrypt_file(input_filepath, PASSWORD)
        
    else:
        print(f"🛑 Invalid command: {command}. Use 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()