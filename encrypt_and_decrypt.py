import base64
import os
import sys
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file():
    password = getpass.getpass("Enter password to encrypt: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    api_key = input("Enter API key to encrypt: ").encode()
    encrypted = fernet.encrypt(api_key)

    with open("encrypted.txt", "wb") as ef:
        ef.write(salt + encrypted)  # prepend salt

    print("✅ Encrypted and saved to 'encrypted.txt'")

def decrypt_file():
    password = getpass.getpass("Enter password to decrypt: ")

    with open("encrypted.txt", "rb") as ef:
        data = ef.read()
        salt, encrypted = data[:16], data[16:]

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted).decode()
        print("🔓 Decrypted API Key:", decrypted)
    except Exception as e:
        print("❌ Decryption failed. Wrong password or corrupted file.")

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("--encrypt", "--decrypt"):
        print("Usage: python secret_tool.py --encrypt | --decrypt")
        sys.exit(1)

    if sys.argv[1] == "--encrypt":
        encrypt_file()
    else:
        decrypt_file()

