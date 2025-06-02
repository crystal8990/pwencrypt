# crypto_utils.py

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt_bytes(vault_key: bytes, plaintext: bytes) -> str:
    """
    Encrypt plaintext (bytes) using the provided vault_key.
    Returns the encrypted token as a str.
    """
    f = Fernet(vault_key)
    token = f.encrypt(plaintext)
    return token.decode('utf-8')

def decrypt_bytes(vault_key: bytes, token: str) -> bytes:
    """
    Decrypt the given token (str) using the provided vault_key.
    Returns the decrypted plaintext (bytes).
    """
    f = Fernet(vault_key)
    raw = token.encode('utf-8')
    plaintext = f.decrypt(raw)
    return plaintext

def generate_key() -> bytes:
    """
    Generate and return a new random Fernet key.
    """
    return Fernet.generate_key()

def derive_key(password: str, salt: bytes = None, iterations: int = 100_000) -> (bytes, bytes):
    """
    Derive a Fernet key from a password.
    Returns (fernet_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw_key = kdf.derive(password.encode('utf-8'))
    fernet_key = base64.urlsafe_b64encode(raw_key)
    return fernet_key, salt
