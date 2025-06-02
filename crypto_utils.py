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
    # DEBUG: show a prefix of the token and the key used
    print(f"[DEBUG ENCRYPT] token[:32]={token[:32]!r}…  key_prefix={vault_key[:8]!r}")
    return token.decode('utf-8')

def decrypt_bytes(vault_key: bytes, token: str) -> bytes:
    """
    Decrypt the given token (str) using the provided vault_key.
    Returns the decrypted plaintext (bytes).
    """
    f = Fernet(vault_key)
    raw = token.encode('utf-8')
    # DEBUG: show what we're about to decrypt
    print(f"[DEBUG DECRYPT] token[:32]={raw[:32]!r}…  key_prefix={vault_key[:8]!r}")
    plaintext = f.decrypt(raw)
    return plaintext

def generate_key() -> bytes:
    """
    Generate and return a new random Fernet key.
    """
    key = Fernet.generate_key()
    print(f"[DEBUG GENERATE_KEY] new_key={key!r}")
    return key

def derive_key(password: str, salt: bytes = None, iterations: int = 100_000) -> (bytes, bytes):
    """
    Derive a Fernet key from a password.
    Returns (fernet_key, salt).
    """
    # 1) Generate a fresh salt if none provided
    if salt is None:
        salt = os.urandom(16)
        print(f"[DEBUG DERIVE_KEY] generated salt(hex)={salt.hex()}")

    # 2) Build the KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    # 3) Derive the raw key bytes
    raw_key = kdf.derive(password.encode('utf-8'))

    # 4) Encode for Fernet
    fernet_key = base64.urlsafe_b64encode(raw_key)

    # DEBUG: show parameters and result
    print(f"[DEBUG DERIVE_KEY]")
    print(f"  iterations={iterations}")
    print(f"  salt(hex)={salt.hex()}")
    print(f"  derived fernet_key={fernet_key!r}")

    return fernet_key, salt
