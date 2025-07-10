# integrity.py

import base64
import hashlib
import hmac
import secrets
from typing import Dict

# KDF parameters
PBKDF2_ITERATIONS = 200_000
KEY_LEN = 32  # 256-bit HMAC key

def _get_or_create_salt(vault: Dict) -> bytes:
    """
    Retrieve the base64-encoded salt from vault["hmac_salt"],
    or generate and store a new 16-byte salt if missing.
    """
    b64 = vault.get("hmac_salt")
    if b64:
        return base64.b64decode(b64)
    salt = secrets.token_bytes(16)
    vault["hmac_salt"] = base64.b64encode(salt).decode("utf-8")
    return salt

def derive_hmac_key(master_password: str, vault: Dict) -> bytes:
    """
    Derive a consistent HMAC key from the master password + vault salt.
    Ensures vault["hmac_salt"] exists for portability.
    """
    salt = _get_or_create_salt(vault)
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LEN
    )

def sign_data(data: bytes, key: bytes) -> str:
    """
    Compute an HMAC-SHA256 over `data` using `key`.
    Returns a Base64-encoded signature string.
    """
    sig = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("utf-8")

def verify_data(data: bytes, signature: str, key: bytes) -> bool:
    """
    Verify that `signature` (Base64) matches HMAC-SHA256(data, key).
    Returns True on match, False otherwise.
    """
    try:
        sig_bytes = base64.b64decode(signature)
    except Exception:
        return False
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig_bytes)
