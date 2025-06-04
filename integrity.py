import os
import hmac
import hashlib
import base64
import secrets
from typing import Tuple

def get_app_data_directory() -> str:
    """
    Returns the path to the SecureVault directory inside the user's APPDATA folder.
    Creates the folder if it doesn't already exist.
    """
    appdata = os.getenv("APPDATA")
    if not appdata:
        # Fallback for non-Windows systems or if APPDATA is not set.
        appdata = os.path.expanduser("~")
    base_path = os.path.join(appdata, "SecureVault")
    os.makedirs(base_path, exist_ok=True)
    return base_path

# Use the AppData folder for key and signature storage.
BASE_DIR = get_app_data_directory()
KEY_PATH = os.path.join(BASE_DIR, "hmac.key")
SIG_PATH = os.path.join(BASE_DIR, "vault.json.sig")

def init_hmac_key(length: int = 32) -> bytes:
    """
    Generate a new random HMAC key and persist it to disk.
    Returns the raw key bytes.
    """
    key = secrets.token_bytes(length)
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

def load_hmac_key() -> bytes:
    """
    Load the HMAC key from disk.
    If it doesn’t exist yet, generate & save a new one.
    """
    if not os.path.exists(KEY_PATH):
        return init_hmac_key()
    with open(KEY_PATH, "rb") as f:
        return f.read()

def sign_data(data: bytes, key: bytes) -> str:
    """
    Compute an HMAC-SHA256 over `data` using `key`.
    Returns a Base64-encoded signature string.
    """
    sig = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()

def verify_data(data: bytes, signature: str, key: bytes) -> bool:
    """
    Verify that `signature` (Base64 string) matches the HMAC of `data`.
    Returns True on match, False otherwise.
    """
    try:
        sig_bytes = base64.b64decode(signature)
    except Exception:
        return False
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(expected, sig_bytes)

def write_signature(data: bytes) -> None:
    """
    Compute HMAC over `data` and write it to the SIG_PATH file.
    Use this right after saving your vault JSON.
    """
    key = load_hmac_key()
    signature = sign_data(data, key)
    with open(SIG_PATH, "w", encoding="utf-8") as f:
        f.write(signature)

def load_signature() -> str:
    """
    Read the stored HMAC signature from disk.
    Returns an empty string if no signature file exists.
    """
    if not os.path.exists(SIG_PATH):
        return ""
    with open(SIG_PATH, "r", encoding="utf-8") as f:
        return f.read().strip()
