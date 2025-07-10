# storage.py

import json
from typing import Dict
from integrity import derive_hmac_key, sign_data, verify_data
from drive_sync import upload_bytes, download_bytes

def save_vault(vault: Dict, master_password: str) -> None:
    """
    Serialize the vault in-memory, HMAC-sign it, and push both
    vault.json and vault.json.sig directly to Google Drive.
    No local files are written.
    """
    # 1) Ensure vault contains a consistent salt, derive the HMAC key
    key = derive_hmac_key(master_password, vault)

    # 2) Dump vault JSON to bytes
    vault_bytes = json.dumps(vault, indent=2).encode("utf-8")

    # 3) Compute signature (base64 string → bytes)
    sig_str   = sign_data(vault_bytes, key)
    sig_bytes = sig_str.encode("utf-8")

    # 4) Upload both artifacts to Drive (best-effort, log errors)
    try:
        upload_bytes("vault.json",     vault_bytes, "application/json")
        upload_bytes("vault.json.sig", sig_bytes,   "text/plain")
    except Exception as e:
        print(f"⚠️  Drive sync failed: {e}")

def load_vault(master_password: str) -> Dict:
    """
    Pull vault.json and vault.json.sig from Google Drive, verify integrity,
    and return the vault dict. Raises on missing remote vault or signature mismatch.
    """
    # 1) Download raw bytes from Drive
    try:
        vault_bytes = download_bytes("vault.json")
        sig_bytes   = download_bytes("vault.json.sig")
    except FileNotFoundError:
        # No remote vault yet
        return {
            "users": {},
            "password_vault": {},
            "details_vault": {},
            "audit_log": []
        }
    except Exception as e:
        print(f"⚠️  Drive load failed: {e}")
        raise

    # 2) Parse JSON and signature
    vault_str = vault_bytes.decode("utf-8")
    vault     = json.loads(vault_str)
    sig_str   = sig_bytes.decode("utf-8")

    # 3) Re-derive HMAC key & verify
    key = derive_hmac_key(master_password, vault)
    if not verify_data(vault_bytes, sig_str, key):
        raise ValueError("Vault signature mismatch! Wrong password or possible tampering.")

    return vault
