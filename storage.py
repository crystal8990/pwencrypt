# storage.py

import os
import json
import shutil
from datetime import datetime
from typing import Dict

from integrity import (
    load_hmac_key, load_signature,
    verify_data, write_signature
)

def get_app_data_directory() -> str:
    """
    Returns the path to the SecureVault directory inside the user's APPDATA folder.
    Creates the directory if it doesn't already exist.
    """
    appdata = os.getenv("APPDATA")
    if not appdata:
        # Fallback for non-Windows systems or if APPDATA is not set.
        appdata = os.path.expanduser("~")
    base_path = os.path.join(appdata, "SecureVault")
    os.makedirs(base_path, exist_ok=True)
    return base_path

# Base directory for storing vault data (this should match the installer-created folder)
BASE_DIR = get_app_data_directory()
VAULT_PATH = os.path.join(BASE_DIR, "vault.json")
SIG_PATH   = os.path.join(BASE_DIR, "vault.json.sig")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")


def _ensure_backup_dir() -> None:
    if not os.path.isdir(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)


def _backup_files() -> None:
    """
    Copy the current vault.json and its .sig into backups/,
    timestamped so you can roll back.
    """
    if not os.path.exists(VAULT_PATH):
        return
    _ensure_backup_dir()
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%SZ")
    shutil.copy2(VAULT_PATH, os.path.join(BACKUP_DIR, f"vault-{ts}.json"))
    if os.path.exists(SIG_PATH):
        shutil.copy2(SIG_PATH, os.path.join(BACKUP_DIR, f"vault-{ts}.sig"))


def _list_backups() -> Dict[int, str]:
    """
    Return a numbered dict of available .json backups, newest first.
    """
    if not os.path.isdir(BACKUP_DIR):
        return {}
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.endswith(".json")],
        reverse=True
    )
    return {i + 1: files[i] for i in range(len(files))}


def _restore_backup() -> bool:
    """
    Prompt the user to pick one of the backups to restore.
    Returns True on success, False on cancel/failure.
    """
    backups = _list_backups()
    if not backups:
        print("⚠️  No backups found.")
        return False

    print("\nAvailable backups:")
    for num, fname in backups.items():
        print(f" {num}) {fname}")
    choice = input("Restore which backup? (# or Enter to cancel): ").strip()
    if not choice.isdigit() or int(choice) not in backups:
        print("Restore cancelled.")
        return False

    sel = backups[int(choice)]
    base = sel[:-5]  # strip ".json"
    json_src = os.path.join(BACKUP_DIR, sel)
    sig_src  = os.path.join(BACKUP_DIR, f"{base}.sig")

    shutil.copy2(json_src, VAULT_PATH)
    if os.path.exists(sig_src):
        shutil.copy2(sig_src, SIG_PATH)
    else:
        # Regenerate missing signature
        raw = open(VAULT_PATH, "rb").read()
        write_signature(raw)

    print(f"✅ Restored backup {sel}\n")
    return True


def load_vault() -> Dict:
    """
    1) If vault.json missing → return empty skeleton.
    2) Else read raw bytes + verify HMAC.
       • On success → json.loads → return dict.
       • On failure → prompt restore or abort.
    """
    if not os.path.exists(VAULT_PATH):
        return {
            "users": {},
            "password_vault": {},
            "details_vault": {},
            "audit_log": []
        }

    raw = open(VAULT_PATH, "rb").read()
    sig = load_signature()
    key = load_hmac_key()
    if not verify_data(raw, sig, key):
        print("⚠️  Vault integrity check FAILED! Possible tampering.")
        resp = input("Restore from backup? (y/N): ").strip().lower()
        if resp == "y" and _restore_backup():
            raw = open(VAULT_PATH, "rb").read()
        else:
            print("Aborting.")
            raise SystemExit(1)

    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        print("⚠️  Could not parse JSON after restore. Aborting.")
        raise SystemExit(1)


def save_vault(vault: Dict) -> None:
    """
    1) Backup current vault+sig into backups/
    2) Write new vault.json
    3) Compute & write new HMAC signature
    """
    # 1) rotate a backup
    _backup_files()

    # 2) dump the JSON
    raw = json.dumps(vault, indent=2).encode("utf-8")
    with open(VAULT_PATH, "wb") as f:
        f.write(raw)

    # 3) sign it
    write_signature(raw)
