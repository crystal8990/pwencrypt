# password_vault.py

import json
from typing import Dict
from getpass import getpass

from crypto_utils import encrypt_bytes, decrypt_bytes
from storage import save_vault
from audit_logger import log_event

# Try to import clear_screen from main.py.
# If that fails (e.g., during isolated testing), define it here.
try:
    from main import clear_screen
except ImportError:
    import os
    def clear_screen():
        os.system("cls" if os.name == "nt" else "clear")


def add_password(
    vault: Dict,
    username: str,
    vault_key: bytes,
    master_password: str
) -> None:
    svc      = input("Service name: ").strip()
    svc_user = input("Service username: ").strip()
    svc_pw   = getpass("Service password: ")

    payload = json.dumps({"user": svc_user, "secret": svc_pw}).encode()
    token   = encrypt_bytes(vault_key, payload)

    vault.setdefault("password_vault", {}).setdefault(username, {})
    vault["password_vault"][username][svc] = token

    save_vault(vault, master_password)
    print(f"✅ [{svc}] saved.\n")

    log_event(vault, username, "add_password", True,
              master_password, {"service": svc})


def get_passwords(
    vault: Dict,
    username: str,
    vault_key: bytes
) -> None:
    user_store = vault.get("password_vault", {}).get(username, {})
    if not user_store:
        print("⚠️  No services stored.\n")
        return

    print("-- Your Password Vault --")
    for svc, token in user_store.items():
        try:
            blob = decrypt_bytes(vault_key, token)
            entry = json.loads(blob)
            print(f"• {svc:15} | user: {entry['user']:15} | pw: {entry['secret']}")
        except Exception:
            print(f"⚠️  Failed to decrypt [{svc}]")
    print()


def del_password(
    vault: Dict,
    username: str,
    master_password: str
) -> None:
    user_store = vault.get("password_vault", {}).get(username, {})
    if not user_store:
        print("⚠️  No services to delete.\n")
        return

    svc = input("Service name to delete: ").strip()
    if svc in user_store:
        del vault["password_vault"][username][svc]
        save_vault(vault, master_password)
        print(f"🗑️  [{svc}] deleted.\n")
        log_event(vault, username, "delete_password", True,
                  master_password, {"service": svc})
    else:
        print("❌ Service not found.\n")


def edit_password(
    vault: Dict,
    username: str,
    vault_key: bytes,
    master_password: str
) -> None:
    user_store = vault.get("password_vault", {}).get(username, {})
    if not user_store:
        print("⚠️  No services stored.\n")
        return

    svc = input("Service name to edit: ").strip()
    if svc not in user_store:
        print("❌ Service not found.\n")
        return

    try:
        blob = decrypt_bytes(vault_key, user_store[svc])
        entry = json.loads(blob)
    except Exception:
        print(f"⚠️  Failed to decrypt [{svc}]. Cannot edit.\n")
        return

    print(f"Current service username: {entry.get('user', '')}")
    new_user = input("New service username (leave blank to keep current): ").strip()
    new_pw   = getpass("New service password (leave blank to keep current): ")

    if new_user:
        entry['user'] = new_user
    if new_pw:
        entry['secret'] = new_pw

    payload = json.dumps(entry).encode()
    token   = encrypt_bytes(vault_key, payload)
    vault["password_vault"][username][svc] = token

    save_vault(vault, master_password)
    print(f"✅ [{svc}] updated.\n")
    log_event(vault, username, "edit_password", True,
              master_password, {"service": svc})


def password_menu(
    vault: Dict,
    username: str,
    vault_key: bytes,
    master_password: str
) -> None:
    while True:
        clear_screen()
        print("Password Vault Menu:")
        print(" 1) Add service")
        print(" 2) View services")
        print(" 3) Delete service")
        print(" 4) Edit password")
        print(" 5) Back to main menu")
        choice = input("> ").strip()

        if choice == "1":
            add_password(vault, username, vault_key, master_password)
            input("Press Enter to continue...")
        elif choice == "2":
            get_passwords(vault, username, vault_key)
            input("Press Enter to continue...")
        elif choice == "3":
            del_password(vault, username, master_password)
            input("Press Enter to continue...")
        elif choice == "4":
            edit_password(vault, username, vault_key, master_password)
            input("Press Enter to continue...")
        elif choice == "5":
            break
        else:
            print("❓ Invalid choice.\n")
            input("Press Enter to continue...")
