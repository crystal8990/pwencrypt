# details_vault.py

import json
from typing import Dict
from getpass import getpass

from crypto_utils import encrypt_bytes, decrypt_bytes
from storage      import save_vault
from audit_logger import log_event

# Try to import clear_screen from main.py; if unavailable, define it locally.
try:
    from main import clear_screen
except ImportError:
    import os

    def clear_screen():
        os.system("cls" if os.name == "nt" else "clear")


def add_detail(
    vault: Dict,
    username: str,
    vault_key: bytes,
    master_password: str
) -> None:
    """
    Add a new detail under a service.
    """
    service     = input("Service name: ").strip()
    detail_type = input("Detail type: ").strip()
    detail_val  = input("Detail value: ").strip()

    payload = json.dumps({"detail": detail_val}).encode()
    token   = encrypt_bytes(vault_key, payload)

    vault.setdefault("details_vault", {}) \
         .setdefault(username, {}) \
         .setdefault(service, {})[detail_type] = token

    save_vault(vault, master_password)
    print(f"✅ [{detail_type}] added under service [{service}].\n")

    log_event(
        vault,
        username,
        "add_detail",
        True,
        master_password,
        {"service": service, "detail_type": detail_type}
    )


def get_details(
    vault: Dict,
    username: str,
    vault_key: bytes
) -> None:
    """
    Decrypt and display all detail entries for a chosen service.
    """
    user_store = vault.get("details_vault", {}).get(username, {})
    if not user_store:
        print("⚠️  No details stored.\n")
        return

    print("-- Services --")
    for svc in user_store:
        print(f"• {svc}")
    service = input("Choose service: ").strip()

    if service not in user_store:
        print("❌ Service not found.\n")
        return

    items = user_store[service]
    if not items:
        print(f"⚠️  No details in service [{service}].\n")
        return

    print(f"-- Details for [{service}] --")
    for dtype, token in items.items():
        try:
            blob  = decrypt_bytes(vault_key, token)
            entry = json.loads(blob)
            print(f"• {dtype:15} | value: {entry['detail']}")
        except Exception:
            print(f"⚠️  Failed to decrypt [{dtype}]")
    print()


def del_detail(
    vault: Dict,
    username: str,
    master_password: str
) -> None:
    """
    Delete a specific detail entry.
    """
    user_store = vault.get("details_vault", {}).get(username, {})
    if not user_store:
        print("⚠️  No details stored.\n")
        return

    service = input("Service name to delete from: ").strip()
    if service not in user_store:
        print("❌ Service not found.\n")
        return

    detail_type = input("Detail type to delete: ").strip()
    if detail_type in user_store[service]:
        del vault["details_vault"][username][service][detail_type]
        # Remove the service if it becomes empty.
        if not vault["details_vault"][username][service]:
            del vault["details_vault"][username][service]
        save_vault(vault, master_password)
        print(f"🗑️  [{detail_type}] deleted from service [{service}].\n")
        log_event(
            vault,
            username,
            "delete_detail",
            True,
            master_password,
            {"service": service, "detail_type": detail_type}
        )
    else:
        print("❌ Detail type not found.\n")


def edit_detail(
    vault: Dict,
    username: str,
    vault_key: bytes,
    master_password: str
) -> None:
    """
    Edit an existing detail entry.
    """
    user_store = vault.get("details_vault", {}).get(username, {})
    if not user_store:
        print("⚠️  No details stored.\n")
        return

    service = input("Service name to edit: ").strip()
    if service not in user_store:
        print("❌ Service not found.\n")
        return

    detail_type = input("Detail type to edit: ").strip()
    if detail_type not in user_store[service]:
        print("❌ Detail type not found.\n")
        return

    try:
        blob  = decrypt_bytes(vault_key, user_store[service][detail_type])
        entry = json.loads(blob)
    except Exception:
        print(f"⚠️  Failed to decrypt [{detail_type}]. Cannot edit.\n")
        return

    print(f"Current value: {entry['detail']}")
    new_val = input("New detail value (leave blank to keep current): ").strip()
    if new_val:
        entry['detail'] = new_val
        payload = json.dumps(entry).encode()
        token   = encrypt_bytes(vault_key, payload)
        vault["details_vault"][username][service][detail_type] = token
        save_vault(vault, master_password)
        print(f"✅ [{detail_type}] updated under service [{service}].\n")
        log_event(
            vault,
            username,
            "edit_detail",
            True,
            master_password,
            {"service": service, "detail_type": detail_type}
        )
    else:
        print("No changes made.\n")


def details_menu(
    vault: Dict,
    username: str,
    vault_key: bytes,
    master_password: str
) -> None:
    """
    Looping menu for details-vault operations.
    """
    while True:
        clear_screen()
        print("Details Vault Menu:")
        print(" 1) Add detail")
        print(" 2) View details")
        print(" 3) Delete detail")
        print(" 4) Edit detail")
        print(" 5) Back to main menu")
        choice = input("> ").strip()

        if choice == "1":
            add_detail(vault, username, vault_key, master_password)
            input("Press Enter to continue...")
        elif choice == "2":
            get_details(vault, username, vault_key)
            input("Press Enter to continue...")
        elif choice == "3":
            del_detail(vault, username, master_password)
            input("Press Enter to continue...")
        elif choice == "4":
            edit_detail(vault, username, vault_key, master_password)
            input("Press Enter to continue...")
        elif choice == "5":
            break
        else:
            print("❓ Invalid choice.\n")
            input("Press Enter to continue...")
