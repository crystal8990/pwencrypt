# user_mgmt.py

import json
from getpass import getpass
import os

from crypto_utils import derive_key, generate_key, encrypt_bytes, decrypt_bytes
from audit_logger import log_event


def create_account(vault: dict, master_password: str) -> None:
    """
    Create a new user account with a wrapped-key system and permanent recovery code.
    """
    print("=== Create Account ===")
    username = input("Username: ").strip()

    # Check if username already exists
    if username in vault.get("users", {}):
        print("❌ User already exists.\n")
        log_event(vault, username, "create_account", False, master_password)
        return

    password = getpass("Enter password: ").strip()
    confirm = getpass("Confirm password: ").strip()
    if password != confirm:
        print("❌ Passwords do not match.\n")
        log_event(vault, username, "create_account", False, master_password)
        return

    # Derive ephemeral key from the user's password
    primary_ephemeral, pwd_salt = derive_key(password)

    # Generate the permanent master key
    master_key = generate_key()

    # Wrap the master key with the password-derived ephemeral key
    wrapped_key = encrypt_bytes(primary_ephemeral, master_key)

    # Generate and wrap with permanent recovery code
    recovery_code = os.urandom(8).hex()
    recovery_ephemeral, recovery_salt = derive_key(recovery_code)
    recovery_wrapper = encrypt_bytes(recovery_ephemeral, master_key)

    # Store user credentials
    user_data = {
        "pwd_salt":       pwd_salt.hex(),
        "wrapped_key":    wrapped_key,
        "recovery_salt":  recovery_salt.hex(),
        "recovery_wrapper": recovery_wrapper
    }
    vault.setdefault("users", {})[username] = user_data

    print("✅ Account created successfully.\n")
    print(f"🔑 Your permanent recovery code is: {recovery_code}")
    print("Store it safely; you will need it to recover your account.\n")
    input("Press Enter to continue...")

    log_event(vault, username, "create_account", True, master_password)


def login(vault: dict, master_password: str) -> (str, bytes):
    """
    Log in a user by unwrapping the master vault key with the password.
    Returns (username, master_key) on success, (None, None) on failure.
    """
    print("=== Login ===")
    username = input("Username: ").strip()

    if username not in vault.get("users", {}):
        print("❌ User does not exist.\n")
        log_event(vault, username, "login", False, master_password)
        return None, None

    password = getpass("Enter password: ").strip()
    user_data = vault["users"][username]

    # Validate stored salt and wrapped key presence
    if "pwd_salt" not in user_data or "wrapped_key" not in user_data:
        print("❌ Missing credentials info.\n")
        log_event(vault, username, "login", False, master_password)
        return None, None

    try:
        salt = bytes.fromhex(user_data["pwd_salt"])
        primary_ephemeral, _ = derive_key(password, salt)
        master_key = decrypt_bytes(primary_ephemeral, user_data["wrapped_key"])
    except Exception:
        print("❌ Login failed. Possible wrong password.\n")
        log_event(vault, username, "login", False, master_password)
        return None, None

    print("✅ Login successful!\n")
    log_event(vault, username, "login", True, master_password)
    return username, master_key


def recover_account(vault: dict, master_password: str) -> None:
    """
    Recover a user's account with their permanent recovery code, then reset password.
    """
    print("=== Recover Account ===")
    username = input("Username: ").strip()

    if username not in vault.get("users", {}):
        print("❌ User does not exist.\n")
        log_event(vault, username, "recover_account", False, master_password)
        return

    user_data = vault["users"][username]
    if "recovery_salt" not in user_data or "recovery_wrapper" not in user_data:
        print("❌ Recovery info missing.\n")
        log_event(vault, username, "recover_account", False, master_password)
        return

    code = input("Enter your permanent recovery code: ").strip()
    try:
        recovery_salt = bytes.fromhex(user_data["recovery_salt"])
        recovery_ephemeral, _ = derive_key(code, recovery_salt)
        master_key = decrypt_bytes(recovery_ephemeral, user_data["recovery_wrapper"])
    except Exception:
        print("❌ Recovery failed. Invalid code.\n")
        log_event(vault, username, "recover_account", False, master_password)
        return

    # Prompt for a new password and re-wrap the master key
    new_password = getpass("Enter new password: ").strip()
    confirm = getpass("Confirm new password: ").strip()
    if new_password != confirm:
        print("❌ Passwords do not match.\n")
        log_event(vault, username, "recover_account", False, master_password)
        return

    new_ephemeral, new_salt = derive_key(new_password)
    vault["users"][username]["pwd_salt"] = new_salt.hex()
    vault["users"][username]["wrapped_key"] = encrypt_bytes(new_ephemeral, master_key)

    print("✅ Account recovery successful!\n")
    log_event(vault, username, "recover_account", True, master_password)
