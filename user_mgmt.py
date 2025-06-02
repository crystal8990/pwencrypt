import json
from getpass import getpass
import os

from crypto_utils import derive_key, generate_key, encrypt_bytes, decrypt_bytes
from audit_logger import log_event


def create_account(vault: dict) -> None:
    """
    Create a new account using a wrapped-key system.
    A permanent master vault key is generated and then wrapped (encrypted) using an ephemeral
    key derived from the user's password. The salt used for deriving the ephemeral key
    is stored.
    """
    print("=== Create Account ===")
    username = input("Username: ").strip()

    # Check if username already exists
    if username in vault.get("users", {}):
        print("❌ User already exists.\n")
        log_event(vault, username, "create_account", False, {"reason": "User already exists"})
        return

    password = getpass("Enter password: ").strip()
    confirm  = getpass("Confirm password: ").strip()
    if password != confirm:
        print("❌ Passwords do not match.\n")
        log_event(vault, username, "create_account", False, {"reason": "Passwords do not match"})
        return

    # Derive an ephemeral key from the user's password (and generate a salt)
    ephemeral_key, salt = derive_key(password)
    
    # Generate a permanent (master) vault key that will be used for all encryption/decryption of data.
    master_key = generate_key()  # This is your permanent vault key.
    
    # Wrap (encrypt) the master key using the ephemeral key.
    wrapped_key = encrypt_bytes(ephemeral_key, master_key)
    
    # Store the salt and wrapped master key in the user's record.
    user_data = {
        "pwd_salt": salt.hex(),         # Store the ephemeral salt as hex.
        "wrapped_key": wrapped_key      # Store the wrapped master key.
    }
    vault.setdefault("users", {})[username] = user_data

    print("✅ Account created successfully.\n")
    log_event(vault, username, "create_account", True)


def login(vault: dict) -> (str, bytes):
    """
    Log in a user using the wrapped-key system.
    The user's password is used to derive an ephemeral key (using the stored salt),
    which is then used to unwrap (decrypt) the permanent master key.
    Returns (username, master_key) on success; otherwise, (None, None).
    """
    print("=== Login ===")
    username = input("Username: ").strip()

    if username not in vault.get("users", {}):
        print("❌ User does not exist.\n")
        log_event(vault, username, "login", False, {"reason": "User not found"})
        return None, None

    password = getpass("Enter password: ").strip()
    user_data = vault["users"][username]

    # Ensure the salt and wrapped key exist.
    if "pwd_salt" not in user_data or "wrapped_key" not in user_data:
        print("❌ Missing credentials info (salt/wrapped key) in user data.\n")
        log_event(vault, username, "login", False, {"reason": "Missing wrapped key or salt"})
        return None, None

    try:
        salt = bytes.fromhex(user_data["pwd_salt"])
    except Exception as e:
        print("❌ Invalid stored salt.\n")
        log_event(vault, username, "login", False, {"reason": "Salt format error"})
        return None, None

    try:
        # Derive the ephemeral key using the user's password and stored salt.
        ephemeral_key, _ = derive_key(password, salt)
    except Exception as e:
        print("❌ Error during key derivation.\n")
        log_event(vault, username, "login", False, {"reason": "Key derivation error", "exception": str(e)})
        return None, None

    try:
        # Unwrap (decrypt) the master vault key using the ephemeral key.
        master_key = decrypt_bytes(ephemeral_key, user_data["wrapped_key"])
    except Exception as e:
        print("❌ Failed to unwrap master key. Possibly wrong password?\n")
        log_event(vault, username, "login", False, {"reason": "Unwrap failed", "exception": str(e)})
        return None, None

    print("✅ Login successful!\n")
    log_event(vault, username, "login", True)
    return username, master_key


def recover_account(vault: dict) -> None:
    """
    Recover a user's account via password reset using the wrapped-key system.
    The user first logs in with the old password to unwrap the master key.
    Then, using a new password, a new ephemeral key is derived, and the master key is re-wrapped.
    """
    print("=== Recover Account ===")
    username = input("Username: ").strip()
    if username not in vault.get("users", {}):
        print("❌ User does not exist.\n")
        log_event(vault, username, "recover_account", False, {"reason": "User not found"})
        return

    # Verify the current password to unwrap the master key.
    print("Please log in with your current password.")
    old_username, master_key = login(vault)
    if master_key is None:
        print("❌ Failed to verify current password. Recovery aborted.\n")
        return

    # Prompt for the new password.
    new_password = getpass("Enter new password: ").strip()
    confirm = getpass("Confirm new password: ").strip()
    if new_password != confirm:
        print("❌ Passwords do not match.\n")
        log_event(vault, username, "recover_account", False, {"reason": "Passwords don't match"})
        return

    # Derive a new ephemeral key from the new password (and generate a new salt).
    new_ephemeral_key, new_salt = derive_key(new_password)
    
    # Re-wrap the same permanent master key using the new ephemeral key.
    new_wrapped_key = encrypt_bytes(new_ephemeral_key, master_key)

    # Update the stored salt and wrapped key.
    vault["users"][username]["pwd_salt"] = new_salt.hex()
    vault["users"][username]["wrapped_key"] = new_wrapped_key

    print("✅ Account recovery successful!\n")
    log_event(vault, username, "recover_account", True)
