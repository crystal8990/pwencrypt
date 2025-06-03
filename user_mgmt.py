import json
from getpass import getpass
import os

from crypto_utils import derive_key, generate_key, encrypt_bytes, decrypt_bytes
from audit_logger import log_event


def create_account(vault: dict) -> None:
    """
    Create a new account using a wrapped-key system with a permanent recovery code.
    
    A permanent master vault key is generated and then wrapped using:
      - A primary ephemeral key derived from the user's password.
      - A secondary ephemeral key derived from a randomly generated permanent recovery code.
    
    The primary wrapper (with its salt) is used for normal login, while the
    secondary recovery wrapper (with its own salt) is stored for account recovery.
    The recovery code is shown to the user and must be stored safely.
    """
    print("=== Create Account ===")
    username = input("Username: ").strip()

    # Check if username already exists
    if username in vault.get("users", {}):
        print("❌ User already exists.\n")
        log_event(vault, username, "create_account", False, {"reason": "User already exists"})
        return

    password = getpass("Enter password: ").strip()
    confirm = getpass("Confirm password: ").strip()
    if password != confirm:
        print("❌ Passwords do not match.\n")
        log_event(vault, username, "create_account", False, {"reason": "Passwords do not match"})
        return

    # Derive an ephemeral key from the user's password (and generate a salt)
    primary_ephemeral, pwd_salt = derive_key(password)
    
    # Generate a permanent (master) vault key used for all encryption/decryption of data.
    master_key = generate_key()
    
    # Wrap (encrypt) the master key using the primary ephemeral key.
    wrapped_key = encrypt_bytes(primary_ephemeral, master_key)
    
    # --- Implement Secondary Wrapper Based on Permanent Recovery Code ---
    # Generate a random permanent recovery code (e.g. a random 16-character hex string).
    recovery_code = os.urandom(8).hex()
    # Derive a recovery ephemeral key (with its own salt) from the recovery code.
    recovery_ephemeral, recovery_salt = derive_key(recovery_code)
    # Wrap the master key using the recovery ephemeral key.
    recovery_wrapper = encrypt_bytes(recovery_ephemeral, master_key)
    # ----------------------------------------------------------------------
    
    # Store primary and secondary wrapper credentials.
    user_data = {
        "pwd_salt": pwd_salt.hex(),         # Salt for primary (password) derivation.
        "wrapped_key": wrapped_key,           # Primary wrapper of master key.
        "recovery_salt": recovery_salt.hex(), # Salt for recovery code derivation.
        "recovery_wrapper": recovery_wrapper  # Recovery wrapper of master key.
    }
    vault.setdefault("users", {})[username] = user_data

    print("✅ Account created successfully.\n")
    print(f"🔑 Your permanent recovery code is: {recovery_code}")
    print("Please store this recovery code safely. It will be required for account recovery.\n")
    input("Press Enter to continue...")  # New prompt added to allow the user time to note the recovery code.
    log_event(vault, username, "create_account", True)


def login(vault: dict) -> (str, bytes):
    """
    Log in a user using the wrapped-key system with password.
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

    # Ensure the primary salt and wrapped key exist.
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
        # Derive the primary ephemeral key using the password and stored salt.
        primary_ephemeral, _ = derive_key(password, salt)
    except Exception as e:
        print("❌ Error during key derivation.\n")
        log_event(vault, username, "login", False, {"reason": "Key derivation error", "exception": str(e)})
        return None, None

    try:
        # Unwrap (decrypt) the master key using the primary ephemeral key.
        master_key = decrypt_bytes(primary_ephemeral, user_data["wrapped_key"])
    except Exception as e:
        print("❌ Failed to unwrap master key. Possibly wrong password?\n")
        log_event(vault, username, "login", False, {"reason": "Unwrap failed", "exception": str(e)})
        return None, None

    print("✅ Login successful!\n")
    log_event(vault, username, "login", True)
    return username, master_key


def recover_account(vault: dict) -> None:
    """
    Recover a user's account via their permanent recovery code.
    
    Instead of verifying using the current password, the user enters their permanent
    recovery code which is used to derive a recovery ephemeral key (using the stored recovery salt)
    and unwrap (decrypt) the permanent master key from the recovery wrapper.
    
    Once the master key is successfully recovered, the user is prompted to set a new password.
    The primary (password-based) wrapper is then updated (i.e. the master key is re-wrapped using the new password)
    while the secondary recovery wrapper remains unchanged.
    """
    print("=== Recover Account ===")
    username = input("Username: ").strip()
    if username not in vault.get("users", {}):
        print("❌ User does not exist.\n")
        log_event(vault, username, "recover_account", False, {"reason": "User not found"})
        return

    user_data = vault["users"][username]
    
    if "recovery_salt" not in user_data or "recovery_wrapper" not in user_data:
        print("❌ Recovery information missing from user data.\n")
        log_event(vault, username, "recover_account", False, {"reason": "Recovery info missing"})
        return

    # Ask for the permanent recovery code.
    recovery_code_input = input("Enter your permanent recovery code: ").strip()

    try:
        recovery_salt = bytes.fromhex(user_data["recovery_salt"])
    except Exception as e:
        print("❌ Invalid stored recovery salt.\n")
        log_event(vault, username, "recover_account", False, {"reason": "Recovery salt format error"})
        return

    try:
        # Derive the recovery ephemeral key using the provided recovery code and stored recovery salt.
        recovery_ephemeral, _ = derive_key(recovery_code_input, recovery_salt)
        # Unwrap (decrypt) the master key using the recovery ephemeral key.
        master_key = decrypt_bytes(recovery_ephemeral, user_data["recovery_wrapper"])
    except Exception as e:
        print("❌ Failed to verify recovery code. Recovery aborted.\n")
        log_event(vault, username, "recover_account", False, {"reason": "Recovery code verification failed", "exception": str(e)})
        return

    # If recovery code verification succeeds, prompt for a new password.
    new_password = getpass("Enter new password: ").strip()
    confirm = getpass("Confirm new password: ").strip()
    if new_password != confirm:
        print("❌ Passwords do not match.\n")
        log_event(vault, username, "recover_account", False, {"reason": "Passwords don't match"})
        return

    # Derive a new primary ephemeral key from the new password.
    new_ephemeral, new_pwd_salt = derive_key(new_password)
    # Re-wrap the master key using the new ephemeral key.
    new_wrapped_key = encrypt_bytes(new_ephemeral, master_key)

    # Update the primary wrapper credentials (password-related salt and wrapped key).
    vault["users"][username]["pwd_salt"] = new_pwd_salt.hex()
    vault["users"][username]["wrapped_key"] = new_wrapped_key

    print("✅ Account recovery successful!\n")
    log_event(vault, username, "recover_account", True)
