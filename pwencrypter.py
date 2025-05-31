import os
import json
import base64
import time
from cryptography.fernet import Fernet
from getpass import getpass

VAULT_FILE = "vault_data.json"
RECOVERY_CODE = "1610"



# Ensure the vault file exists
if not os.path.exists(VAULT_FILE):
    with open(VAULT_FILE, "w") as f:
        json.dump({}, f)

# Load vault data from file
def load_vault():
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

# Save vault data to file
def save_vault(data):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Generate a Fernet key based on the permanent password
def generate_key(password):
    return base64.urlsafe_b64encode(password.encode().ljust(32)[:32])

# Encrypt text using the generated key
def encrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

# Decrypt text using the generated key
def decrypt_data(data, key):
    cipher = Fernet(key)
    return cipher.decrypt(data.encode()).decode()

# User Authentication System
def login():
    vault = load_vault()
    username = input("Enter username: ")

    if username not in vault:
        print("User not found! Create a new profile.")
        return create_profile()

    attempts = 3
    while attempts > 0:
        password = getpass("Enter Vault Password: ")

        # Check if recovery code is entered
        if password == RECOVERY_CODE:
            print("Recovery Code Entered! 🔒 Retrieving vault access...")
            vault_key = decrypt_vault_key_with_recovery(vault[username]["recovery_vault_key"])
            print(f"Vault access restored via recovery code.")
            return username, vault_key, vault

        # Validate password and decrypt vault key
        if vault[username]["password"] == password:
            vault_key = decrypt_vault_key(vault[username]["vault_key"], password)
            print(f"Welcome, {username}! 🔐 Vault Unlocked.")
            return username, vault_key, vault

        attempts -= 1
        print(f"Incorrect password! {attempts} attempt(s) remaining.")

    print("Too many failed attempts.")
    if input("Enter recovery code to reset your password: ") == RECOVERY_CODE:
        return reset_password(username)
    else:
        print("Access denied.")
        return None

# Create a new user profile
def create_profile():
    username = input("Create a username: ")
    password = getpass("Set your vault password: ")
    vault = load_vault()

    # Generate new vault key
    vault_key = generate_vault_key()

    # Encrypt vault key using master password & recovery code
    encrypted_vault_key = encrypt_vault_key(vault_key, password)
    encrypted_vault_key_recovery = encrypt_vault_key_with_recovery(vault_key)

    # Store user profile with encrypted vault key
    vault[username] = {
        "password": password,
        "vault_key": encrypted_vault_key,
        "recovery_vault_key": encrypted_vault_key_recovery,
        "passwords": {},
        "details": {}
    }

    save_vault(vault)
    print("✅ Profile created successfully!")
    return username, generate_key(password), vault

# Reset the password using recovery code 1610
def reset_password(username):
    vault = load_vault()
    if username not in vault:
        print("❌ No profile found for recovery.")
        return None

    # Retrieve current vault key using old password before resetting
    old_password = vault[username]["password"]
    vault_key = decrypt_vault_key(vault[username]["vault_key"], old_password)

    # Set new vault password
    new_password = getpass("Set a new vault password: ")
    vault[username]["password"] = new_password

    # Re-encrypt vault key with new password & recovery code
    new_encrypted_vault_key, new_encrypted_recovery_vault_key = update_vault_key_encryption(vault_key, new_password)
    vault[username]["vault_key"] = new_encrypted_vault_key
    vault[username]["recovery_vault_key"] = new_encrypted_recovery_vault_key

    save_vault(vault)
    print("🔑 Vault successfully re-encrypted with new password.")
    return username, vault_key, vault

import base64
from cryptography.fernet import Fernet

def generate_vault_key():
    return Fernet.generate_key()

import base64
from cryptography.fernet import Fernet

def encrypt_vault_key(vault_key, master_password):
    master_key = base64.urlsafe_b64encode(master_password.encode().ljust(32)[:32])
    cipher = Fernet(master_key)

    # Ensure vault_key is properly formatted as bytes before encryption
    return cipher.encrypt(vault_key.encode()).decode() if isinstance(vault_key, str) else cipher.encrypt(vault_key).decode()

import base64
from cryptography.fernet import Fernet

def encrypt_vault_key_with_recovery(vault_key):
    recovery_key = base64.urlsafe_b64encode("1610".encode().ljust(32)[:32])
    cipher = Fernet(recovery_key)

    # Convert vault_key to bytes before encryption
    return cipher.encrypt(vault_key.encode() if isinstance(vault_key, str) else vault_key).decode()

def decrypt_vault_key_with_recovery(encrypted_vault_key):
    recovery_key = base64.urlsafe_b64encode("1610".encode().ljust(32)[:32])
    cipher = Fernet(recovery_key)

    # Ensure decrypted output is a string
    return cipher.decrypt(encrypted_vault_key.encode()).decode()

import base64
from cryptography.fernet import Fernet

def decrypt_vault_key(encrypted_vault_key, master_password):
    master_key = base64.urlsafe_b64encode(master_password.encode().ljust(32)[:32])
    cipher = Fernet(master_key)

    # Ensure decryption converts bytes back into a string format
    return cipher.decrypt(encrypted_vault_key.encode()).decode()

def update_vault_key_encryption(vault_key, new_master_password):
    encrypted_key_with_new_password = encrypt_vault_key(vault_key, new_master_password)
    encrypted_key_with_recovery = encrypt_vault_key_with_recovery(vault_key)

    return encrypted_key_with_new_password, encrypted_key_with_recovery

#--------------------------------------------------
# Password Vault Functions
#--------------------------------------------------

def add_password(vault, username, key):
    service = input("Enter service name to store password: ")
    pw = input(f"Enter the password for {service}: ")
    vault[username]["passwords"][service] = encrypt_data(pw, key)
    save_vault(vault)
    print(f"🔒 Password for {service} saved securely.")

def retrieve_password(vault, username, key):
    services = list(vault[username]["passwords"].keys())
    if not services:
        print("No passwords stored.")
        return
    print("Available Services:", services)
    service = input("Select a service to retrieve password: ")
    if service in vault[username]["passwords"]:
        decrypted = decrypt_data(vault[username]["passwords"][service], key)
        print(f"🔑 Password for {service}: {decrypted}")
    else:
        print("Service not found.")

def modify_password(vault, username, key):
    services = list(vault[username]["passwords"].keys())
    if not services:
        print("No passwords stored.")
        return
    print("Available Services:", services)
    service = input("Select a service to modify password: ")
    if service in vault[username]["passwords"]:
        new_pw = input(f"Enter new password for {service}: ")
        vault[username]["passwords"][service] = encrypt_data(new_pw, key)
        save_vault(vault)
        print(f"Password for {service} updated.")
    else:
        print("Service not found.")

def delete_password(vault, username, key):
    services = list(vault[username]["passwords"].keys())
    if not services:
        print("No passwords stored.")
        return
    print("Available Services:", services)
    service = input("Select a service to delete: ")
    if service in vault[username]["passwords"]:
        confirm = input(f"Are you sure you want to delete password for {service}? (y/n): ")
        if confirm.lower() == "y":
            del vault[username]["passwords"][service]
            save_vault(vault)
            print(f"Password for {service} deleted.")
        else:
            print("Deletion cancelled.")
    else:
        print("Service not found.")

#--------------------------------------------------
# Details Vault Functions
#--------------------------------------------------

def add_details(vault, username, key):
    service = input("Enter service name for details: ")
    entry_type = input("Enter entry type: ")
    details = input("Enter details: ")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if service not in vault[username]["details"]:
        vault[username]["details"][service] = {}
    vault[username]["details"][service][entry_type] = {
        "data": encrypt_data(details, key),
        "created": timestamp,
        "modified": timestamp,
        "edit_count": 0
    }
    save_vault(vault)
    print(f"📌 Details for {service} ({entry_type}) saved securely.")

def retrieve_details(vault, username, key):
    services = list(vault[username]["details"].keys())
    if not services:
        print("No details stored.")
        return
    print("Available Services:", services)
    service = input("Select a service: ")
    if service in vault[username]["details"]:
        entry_types = list(vault[username]["details"][service].keys())
        print("Available Entry Types:", entry_types)
        entry_type = input("Select an entry type: ")
        if entry_type in vault[username]["details"][service]:
            record = vault[username]["details"][service][entry_type]
            decrypted = decrypt_data(record["data"], key)
            print(f"📌 Details for {service} - {entry_type}: {decrypted}")
            if input("View editing logs? (y/n): ").lower() == "y":
                print(f"Created: {record['created']}")
                print(f"Last Modified: {record['modified']}")
                print(f"Edit Count: {record['edit_count']}")
        else:
            print("Entry type not found.")
    else:
        print("Service not found.")

def modify_details(vault, username, key):
    services = list(vault[username]["details"].keys())
    if not services:
        print("No details stored.")
        return
    print("Available Services:", services)
    service = input("Select a service to modify details: ")
    if service in vault[username]["details"]:
        entry_types = list(vault[username]["details"][service].keys())
        print("Available Entry Types:", entry_types)
        entry_type = input("Select an entry type to modify: ")
        if entry_type in vault[username]["details"][service]:
            new_details = input(f"Enter new details for {service} - {entry_type}: ")
            record = vault[username]["details"][service][entry_type]
            record["data"] = encrypt_data(new_details, key)
            record["modified"] = time.strftime("%Y-%m-%d %H:%M:%S")
            record["edit_count"] += 1
            save_vault(vault)
            print(f"Details for {service} - {entry_type} updated.")
        else:
            print("Entry type not found.")
    else:
        print("Service not found.")

def delete_details(vault, username, key):
    services = list(vault[username]["details"].keys())
    if not services:
        print("No details stored.")
        return
    print("Available Services:", services)
    service = input("Select a service to delete details from: ")
    if service in vault[username]["details"]:
        entry_types = list(vault[username]["details"][service].keys())
        print("Available Entry Types:", entry_types)
        entry_type = input("Select an entry type to delete: ")
        if entry_type in vault[username]["details"][service]:
            confirm = input(f"Are you sure you want to delete details for {service} - {entry_type}? (y/n): ")
            if confirm.lower() == "y":
                del vault[username]["details"][service][entry_type]
                if not vault[username]["details"][service]:
                    del vault[username]["details"][service]
                save_vault(vault)
                print(f"Details for {service} - {entry_type} deleted.")
            else:
                print("Deletion cancelled.")
        else:
            print("Entry type not found.")
    else:
        print("Service not found.")

#--------------------------------------------------
# Vault Menus
#--------------------------------------------------

def password_vault_menu(vault, username, key):
    while True:
        print("\n----- Password Vault -----")
        print("1. Add Password")
        print("2. Retrieve Password")
        print("3. Modify Password")
        print("4. Delete Password")
        print("5. List Services")
        print("6. Return to Main Menu")
        choice = input("Select an option: ")
        if choice == "1":
            add_password(vault, username, key)
        elif choice == "2":
            retrieve_password(vault, username, key)
        elif choice == "3":
            modify_password(vault, username, key)
        elif choice == "4":
            delete_password(vault, username, key)
        elif choice == "5":
            services = list(vault[username]["passwords"].keys())
            print("Stored Services:", services)
        elif choice == "6":
            break
        else:
            print("Invalid option. Please try again.")

def details_vault_menu(vault, username, key):
    while True:
        print("\n----- Details Vault -----")
        print("1. Add Entry")
        print("2. Retrieve Entry")
        print("3. Modify Entry")
        print("4. Delete Entry")
        print("5. List Services")
        print("6. Return to Main Menu")
        choice = input("Select an option: ")
        if choice == "1":
            add_details(vault, username, key)
        elif choice == "2":
            retrieve_details(vault, username, key)
        elif choice == "3":
            modify_details(vault, username, key)
        elif choice == "4":
            delete_details(vault, username, key)
        elif choice == "5":
            services = list(vault[username]["details"].keys())
            print("Stored Services:", services)
        elif choice == "6":
            break
        else:
            print("Invalid option. Please try again.")

def main_menu():
    user_data = login()
    if not user_data:
        return
    username, key, vault = user_data
    while True:
        print("\n========= Secure Vault Main Menu =========")
        print("1. Password Vault")
        print("2. Details Vault")
        print("3. Logout")
        choice = input("Select an option: ")
        if choice == "1":
            password_vault_menu(vault, username, key)
        elif choice == "2":
            details_vault_menu(vault, username, key)
        elif choice == "3":
            print("🔒 Vault Locked. Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()
