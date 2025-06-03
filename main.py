# main.py

import os
import sys

from storage         import load_vault, save_vault
from user_mgmt       import create_account, login, recover_account
from password_vault  import password_menu
from details_vault   import details_menu
from audit_logger    import view_logs

import os
os.system("title Secure Vault")

def clear_screen():
    """Clear terminal on Windows or Unix."""
    os.system("cls" if os.name == "nt" else "clear")

def delete_my_account(vault, username):
    """
    Delete all details for the given user after a confirmation prompt.
    If confirmed, remove the user's entry from the vault dictionary.
    
    Returns:
        True if deletion occurred (so that the vault menu can exit),
        False if deletion was aborted.
    """
    clear_screen()
    print(f"=== Delete My Account ({username}) ===\n")
    print("WARNING: This action will permanently delete ALL your account data!")
    confirm = input("Type 'DELETE' to confirm account deletion, or anything else to abort: ").strip()
    
    if confirm == "DELETE":
        if "users" in vault and username in vault["users"]:
            del vault["users"][username]
            print("\n✅ Your account has been deleted successfully.")
        else:
            print("\n❌ Error: Account not found.")
        input("\nPress Enter to return to the main menu...")
        return True  # Indicate that deletion occurred.
    else:
        print("\nAccount deletion aborted.")
        input("\nPress Enter to return to the vault menu...")
        return False

def vault_menu(vault, username, vault_key):
    """
    Intermediate vault menu that loads after a successful login.
    Offers access to the password vault, details vault, and account deletion.
    """
    while True:
        clear_screen()
        print(f"=== Vault Menu ({username}) ===")
        print("1) Password Vault")
        print("2) Details Vault")
        print("3) Delete My Account")
        print("4) Logout")
        choice = input("> ").strip()

        if choice == "1":
            clear_screen()
            password_menu(vault, username, vault_key)
        elif choice == "2":
            clear_screen()
            details_menu(vault, username, vault_key)
        elif choice == "3":
            # Trigger account deletion: if deletion occurs, break out of the vault menu.
            if delete_my_account(vault, username):
                break
        elif choice == "4":
            break
        else:
            print("❓ Invalid option. Please try again.")
            input("Press Enter to continue...")

def main_menu():
    vault = load_vault()

    while True:
        clear_screen()
        print("=== 🔒 Secure Vault ===")
        print("1) Create account")
        print("2) Login")
        print("3) Recover account")
        print("4) View audit log (only for admin)")
        print("5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            clear_screen()
            create_account(vault)

        elif choice == "2":
            clear_screen()
            username, vault_key = login(vault)
            if username:
                # Load the intermediate vault menu after successful login.
                vault_menu(vault, username, vault_key)

        elif choice == "3":
            clear_screen()
            recover_account(vault)

        elif choice == "4":
            clear_screen()
            view_logs(vault)

        elif choice == "5":
            clear_screen()
            print("👋 Bye!")
            break

        else:
            print("❓ Invalid choice. Please enter 1–5.")
            input("Press Enter to continue…")

    save_vault(vault)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted—exiting.")
        sys.exit(0)
