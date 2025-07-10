import os
import sys
import screenshot_protection

from storage         import load_vault, save_vault
from user_mgmt       import create_account, login, recover_account
from password_vault  import password_menu
from details_vault   import details_menu
from audit_logger    import view_logs

# Set console title
os.system("title Secure Vault")

def clear_screen():
    """Clear terminal on Windows or Unix."""
    os.system("cls" if os.name == "nt" else "clear")

def delete_my_account(vault, username):
    """
    Delete all details for the given user after confirmation.
    Returns True if deletion occurred, False otherwise.
    """
    clear_screen()
    print(f"=== Delete My Account ({username}) ===\n")
    print("WARNING: This action will permanently delete ALL your account data!")
    confirm = input("Type 'DELETE' to confirm, or anything else to abort: ").strip()

    if confirm == "DELETE":
        if "users" in vault and username in vault["users"]:
            del vault["users"][username]
            print("\n✅ Your account has been deleted successfully.")
        else:
            print("\n❌ Error: Account not found.")
        input("\nPress Enter to return to the main menu...")
        return True
    else:
        print("\nAccount deletion aborted.")
        input("\nPress Enter to return to the vault menu...")
        return False

def vault_menu(vault, username, vault_key, master_password):
    """
    Menu after a successful login.
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
            password_menu(vault, username, vault_key, master_password)

        elif choice == "2":
            clear_screen()
            details_menu(vault, username, vault_key, master_password)

        elif choice == "3":
            # If deletion occurs, exit the vault menu
            if delete_my_account(vault, username):
                break

        elif choice == "4":
            break

        else:
            print("❓ Invalid option. Please try again.")
            input("Press Enter to continue...")

def main_menu():

    screenshot_protection.initialize_screenshot_protection()
    
    clear_screen()

    # 1) Prompt for the master password used to sign/sync the vault
    master_password = input("Enter your SecureVault master password: ").strip()

    # 2) Load (or initialize) the vault from Google Drive (or empty skeleton)
    try:
        vault = load_vault(master_password)
    except Exception as e:
        print(f"❌ Failed to load vault: {e}")
        return

    # 3) Main application menu
    while True:
        clear_screen()
        print("=== 🔒 Secure Vault ===")
        print("1) Create account")
        print("2) Login")
        print("3) Recover account")
        print("4) View audit log (admin only)")
        print("5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            clear_screen()
            create_account(vault, master_password)

        elif choice == "2":
            clear_screen()
            username, vault_key = login(vault, master_password)
            if username:
                vault_menu(vault, username, vault_key, master_password)

        elif choice == "3":
            clear_screen()
            recover_account(vault, master_password)

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

    # 4) Save & sync the vault upon exit
    try:
        save_vault(vault, master_password)
        print("✅ Vault saved and synced to Drive.")
    except Exception as e:
        print(f"⚠️  Failed to save vault: {e}")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted—exiting.")
        sys.exit(0)
