# main.py

import os
import sys

from storage         import load_vault, save_vault
from user_mgmt       import create_account, login, recover_account
from password_vault  import password_menu
from details_vault   import details_menu
from audit_logger    import view_logs

def clear_screen():
    """Clear terminal on Windows or Unix."""
    os.system("cls" if os.name == "nt" else "clear")

def main():
    vault = load_vault()

    while True:
        # ——— Main menu ———
        clear_screen()
        print("=== 🔒 Secure Vault ===")
        print("1) Create account")
        print("2) Login")
        print("3) Recover account")
        print("4) View audit log")
        print("5) Exit")
        choice = input("> ").strip()

        if choice == "1":
            clear_screen()
            create_account(vault)

        elif choice == "2":
            clear_screen()
            username, vault_key = login(vault)
            if username:
                # Sub-menus inherit a clean screen from main
                password_menu(vault, username, vault_key)
                details_menu(vault, username, vault_key)

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
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted—exiting.")
        sys.exit(0)
