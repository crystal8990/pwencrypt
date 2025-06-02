# audit_logger.py

import datetime
from typing import Dict, Any

from storage import save_vault


def log_event(vault: Dict, username: str, action: str,
              success: bool, metadata: Dict[str, Any] = None) -> None:
    """
    Record an event in vault['audit_log'] and immediately save.

    • vault:     your in-memory vault dict
    • username:  the user performing the action
    • action:    a short string, e.g. "login", "add_password"
    • success:   True if it worked, False on failure
    • metadata:  optional extra details (service name, error msg…)
    """
    entry = {
        "time":     datetime.datetime.utcnow().isoformat() + "Z",
        "user":     username,
        "action":   action,
        "success":  success,
        "meta":     metadata or {}
    }
    # ensure the list exists
    vault.setdefault("audit_log", []).append(entry)
    # persist right away so logs survive crashes
    save_vault(vault)


def view_logs(vault: Dict) -> None:
    """
    Pretty-print all audit entries, newest first.
    """
    logs = vault.get("audit_log", [])
    if not logs:
        print("⚠️  No audit entries yet.\n")
        return

    # Print header
    print("\n=== Audit Log ===")
    # Reverse so most recent is at top
    for entry in reversed(logs):
        t    = entry["time"]
        usr  = entry["user"]
        act  = entry["action"]
        ok   = "✔️" if entry["success"] else "❌"
        meta = entry["meta"]

        # Build a one-line summary
        line = f"[{t}] {ok} {usr:10s} • {act}"
        # If there’s extra metadata, show it
        if meta:
            # e.g. meta = {"service": "gmail", "item": "api_key"}
            extras = ", ".join(f"{k}={v}" for k, v in meta.items())
            line += f" ({extras})"
        print(line)
    print()
