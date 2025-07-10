# audit_logger.py

import datetime
from typing import Dict, Any

from storage import save_vault


def log_event(
    vault: Dict,
    username: str,
    action: str,
    success: bool,
    master_password: str,
    metadata: Dict[str, Any] = None
) -> None:
    """
    Record an event in vault['audit_log'] and immediately save & sync.

    Parameters:
      vault: in-memory vault dictionary
      username: user performing the action
      action: short action identifier (e.g. "login")
      success: True if it succeeded, False otherwise
      master_password: required to derive HMAC key and persist the vault
      metadata: optional extra details (e.g. error messages)
    """
    entry = {
        "time":    datetime.datetime.utcnow().isoformat() + "Z",
        "user":    username,
        "action":  action,
        "success": success,
        "meta":    metadata or {}
    }
    vault.setdefault("audit_log", []).append(entry)

    # persist & sync immediately using the master password
    save_vault(vault, master_password)


def view_logs(vault: Dict) -> None:
    """
    Pretty-print all audit entries, newest first.
    """
    logs = vault.get("audit_log", [])
    if not logs:
        print("⚠️  No audit entries yet.\n")
        return

    print("\n=== Audit Log ===")
    for entry in reversed(logs):
        t    = entry["time"]
        usr  = entry["user"]
        act  = entry["action"]
        ok   = "✔️" if entry["success"] else "❌"
        meta = entry["meta"]

        line = f"[{t}] {ok} {usr:10s} • {act}"
        if meta:
            extras = ", ".join(f"{k}={v}" for k, v in meta.items())
            line += f" ({extras})"
        print(line)
    print()
