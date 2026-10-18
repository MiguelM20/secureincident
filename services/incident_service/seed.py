"""Create synthetic accounts and cases once. Never ship example passwords to production.

Run from repository root: python -m services.incident_service.seed
"""

import getpass
import os

from argon2 import PasswordHasher

from .store import database, initialize_schema


def seed(passwords: dict[str, str]) -> None:
    if any(not passwords.get(name) for name in ("alice", "bob", "admin")):
        raise ValueError("Non-empty passwords required for all three synthetic accounts")
    initialize_schema()
    ph = PasswordHasher()
    accounts = [(1, "alice", "analyst"), (2, "bob", "analyst"), (3, "admin", "admin")]
    with database() as conn:
        for user_id, username, role in accounts:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                continue
            conn.execute(
                "INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)",
                (user_id, username, ph.hash(passwords[username]), role),
            )
        for incident_id, owner_id, title, desc, severity in (
            (101, 1, "Suspicious authentication", "Synthetic repeated login events", "medium"),
            (102, 2, "Unexpected network activity", "Synthetic outbound traffic", "high"),
        ):
            if conn.execute("SELECT 1 FROM incidents WHERE id=?", (incident_id,)).fetchone():
                continue
            conn.execute(
                "INSERT INTO incidents(id,owner_id,title,description,severity) VALUES(?,?,?,?,?)",
                (incident_id, owner_id, title, desc, severity),
            )


if __name__ == "__main__":
    passwords = {
        name: os.environ.get(f"SEED_{name.upper()}_PASSWORD") or getpass.getpass(f"Password for {name}: ")
        for name in ("alice", "bob", "admin")
    }
    seed(passwords)
    print("Synthetic accounts/cases seeded. Existing entries were not overwritten.")
