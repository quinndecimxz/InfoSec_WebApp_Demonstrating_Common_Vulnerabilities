"""
database.py , Initialize and seed the SQLite database.

VULNERABILITY (Weak Password Hashing):
    Passwords are hashed with plain MD5 (no salt, no stretching).
    MD5 is cryptographically broken and trivially reversible
    via precomputed rainbow tables.
"""

import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vuln.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_db():
    """Return a database connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5_hash(password: str) -> str:
    # VULNERABILITY: MD5 with no salt , rainbow-table trivial
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    """Create tables and insert seed data."""
    conn = get_db()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())

    # Seed users only if the table is empty
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        seed_users = [
            ("admin",  md5_hash("admin123"),  "admin", "admin@lab.local",  "Site administrator"),
            ("alice",  md5_hash("password1"), "user",  "alice@lab.local",  "Alice's bio"),
            ("bob",    md5_hash("password2"), "user",  "bob@lab.local",    "Bob's bio"),
        ]
        conn.executemany(
            "INSERT INTO users (username, password, role, email, bio) VALUES (?, ?, ?, ?, ?)",
            seed_users,
        )

        # Seed private notes per user
        conn.executemany(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)",
            [
                (1, "Admin secret note: internal API key = ADMIN-9f2k-XYZ"),
                (2, "Alice's private note: my diary entry #1"),
                (3, "Bob's private note: bank PIN reminder 4821"),
            ],
        )

    conn.commit()
    conn.close()
    print(f"[+] Database initialised at {DB_PATH}")


if __name__ == "__main__":
    init_db()
