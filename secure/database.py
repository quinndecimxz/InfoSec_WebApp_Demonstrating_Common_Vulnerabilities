"""
database.py — Initialise and seed the SQLite database (Secure Version).

MITIGATION [V3]  Weak Password Hashing:
    Passwords are hashed with bcrypt (work factor = 12).
    bcrypt automatically generates a random per-user salt and embeds it
    in the resulting hash string, so no two identical passwords produce
    the same hash. The high work factor makes brute-force and
    dictionary attacks computationally expensive.
"""

import sqlite3
import bcrypt
import os

DB_PATH     = os.path.join(os.path.dirname(__file__), "secure.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_db() -> sqlite3.Connection:
    """Return a new database connection with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(plaintext: str) -> str:
    """
    SECURE: bcrypt with work factor 12.
    Returns the hash as a UTF-8 string ready for DB storage.
    A fresh random salt is generated automatically by bcrypt on every call,
    so two calls with the same plaintext yield different hashes.
    """
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode("utf-8")


def check_password(plaintext: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison  safe against timing attacks."""
    return bcrypt.checkpw(plaintext.encode(), hashed.encode())


def init_db() -> None:
    """Create tables and insert seed data."""
    conn = get_db()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())

    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        seed_users = [
            ("admin",  hash_password("admin123"),  "admin", "admin@lab.local",  "Site administrator"),
            ("alice",  hash_password("password1"), "user",  "alice@lab.local",  "Alice's bio"),
            ("bob",    hash_password("password2"), "user",  "bob@lab.local",    "Bob's bio"),
        ]
        conn.executemany(
            "INSERT INTO users (username, password, role, email, bio) VALUES (?, ?, ?, ?, ?)",
            seed_users,
        )

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
    print(f"[+] Secure database initialised at {DB_PATH}")


if __name__ == "__main__":
    init_db()
