-- ============================================================
-- Secure App SQLite Schema  (identical structure to vuln version)
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,   -- SECURE: bcrypt hash with per-user salt
    role      TEXT    NOT NULL DEFAULT 'user',
    email     TEXT    NOT NULL,
    bio       TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    content   TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
