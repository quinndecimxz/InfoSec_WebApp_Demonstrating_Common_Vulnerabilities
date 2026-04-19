-- ============================================================
-- Vulnerable App  SQLite Schema
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,   -- VULNERABILITY: stored as MD5 hash (no salt)
    role      TEXT    NOT NULL DEFAULT 'user',  -- 'user' or 'admin'
    email     TEXT    NOT NULL,
    bio       TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    content   TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
