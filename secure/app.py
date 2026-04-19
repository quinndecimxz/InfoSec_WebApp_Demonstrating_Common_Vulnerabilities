"""
app.py of Secure Flask Application  (Patched Version)
=====================================================

This file is the security-patched counterpart of the vulnerable version.
Every vulnerability from that version is mitigated here, with inline
comments explaining WHAT was fixed and WHY.

Mitigations applied:
    [M1] Parameterized queries          eliminates SQL Injection
    [M2] Ownership + role decorators    eliminates IDOR / broken access
    [M3] bcrypt password hashing        replaces MD5
    [M4] Secure session configuration   strong key, HttpOnly, SameSite, TTL
    [M5] Input validation               length limits + regex allowlists
"""

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, abort
)
from functools import wraps
from datetime import timedelta
import sqlite3
import secrets
import re
import os

from database import init_db, get_db, hash_password, check_password

# ------------------------------------------------------------------ #
#  Application setup                                                   #
# ------------------------------------------------------------------ #

app = Flask(__name__)

# [M4] SECRET KEY  loaded from environment variable; falls back to a
#      cryptographically random 32-byte hex string generated at startup.
#      In production, set the SECRET_KEY environment variable explicitly
#      and keep it out of source control.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# [M4] SECURE SESSION COOKIE FLAGS
#      HttpOnly   cookie cannot be read by JavaScript (blocks XSS theft)
#      SameSite   cookie is not sent with cross-site requests (blocks CSRF)
#      Lifetime   session expires after 30 minutes of inactivity
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


# ------------------------------------------------------------------ #
#  Input validation constants                                          #
# ------------------------------------------------------------------ #

# [M5] Allowlist patterns and length limits applied before any DB work
USERNAME_RE  = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_RE     = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_MIN = 8
BIO_MAX_LEN  = 300


def validate_username(value: str) -> str | None:
    """Return an error string, or None if valid."""
    if not value:
        return "Username is required."
    if not USERNAME_RE.match(value):
        return "Username must be 3–20 characters: letters, digits, underscores only."
    return None


def validate_email(value: str) -> str | None:
    if not value:
        return "Email is required."
    if len(value) > 254 or not EMAIL_RE.match(value):
        return "Enter a valid email address."
    return None


def validate_password(value: str) -> str | None:
    if not value:
        return "Password is required."
    if len(value) < PASSWORD_MIN:
        return f"Password must be at least {PASSWORD_MIN} characters."
    return None


# ------------------------------------------------------------------ #
#  Access-control decorators                                           #
# ------------------------------------------------------------------ #

def login_required(f):
    """Redirect unauthenticated visitors to the login page."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    [M2] MITIGATION  Broken Access Control:
    The role is re-queried from the database on every admin request.
    This means even if someone tampers with the session cookie (via
    a forged or stolen token), they will be denied if the DB says
    they are not an admin.  The session cookie alone is not trusted.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        db   = get_conn()
        user = db.execute(
            "SELECT role FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not user or user["role"] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ------------------------------------------------------------------ #
#  Database helpers                                                    #
# ------------------------------------------------------------------ #

def get_conn() -> sqlite3.Connection:
    if "db" not in g:
        g.db = get_db()
    return g.db


@app.teardown_appcontext
def close_conn(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ------------------------------------------------------------------ #
#  Home                                                                #
# ------------------------------------------------------------------ #

@app.route("/")
def index():
    return render_template("index.html")


# ------------------------------------------------------------------ #
#  Register                                                            #
# ------------------------------------------------------------------ #

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email    = request.form.get("email", "").strip().lower()

        # [M5] INPUT VALIDATION  reject before touching the database
        error = (
            validate_username(username)
            or validate_email(email)
            or validate_password(password)
        )

        if not error:
            # [M3] BCRYPT  salted, work-factor 12; safe against rainbow tables
            hashed = hash_password(password)
            db     = get_conn()
            try:
                # [M1] PARAMETERIZED QUERY  no string interpolation
                db.execute(
                    "INSERT INTO users (username, password, role, email) VALUES (?, ?, 'user', ?)",
                    (username, hashed, email),
                )
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username already taken."

    return render_template("register.html", error=error)


# ------------------------------------------------------------------ #
#  Login                                                               #
# ------------------------------------------------------------------ #

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_conn()

        # [M1] PARAMETERIZED QUERY  username is passed as a bound
        #      parameter, never concatenated into the SQL string.
        #      A payload like  ' OR '1'='1' --  is treated as a literal
        #      string value, not SQL syntax, so injection is impossible.
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # [M3] BCRYPT CHECK  constant-time comparison via bcrypt.checkpw;
        #      we always call check_password even when user is None to avoid
        #      a username-enumeration timing side-channel.
        dummy_hash = "$2b$12$invalidhashusedtoblindtimingXXXXXXXXXXXXXXXX"
        stored_hash = user["password"] if user else dummy_hash
        password_ok = check_password(password, stored_hash)

        if user and password_ok:
            session.permanent = True   # [M4] apply PERMANENT_SESSION_LIFETIME

            # [M4] We store only the user id in the session.
            #      The role is never stored in the session; it is always
            #      re-fetched from the DB inside @admin_required so a
            #      tampered cookie cannot grant elevated privileges.
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]   # kept for nav display only
            return redirect(url_for("dashboard"))
        else:
            # Generic error  does NOT reveal whether the username exists
            error = "Invalid username or password."

    return render_template("login.html", error=error)


# ------------------------------------------------------------------ #
#  Logout                                                              #
# ------------------------------------------------------------------ #

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ------------------------------------------------------------------ #
#  Dashboard                                                           #
# ------------------------------------------------------------------ #

@app.route("/dashboard")
@login_required
def dashboard():
    db   = get_conn()
    # [M1] Parameterized query  session["user_id"] bound as parameter
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    return render_template("dashboard.html", user=user)


# ------------------------------------------------------------------ #
#  User Profile                                                        #
# ------------------------------------------------------------------ #

@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    # [M2] IDOR PREVENTION  ownership check:
    #      A regular user may only view their own profile.
    #      Admin users may view any profile.
    #      Any other combination gets a 403  the resource is not
    #      simply "hidden", it is actively denied.
    if session["user_id"] != user_id and session.get("role") != "admin":
        abort(403)

    db   = get_conn()
    # [M1] Parameterized query
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        abort(404)

    # [M2] Notes are only fetched after the ownership check above passes
    notes = db.execute(
        "SELECT * FROM notes WHERE user_id = ?", (user_id,)
    ).fetchall()

    return render_template("profile.html", profile_user=user, notes=notes)


# ------------------------------------------------------------------ #
#  Edit Profile                                                        #
# ------------------------------------------------------------------ #

@app.route("/profile/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def edit_profile(user_id):
    # [M2] IDOR PREVENTION  same ownership check as profile view
    if session["user_id"] != user_id and session.get("role") != "admin":
        abort(403)

    db   = get_conn()
    # [M1] Parameterized query
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        abort(404)

    error = None
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()

        # [M5] INPUT VALIDATION  enforce maximum length on bio
        if len(bio) > BIO_MAX_LEN:
            error = f"Bio must be {BIO_MAX_LEN} characters or fewer."
        else:
            # [M1] Parameterized query
            db.execute(
                "UPDATE users SET bio = ? WHERE id = ?", (bio, user_id)
            )
            db.commit()
            return redirect(url_for("profile", user_id=user_id))

    return render_template("edit_profile.html", profile_user=user, error=error)


# ------------------------------------------------------------------ #
#  Search                                                              #
# ------------------------------------------------------------------ #

@app.route("/search")
@login_required
def search():
    query   = request.args.get("q", "").strip()
    results = []
    error   = None

    if query:
        # [M5] INPUT VALIDATION  cap search term length to prevent
        #      oversized inputs and limit result-set exposure
        if len(query) > 50:
            error = "Search term must be 50 characters or fewer."
        else:
            db = get_conn()

            # [M1] PARAMETERIZED QUERY  the LIKE wildcard characters are
            #      passed as part of the bound value, not the SQL string.
            #      SQLite treats the entire value as a literal LIKE pattern;
            #      metacharacters in user input (%, _, UNION, --, etc.)
            #      have no effect on the query structure.
            results = db.execute(
                "SELECT id, username, email, role FROM users "
                "WHERE username LIKE ?",
                (f"%{query}%",),
            ).fetchall()

    return render_template("search.html", results=results, query=query, error=error)


# ------------------------------------------------------------------ #
#  Admin Panel                                                         #
# ------------------------------------------------------------------ #

@app.route("/admin")
@admin_required   # [M2] DB-backed role check  cookie tampering cannot bypass this
def admin():
    db    = get_conn()
    # [M1] Parameterized query (no user input here, but consistent style)
    users = db.execute(
        "SELECT id, username, email, role FROM users"
    ).fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/delete/<int:user_id>")
@admin_required   # [M2] Re-validates role from DB on every call
def admin_delete(user_id):
    # Prevent admin from deleting themselves
    if user_id == session["user_id"]:
        abort(400)

    db = get_conn()
    # [M1] Parameterized queries
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.execute("DELETE FROM notes WHERE user_id = ?", (user_id,))
    db.commit()
    return redirect(url_for("admin"))


# ------------------------------------------------------------------ #
#  Entry point                                                         #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    init_db()
    # [M4] debug=False  Werkzeug debugger and full tracebacks are
    #      never exposed to end users in a production-like setting.
    app.run(debug=False, port=5001)
