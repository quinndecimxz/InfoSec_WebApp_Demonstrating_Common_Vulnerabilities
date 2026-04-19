"""
app.py = Intentionally Vulnerable Flask Application
=====================================================
This file intentionally contains the following security vulnerabilities:

    [V1] SQL Injection           /login, /search
    [V2] Broken Access Control   /profile/<id>, /admin
    [V3] Weak Password Hashing   /register, /login  (MD5, no salt)
    [V4] Session Weaknesses      secret key, no expiry, no flags
    [V5] Improper Input Valid.   /register, /search, /profile/edit

Each vulnerability is labeled inline with [V#].
"""

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, abort
)
import sqlite3
import hashlib
import os

from database import init_db, get_db, md5_hash

# ------------------------------------------------------------------ #
#  Application setup                                                   #
# ------------------------------------------------------------------ #

app = Flask(__name__)

# [V4] INSECURE: Hard-coded, trivially guessable secret key.
#      Anyone who knows the key can forge session cookies.
app.secret_key = "secret"

# [V4] INSECURE: No session cookie security flags.
#      SESSION_COOKIE_HTTPONLY and SESSION_COOKIE_SAMESITE are left at
#      their insecure defaults; no PERMANENT_SESSION_LIFETIME is set.


# ------------------------------------------------------------------ #
#  Database helpers                                                    #
# ------------------------------------------------------------------ #

def get_conn():
    """Open a per-request DB connection stored on Flask's g object."""
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email    = request.form.get("email", "")

        # [V5] NO INPUT VALIDATION:
        #      - No minimum/maximum length enforced
        #      - No character allowlist (accepts <script>, SQL chars, etc.)
        #      - No email format check
        #      - Empty strings accepted silently

        # [V3] WEAK HASHING: MD5 with no salt
        hashed = md5_hash(password)

        db = get_conn()
        try:
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # [V3] WEAK HASHING: comparing against unsalted MD5
        hashed = md5_hash(password)

        db = get_conn()

        # [V1] SQL INJECTION:
        #      The username value is concatenated directly into the query
        #      string with no sanitisation or parameterisation.
        #
        #      Attack example:
        #        username = ' OR '1'='1' --
        #      Resulting query:
        #        SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='...'
        #      This bypasses authentication entirely and returns the first
        #      row in the table (the admin account).
        query = (
            "SELECT * FROM users WHERE username='"
            + username
            + "' AND password='"
            + hashed
            + "'"
        )
        user = db.execute(query).fetchone()

        if user:
            # [V4] SESSION WEAKNESS:
            #      Role is stored directly in the session cookie.
            #      Because secret_key is weak, an attacker can forge this
            #      cookie and escalate their role to 'admin'.
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            return redirect(url_for("dashboard"))
        else:
            # [V4] RAW EXCEPTION / INFO LEAK:
            #      In debug mode (below) full tracebacks are exposed.
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
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db   = get_conn()
    # Parameterised here only to keep the query readable , the value
    # is already trusted (comes from our own session).
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()

    return render_template("dashboard.html", user=user)


# ------------------------------------------------------------------ #
#  User Profile (IDOR target)                                        #
# ------------------------------------------------------------------ #

@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # [V2] BROKEN ACCESS CONTROL i.e IDOR:
    #      There is NO check that session["user_id"] == user_id.
    #      Any authenticated user can view any other user's profile
    #      and private notes simply by changing the number in the URL.
    #
    #      Attack: log in as alice (id=2), then visit /profile/1
    #      to read the admin's private notes.

    db   = get_conn()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        abort(404)

    notes = db.execute(
        "SELECT * FROM notes WHERE user_id = ?", (user_id,)
    ).fetchall()

    return render_template("profile.html", profile_user=user, notes=notes)


# ------------------------------------------------------------------ #
#  Edit Profile                                                        #
# ------------------------------------------------------------------ #

@app.route("/profile/<int:user_id>/edit", methods=["GET", "POST"])
def edit_profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # [V2] BROKEN ACCESS CONTROL i.e IDOR:
    #      Same as above i.e no ownership check.
    #      Any authenticated user can overwrite any other user's bio.

    db   = get_conn()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        abort(404)

    if request.method == "POST":
        bio = request.form.get("bio", "")

        # [V5] NO INPUT VALIDATION:
        #      bio is written directly to the DB with no length cap or
        #      sanitisation, enabling stored XSS when rendered in the
        #      template without escipping (see profile.html note).
        db.execute(
            "UPDATE users SET bio = ? WHERE id = ?", (bio, user_id)
        )
        db.commit()
        return redirect(url_for("profile", user_id=user_id))

    return render_template("edit_profile.html", profile_user=user)


# ------------------------------------------------------------------ #
#  Search                                                              #
# ------------------------------------------------------------------ #

@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    query   = request.args.get("q", "")
    results = []

    if query:
        db = get_conn()

        # [V1] SQL INJECTION:
        #      The search term is concatenated into a LIKE clause with no
        #      escaping or parameterisation.
        #
        #      Attack example (UNION-based data extraction):
        #        q = %' UNION SELECT id, password, username, role, email, bio FROM users --
        #      This appends a second SELECT that dumps the entire users
        #      table (including hashed passwords) into the result set.
        #
        # [V5] NO INPUT VALIDATION:
        #      No max length, no stripping of SQL special characters.
        raw_query = (
            "SELECT id, username, email, role FROM users "
            "WHERE username LIKE '%" + query + "%'"
        )
        results = db.execute(raw_query).fetchall()

    return render_template("search.html", results=results, query=query)


# ------------------------------------------------------------------ #
#  Admin Panel                                                         #
# ------------------------------------------------------------------ #

@app.route("/admin")
def admin():
    # [V2] BROKEN ACCESS CONTROL:
    #      The role check relies entirely on the session cookie value.
    #      Because the secret_key is weak ("secret"), an attacker can
    #      decode, modify, and re-sign the Flask session cookie to set
    #      role = 'admin' without ever having admin credentials.
    #
    #      There is also no server-side re-validation of the role against
    #      the database on each request.
    if session.get("role") != "admin":
        abort(403)

    db    = get_conn()
    users = db.execute("SELECT id, username, email, role FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/delete/<int:user_id>")
def admin_delete(user_id):
    # [V2] Same broken access control issue as /admin
    if session.get("role") != "admin":
        abort(403)

    # [V5] No confirmation, no CSRF token , one-click delete via crafted link
    db = get_conn()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.execute("DELETE FROM notes WHERE user_id = ?", (user_id,))
    db.commit()
    return redirect(url_for("admin"))


# ------------------------------------------------------------------ #
#  Entry point                                                         #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    init_db()
    # [V4] debug=True exposes full stack traces and the interactive
    #      Werkzeug debugger (remote code execution) to any visitor.
    app.run(debug=True, port=5000)
