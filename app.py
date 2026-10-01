#!/usr/bin/env python3
"""
DevBank — a small (deliberately insecure) demo banking app for FIT5003 A2.

Run it in Docker (see README / the assignment brief). It contains a number of
web vulnerabilities of the kinds covered in the Weeks 4-5 labs. Your job is to
FIND them, exploit them, then FIX them in this source and show the exploit no
longer works.

Do NOT deploy this anywhere public — it is intentionally vulnerable and binds to
localhost only via the provided Docker command.
"""
import os
import sqlite3
import secrets
import hashlib
from flask import Flask, request, redirect, make_response, render_template, jsonify, g

app = Flask(__name__)

STUDENT_ID = os.environ.get("STUDENT_ID", "set-STUDENT_ID")
DB_PATH = os.environ.get("DEVBANK_DB", "/tmp/devbank.db")

# Server-side session store: token -> username. (Reset each time the app starts.)
SESSIONS = {}


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
def get_db():
    if "db" not in g.__dict__:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.__dict__.pop("db", None)
    if db is not None:
        db.close()


def admin_password():
    """Admin's password is derived from STUDENT_ID, so each student's blind-SQLi
    extraction target is unique — and a marker can recompute it from the ID."""
    digest = hashlib.sha256(("devbank-a2:" + STUDENT_ID).encode()).hexdigest()
    return "adm-" + digest[:12]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            balance INTEGER
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            username TEXT,
            content TEXT
        );
        """
    )
    conn.executemany(
        "INSERT INTO users (username, password, email, balance) VALUES (?,?,?,?)",
        [
            ("alice", "alice-password", "alice@devbank.local", 1000),
            ("bob", "bob-password", "bob@devbank.local", 250),
            ("admin", admin_password(), "admin@devbank.local", 999999),
        ],
    )
    conn.execute(
        "INSERT INTO notes (username, content) VALUES (?,?)",
        ("alice", "Remember to pay the electricity bill."),
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------- #
# Session helpers
# --------------------------------------------------------------------------- #
def current_user():
    token = request.cookies.get("auth")
    return SESSIONS.get(token)


def require_login():
    user = current_user()
    if not user:
        return None
    return user


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return redirect("/dashboard" if current_user() else "/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        row = db.execute(query).fetchone()
        if row:
            token = secrets.token_hex(16)
            SESSIONS[token] = row["username"]
            resp = make_response(redirect("/dashboard"))
            resp.set_cookie("auth", token)
            return resp
        error = "Invalid username or password."
    return render_template("login.html", error=error, student_id=STUDENT_ID)


@app.route("/logout")
def logout():
    SESSIONS.pop(request.cookies.get("auth"), None)
    resp = make_response(redirect("/login"))
    resp.delete_cookie("auth")
    return resp


@app.route("/dashboard")
def dashboard():
    user = require_login()
    if not user:
        return redirect("/login")
    db = get_db()
    me = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
    notes = db.execute(
        "SELECT * FROM notes WHERE username = ?", (user,)
    ).fetchall()
    return render_template(
        "dashboard.html", me=me, notes=notes, student_id=STUDENT_ID
    )


@app.route("/transfer", methods=["POST"])
def transfer():
    user = require_login()
    if not user:
        return redirect("/login")
    to = request.form.get("to", "")
    try:
        amount = int(request.form.get("amount", "0") or 0)
    except (ValueError, TypeError):
        amount = 0
    db = get_db()
    me = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
    dest = db.execute("SELECT * FROM users WHERE username = ?", (to,)).fetchone()
    if dest and 0 < amount <= me["balance"]:
        db.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, user))
        db.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, to))
        db.commit()
    return redirect("/dashboard")


@app.route("/note", methods=["POST"])
def add_note():
    user = require_login()
    if not user:
        return redirect("/login")
    content = request.form.get("content", "")
    db = get_db()
    db.execute("INSERT INTO notes (username, content) VALUES (?, ?)", (user, content))
    db.commit()
    return redirect("/dashboard")


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = require_login()
    if not user:
        return redirect("/login")
    db = get_db()
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        if email:
            db.execute("UPDATE users SET email = ? WHERE username = ?", (email, user))
        if password:
            db.execute("UPDATE users SET password = ? WHERE username = ?", (password, user))
        db.commit()
        return redirect("/profile")
    me = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
    return render_template("profile.html", me=me, student_id=STUDENT_ID)


@app.route("/search")
def search():
    user = require_login()
    if not user:
        return redirect("/login")
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        "SELECT * FROM users WHERE username LIKE ?", ("%" + q + "%",)
    ).fetchall()
    return render_template("search.html", q=q, rows=rows, student_id=STUDENT_ID)


@app.route("/api/account")
def api_account():
    user = require_login()
    if not user:
        return jsonify({"error": "not logged in"}), 401
    db = get_db()
    me = db.execute("SELECT * FROM users WHERE username = ?", (user,)).fetchone()
    resp = jsonify({"username": me["username"], "email": me["email"], "balance": me["balance"]})
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
