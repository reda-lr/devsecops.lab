from flask import Flask, request
import sqlite3
import subprocess
import os
import re
from pathlib import Path
import bcrypt

app = Flask(__name__)

# Secret non hardcodé (valeur par défaut OK فقط للـ lab)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY", "dev-only-secret")

DB_PATH = os.getenv("DB_PATH", "users.db")
SAFE_DATA_DIR = os.getenv("SAFE_DATA_DIR", "/app/data")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not USERNAME_PATTERN.fullmatch(username) or not password:
        return {"status": "error", "message": "Invalid input"}, 400

    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()

        # ✅ requête paramétrée -> ضد SQL injection
        cur.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    except Exception:
        return {"status": "error", "message": "Server error"}, 500
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

    if not row:
        return {"status": "error", "message": "Invalid credentials"}, 401

    stored_hash = (row[0] or "").encode()
    if not bcrypt.checkpw(password.encode(), stored_hash):
        return {"status": "error", "message": "Invalid credentials"}, 401

    return {"status": "success", "user": username}, 200


@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json() or {}
    host = (data.get("host") or "").strip()

    if not HOST_PATTERN.fullmatch(host):
        return {"error": "Invalid host"}, 400

    try:
        # ✅ pas de shell=True + timeout
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
        return {"output": result.stdout}
    except subprocess.CalledProcessError:
        return {"error": "Ping failed"}, 502
    except Exception:
        return {"error": "Server error"}, 500


@app.route("/compute", methods=["POST"])
def compute():
    # ✅ on supprime eval() : on accepte 2 nombres
    data = request.get_json() or {}
    a = data.get("a")
    b = data.get("b")

    try:
        a = float(a)
        b = float(b)
    except (TypeError, ValueError):
        return {"error": "Invalid numbers"}, 400

    return {"result": a + b}


@app.route("/hash", methods=["POST"])
def hash_password():
    # ✅ bcrypt au lieu de MD5
    data = request.get_json() or {}
    pwd = data.get("password", "admin")

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd.encode(), salt)
    return {"bcrypt": hashed.decode()}


@app.route("/readfile", methods=["POST"])
def readfile():
    # ✅ protection path traversal
    data = request.get_json() or {}
    filename = data.get("filename", "test.txt")

    base_dir = Path(SAFE_DATA_DIR).resolve()
    target = (base_dir / filename).resolve()

    if not str(target).startswith(str(base_dir)):
        return {"error": "Invalid path"}, 400
    if not target.is_file():
        return {"error": "File not found"}, 404

    try:
        return {"content": target.read_text(encoding="utf-8")}
    except Exception:
        return {"error": "Server error"}, 500


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps secure API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
