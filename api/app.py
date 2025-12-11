from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import re
from pathlib import Path
import bcrypt

app = Flask(__name__)
# Secret non hardcodé en clair (valeur par défaut seulement pour le lab)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY", "dev-only-secret")

DB_PATH = os.getenv("DB_PATH", "users.db")
SAFE_DATA_DIR = os.getenv("SAFE_DATA_DIR", "/app/data")

# Host autorisé : uniquement lettres, chiffres, points, tirets
HOST_PATTERN = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def get_db():
    return sqlite3.connect(DB_PATH)


def validate_username(username: str) -> bool:
    """Validation simple du format du username."""
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", username))


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return {"status": "error", "message": "Missing username/password"}, 400

    if not validate_username(username):
        return {"status": "error", "message": "Invalid username format"}, 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        # ✅ Requête paramétrée : protège contre SQL Injection
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
    except Exception:
        return {"status": "error", "message": "Server error"}, 500
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if not row:
        return {"status": "error", "message": "Invalid credentials"}, 401

    # On suppose que password_hash est stocké en bcrypt (texte)
    stored_hash = row[0].encode()
    if not bcrypt.checkpw(password.encode(), stored_hash):
        return {"status": "error", "message": "Invalid credentials"}, 401

    return {"status": "success", "user": username}, 200


@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json() or {}
    host = data.get("host", "")

    # ✅ Validation d'entrée
    if not HOST_PATTERN.fullmatch(host):
        return {"error": "Invalid host"}, 400

    try:
        # ✅ Pas de shell=True, timeout limité
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            check=True,
            timeout=3,
        )
    except subprocess.CalledProcessError:
        return {"error": "Ping failed"}, 502
    except Exception:
        return {"error": "Server error"}, 500

    return {"output": result.stdout}


@app.route("/compute", methods=["POST"])
def compute():
    """
    Version sécurisée : au lieu de eval(expression),
    on accepte deux nombres et on renvoie leur somme.
    """
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
    """
    Démo de hashing sécurisé avec bcrypt (au lieu de MD5).
    """
    data = request.get_json() or {}
    pwd = data.get("password", "admin")

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd.encode(), salt)

    return {"bcrypt": hashed.decode()}


@app.route("/readfile", methods=["POST"])
def readfile():
    """
    Lecture de fichier dans un répertoire contrôlé,
    avec protection contre la traversal path (../../).
    """
    data = request.get_json() or {}
    filename = data.get("filename", "test.txt")

    base_dir = Path(SAFE_DATA_DIR).resolve()
    target = (base_dir / filename).resolve()

    # ✅ Empêche de sortir du dossier SAFE_DATA_DIR
    if not str(target).startswith(str(base_dir)):
        return {"error": "Invalid path"}, 400

    if not target.is_file():
        return {"error": "File not found"}, 404

    try:
        with open(target, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return {"error": "Server error"}, 500

    return {"content": content}


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps secure API"}


if __name__ == "__main__":
    # On garde le host 0.0.0.0 pour docker
    app.run(host="0.0.0.0", port=5000)
