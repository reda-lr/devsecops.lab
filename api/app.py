from flask import Flask, request
import sqlite3


app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")


    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()


    # Vulnérabilité volontaire : SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)


    result = cursor.fetchone()
    if result:
        return {"status": "success", "user": username}


    return {"status": "error", "message": "Invalid credentials"}


if __name__ == "__main__":
    app.run()
