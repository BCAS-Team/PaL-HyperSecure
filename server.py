from flask import Flask, request, jsonify
import bcrypt
import json
import os

app = Flask(__name__)
USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    users = load_users()
    if username in users:
        return jsonify({"status": "error", "message": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users[username] = hashed_pw
    save_users(users)

    return jsonify({"status": "success", "message": "User registered successfully"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    users = load_users()
    if username not in users:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 400

    hashed_pw = users[username].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 400

if __name__ == "__main__":
    # Listen on all interfaces, port 5000 (Render defaults)
    app.run(host="0.0.0.0", port=5000)
