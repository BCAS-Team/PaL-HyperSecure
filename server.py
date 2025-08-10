from flask import Flask, request, jsonify
import bcrypt
import json
import os
from datetime import datetime
import threading
import time

app = Flask(__name__)
USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"

active_users = set()
active_users_lock = threading.Lock()

def load_json(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, "r") as f:
        return json.load(f)

def save_json(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f)

def log_user_creation(username, ip):
    timestamp = datetime.utcnow().isoformat() + "Z"
    print(f"[{timestamp}] User created: '{username}' from IP: {ip}")

def background_stats():
    while True:
        time.sleep(10)
        with active_users_lock:
            users_count = len(active_users)
        messages = load_json(MESSAGES_FILE)
        tasks_count = sum(len(msgs) for msgs in messages.values()) if messages else 0
        timestamp = datetime.utcnow().isoformat() + "Z"
        print(f"[{timestamp}] Active users: {users_count} | Total messages stored: {tasks_count}")

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")
    ip = request.remote_addr or "unknown"

    if not username or not password or not public_key:
        return jsonify({"status": "error", "message": "Username, password, and public_key required"}), 400

    users = load_json(USERS_FILE)
    if username in users:
        return jsonify({"status": "error", "message": "User already exists"}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users[username] = {
        "password": hashed_pw,
        "public_key": public_key
    }
    save_json(USERS_FILE, users)

    log_user_creation(username, ip)

    return jsonify({"status": "success", "message": "User registered successfully"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400

    users = load_json(USERS_FILE)
    if username not in users:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 400

    hashed_pw = users[username]["password"].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
        with active_users_lock:
            active_users.add(username)
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 400

@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    username = data.get("username")
    if not username:
        return jsonify({"status": "error", "message": "Username required"}), 400

    with active_users_lock:
        active_users.discard(username)
    return jsonify({"status": "success", "message": f"User '{username}' logged out"})

@app.route("/public_key/<username>", methods=["GET"])
def get_public_key(username):
    users = load_json(USERS_FILE)
    if username not in users:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "public_key": users[username]["public_key"]})

@app.route("/messages/send", methods=["POST"])
def send_message():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    ciphertext = data.get("ciphertext")
    timestamp = datetime.utcnow().isoformat() + "Z"

    if not sender or not receiver or not ciphertext:
        return jsonify({"status": "error", "message": "sender, receiver, and ciphertext required"}), 400

    messages = load_json(MESSAGES_FILE)
    if receiver not in messages:
        messages[receiver] = []
    messages[receiver].append({
        "sender": sender,
        "ciphertext": ciphertext,
        "timestamp": timestamp
    })

    save_json(MESSAGES_FILE, messages)
    return jsonify({"status": "success", "message": "Message sent"})

@app.route("/messages/<username>", methods=["GET"])
def get_messages(username):
    messages = load_json(MESSAGES_FILE)
    user_msgs = messages.get(username, [])
    return jsonify({"status": "success", "messages": user_msgs})

if __name__ == "__main__":
    stats_thread = threading.Thread(target=background_stats, daemon=True)
    stats_thread.start()
    app.run(host="0.0.0.0", port=5000)
