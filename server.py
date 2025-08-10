from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
import json

app = Flask(__name__)

# ====== CONFIG ======
DATA_FILE = "users.json"
FILES_DIR = "user_files"
MASTER_KEY_FILE = "master.key"

# ====== ENSURE STORAGE ======
os.makedirs(FILES_DIR, exist_ok=True)
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump({}, f)

if not os.path.exists(MASTER_KEY_FILE):
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(MASTER_KEY_FILE, "rb") as f:
    MASTER_KEY = f.read()

fernet = Fernet(MASTER_KEY)

# ====== HELPER FUNCTIONS ======
def load_users():
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DATA_FILE, "w") as f:
        json.dump(users, f, indent=4)

# ====== ROUTES ======

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "service": "PaL-HyperSecure",
        "status": "online"
    }), 200


@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    device_id = data.get("device_id")

    if not username or not password or not device_id:
        return jsonify({"error": "Missing required fields"}), 400

    users = load_users()

    if username in users:
        return jsonify({"error": "User already exists"}), 400

    users[username] = {
        "password_hash": generate_password_hash(password),
        "devices": [device_id]
    }
    save_users(users)
    return jsonify({"message": "Signup successful"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    device_id = data.get("device_id")

    users = load_users()

    if username not in users:
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(users[username]["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Add device if new
    if device_id not in users[username]["devices"]:
        users[username]["devices"].append(device_id)
        save_users(users)

    return jsonify({"message": "Login successful"}), 200


@app.route("/upload", methods=["POST"])
def upload():
    username = request.form.get("username")
    password = request.form.get("password")

    users = load_users()
    if username not in users or not check_password_hash(users[username]["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    encrypted_data = fernet.encrypt(file.read())

    file_path = os.path.join(FILES_DIR, f"{username}_{file.filename}.enc")
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    return jsonify({"message": "File uploaded and encrypted"}), 200


@app.route("/download", methods=["POST"])
def download():
    username = request.json.get("username")
    password = request.json.get("password")
    filename = request.json.get("filename")

    users = load_users()
    if username not in users or not check_password_hash(users[username]["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    file_path = os.path.join(FILES_DIR, f"{username}_{filename}.enc")
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    with open(file_path, "rb") as f:
        decrypted_data = fernet.decrypt(f.read())

    return decrypted_data, 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
