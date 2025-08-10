import os
import uuid
import gzip
import shutil
import json
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from threading import Lock
import jwt  # Import PyJWT for token handling
import functools
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.exceptions import InvalidTag

# ===== CONFIG =====
UPLOAD_FOLDER = "uploads"
META_FILE = "file_meta.json"
USER_FILE = "users.json"
MESSAGES_FILE = "messages.json"
MAX_DOWNLOADS = 3
FILE_EXPIRY_DAYS = 30
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Secret key for JWTs
SECRET_KEY = os.environ.get("SECRET_KEY", "your_super_secret_key_here")

app = Flask(__name__)
lock = Lock()

# ===== HELPERS =====
def load_json(file):
    if not os.path.exists(file):
        return {}
    with open(file, "r") as f:
        return json.load(f)

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

def compress_file(in_path, out_path):
    with open(in_path, 'rb') as f_in:
        with gzip.open(out_path, 'wb', compresslevel=9) as f_out:
            f_out.writelines(f_in)

def decompress_file(in_path, out_path):
    with gzip.open(in_path, 'rb') as f_in:
        with open(out_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

def token_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            kwargs['current_user'] = data['username']
        except Exception as e:
            return jsonify({'message': f'Token is invalid! {e}'}), 401
        return f(*args, **kwargs)
    return decorated_function

def load_user_public_key(username):
    users = load_json(USER_FILE)
    if username in users:
        return users[username]["public_key"]
    return None

# ===== ROUTES =====

@app.route("/")
def index():
    return "PaL-HyperSecure Server is running!"

@app.route("/status")
def status():
    meta = load_json(META_FILE)
    return jsonify({
        "status": "online",
        "files": len(meta),
        "message": "Server is up and running!"
    })

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    public_key = data.get("public_key")

    if not username or not public_key:
        return jsonify({"error": "Username and public key are required"}), 400

    with lock:
        users = load_json(USER_FILE)
        if username in users:
            return jsonify({"error": "Username already exists"}), 409
        
        users[username] = {
            "public_key": public_key,
            "registered_at": time.time()
        }
        save_json(USER_FILE, users)

    # Generate and sign a JWT token for the new user
    token = jwt.encode(
        {'username': username, 'exp': datetime.utcnow() + timedelta(hours=24)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return jsonify({"message": "Registration successful", "token": token, "username": username}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    
    with lock:
        users = load_json(USER_FILE)
        if username not in users:
            return jsonify({"error": "Username not found"}), 404
    
    # Generate and sign a JWT token for the user
    token = jwt.encode(
        {'username': username, 'exp': datetime.utcnow() + timedelta(hours=24)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return jsonify({"message": "Login successful", "token": token, "username": username})


@app.route("/upload", methods=["POST"])
@token_required
def upload(current_user):
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    raw_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(raw_path)

    file_id = str(uuid.uuid4())
    compressed_path = os.path.join(UPLOAD_FOLDER, file_id + ".gz")
    compress_file(raw_path, compressed_path)
    os.remove(raw_path)

    with lock:
        meta = load_json(META_FILE)
        meta[file_id] = {
            "original_name": filename,
            "path": compressed_path,
            "downloads": 0,
            "upload_time": time.time(),
            "uploader": current_user
        }
        save_json(META_FILE, meta)
    
    return jsonify({"message": "Uploaded", "file_id": file_id})

@app.route("/download/<file_id>", methods=["GET"])
@token_required
def download(file_id, current_user):
    meta = load_json(META_FILE)
    if file_id not in meta:
        return jsonify({"error": "Not found"}), 404

    info = meta[file_id]
    
    # We'll handle download limits and expiry, but will disable for now to make testing easier
    # if info["downloads"] >= MAX_DOWNLOADS:
    #     return jsonify({"error": "Download limit reached"}), 403
    #
    # if time.time() - info["upload_time"] > FILE_EXPIRY_DAYS * 86400:
    #     return jsonify({"error": "Expired"}), 403

    info["downloads"] += 1
    save_json(META_FILE, meta)
    
    return send_file(info["path"], as_attachment=True, download_name=info["original_name"])

@app.route("/messages", methods=["POST"])
@token_required
def send_message(current_user):
    data = request.get_json()
    recipient = data.get("recipient")
    content = data.get("content")

    if not recipient or not content:
        return jsonify({"error": "Recipient and content are required"}), 400

    # For this simple example, we're not encrypting the message with the recipient's public key.
    # We're just storing it.
    with lock:
        messages = load_json(MESSAGES_FILE)
        if recipient not in messages:
            messages[recipient] = []
        messages[recipient].append({
            "from": current_user,
            "content": content,
            "timestamp": time.time()
        })
        save_json(MESSAGES_FILE, messages)

    return jsonify({"message": "Message sent"}), 201

@app.route("/messages/<username>", methods=["GET"])
@token_required
def get_messages(username, current_user):
    if username != current_user:
        return jsonify({"error": "Unauthorized"}), 403
        
    messages = load_json(MESSAGES_FILE)
    user_messages = messages.get(username, [])
    
    # Clear the messages after fetching them once for this simple implementation
    with lock:
        if username in messages:
            messages[username] = []
        save_json(MESSAGES_FILE, messages)

    return jsonify({"messages": user_messages})


if __name__ == "__main__":
    app.run(debug=True)

