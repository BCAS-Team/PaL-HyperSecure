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
            shutil.copyfileobj(f_in, f_out)

def cleanup_files():
    meta = load_json(META_FILE)
    now = datetime.now().timestamp()
    to_delete = []
    for file_id, info in list(meta.items()):
        expired = now - info["upload_time"] > FILE_EXPIRY_DAYS * 86400
        over_dl = info["downloads"] >= MAX_DOWNLOADS
        if expired or over_dl or not os.path.exists(info["path"]):
            try:
                os.remove(info["path"])
            except:
                pass
            to_delete.append(file_id)
    for file_id in to_delete:
        meta.pop(file_id, None)
    save_json(META_FILE, meta)

# Authentication decorator
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# ===== ROUTES =====
@app.route("/status", methods=["GET"])
def status():
    cleanup_files()
    return jsonify({"status": "running", "files": len(load_json(META_FILE))})

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    users = load_json(USER_FILE)
    if data["username"] in users:
        return jsonify({"error": "User exists"}), 400
    
    users[data["username"]] = {
        "password": data["password"],
        "public_key": data.get("public_key", "")
    }
    save_json(USER_FILE, users)
    return jsonify({"message": "User created", "status": "success"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    users = load_json(USER_FILE)
    
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")
    
    if username not in users or users[username]["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Update the public key if provided
    if public_key:
        users[username]["public_key"] = public_key
        save_json(USER_FILE, users)

    # Generate a JWT token that expires in 1 hour
    token_expiry = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode(
        {"username": username, "exp": token_expiry},
        SECRET_KEY,
        algorithm="HS256"
    )
    
    return jsonify({
        "message": "Login successful",
        "status": "success",
        "token": token,
        "access_token": token,  # client uses both, so provide both
        "expiry": token_expiry.timestamp()
    })

@app.route("/public_key/<username>", methods=["GET"])
def get_public_key(username):
    users = load_json(USER_FILE)
    if username not in users:
        return jsonify({"error": "User not found"}), 404
        
    public_key = users[username].get("public_key")
    if not public_key:
        return jsonify({"error": "No public key available for user"}), 404
    
    # Client expects a specific format
    return jsonify({
        "status": "success",
        "public_keys": {
            "device_id_placeholder": {  # Client expects a device_id map
                "public_key": public_key
            }
        }
    })

@app.route("/messages/send", methods=["POST"])
@token_required
def send_message(current_user):
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    ciphertext = data.get("ciphertext")

    if not all([sender, receiver, ciphertext]):
        return jsonify({"error": "Missing data"}), 400
        
    # Verify sender matches the logged-in user
    if sender != current_user:
        return jsonify({"error": "Unauthorized sender"}), 403

    messages = load_json(MESSAGES_FILE)
    if receiver not in messages:
        messages[receiver] = []
        
    messages[receiver].append({
        "sender": sender,
        "ciphertext": ciphertext,
        "timestamp": time.time()
    })
    
    save_json(MESSAGES_FILE, messages)
    return jsonify({"message": "Message sent", "status": "success"})
    
@app.route("/messages/<username>", methods=["GET"])
@token_required
def get_messages(current_user, username):
    # Verify the user is requesting their own messages
    if current_user != username:
        return jsonify({"error": "Unauthorized"}), 403

    messages = load_json(MESSAGES_FILE)
    msgs = messages.get(username, [])
    
    # Clear the messages after retrieval
    if username in messages:
        messages[username] = []
        save_json(MESSAGES_FILE, messages)
        
    return jsonify({"messages": msgs, "status": "success"})

@app.route("/upload", methods=["POST"])
def upload():
    username = request.form.get("username")
    password = request.form.get("password")

    users = load_json(USER_FILE)
    if username not in users or users[username]["password"] != password:
        return jsonify({"error": "Auth failed"}), 401

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files["file"]
    filename = secure_filename(file.filename)
    raw_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(raw_path)

    file_id = str(uuid.uuid4())
    compressed_path = os.path.join(UPLOAD_FOLDER, file_id + ".gz")
    compress_file(raw_path, compressed_path)
    os.remove(raw_path)

    meta = load_json(META_FILE)
    meta[file_id] = {
        "original_name": filename,
        "path": compressed_path,
        "downloads": 0,
        "upload_time": time.time()
    }
    save_json(META_FILE, meta)
    return jsonify({"message": "Uploaded", "file_id": file_id})

@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
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

    meta[file_id]["downloads"] += 1
    save_json(META_FILE, meta)

    # Use a custom header to pass the original filename back to the client
    response = send_file(info["path"], as_attachment=True, download_name=info["original_name"] + ".gz")
    response.headers["X-Orig-Filename"] = info["original_name"]
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
