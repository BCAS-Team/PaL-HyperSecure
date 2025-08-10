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

# ===== CONFIG =====
UPLOAD_FOLDER = "uploads"
META_FILE = "file_meta.json"
USER_FILE = "users.json"
MAX_DOWNLOADS = 3
FILE_EXPIRY_DAYS = 30
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
    users[data["username"]] = {"password": data["password"]}
    save_json(USER_FILE, users)
    return jsonify({"message": "User created"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    users = load_json(USER_FILE)
    if data["username"] in users and users[data["username"]]["password"] == data["password"]:
        return jsonify({"message": "Login OK"})
    return jsonify({"error": "Invalid credentials"}), 401

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
    if info["downloads"] >= MAX_DOWNLOADS:
        return jsonify({"error": "Download limit reached"}), 403

    if time.time() - info["upload_time"] > FILE_EXPIRY_DAYS * 86400:
        return jsonify({"error": "Expired"}), 403

    meta[file_id]["downloads"] += 1
    save_json(META_FILE, meta)

    return send_file(info["path"], as_attachment=True, download_name=info["original_name"] + ".gz")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
