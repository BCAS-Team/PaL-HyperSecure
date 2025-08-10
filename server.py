import os
import uuid
import gzip
import shutil
import json
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from threading import Lock
import jwt
import functools
import hashlib
from pathlib import Path

# ===== LOGGING SETUP =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ===== CONFIG =====
UPLOAD_FOLDER = Path("uploads")
DATA_FOLDER = Path("data")
UPLOAD_FOLDER.mkdir(exist_ok=True)
DATA_FOLDER.mkdir(exist_ok=True)

META_FILE = DATA_FOLDER / "file_meta.json"
USER_FILE = DATA_FOLDER / "users.json"
MESSAGES_FILE = DATA_FOLDER / "messages.json"

MAX_DOWNLOADS = 3
FILE_EXPIRY_DAYS = 30
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 
    'xls', 'xlsx', 'zip', 'rar', '7z', 'mp3', 'mp4', 'avi'
}

# Secret key for JWTs - MUST be set in production
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
    logger.warning("Using generated SECRET_KEY. Set SECRET_KEY environment variable in production!")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
lock = Lock()

# ===== HELPERS =====
def load_json(file_path):
    """Load JSON file with error handling."""
    try:
        if not file_path.exists():
            return {}
        with open(file_path, "r", encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading {file_path}: {e}")
        return {}

def save_json(file_path, data):
    """Save JSON file with error handling."""
    try:
        with open(file_path, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except IOError as e:
        logger.error(f"Error saving {file_path}: {e}")
        return False

def compress_file(in_path, out_path):
    """Compress file using gzip."""
    try:
        with open(in_path, 'rb') as f_in:
            with gzip.open(out_path, 'wb', compresslevel=6) as f_out:
                shutil.copyfileobj(f_in, f_out)
        return True
    except Exception as e:
        logger.error(f"Error compressing file: {e}")
        return False

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def token_required(f):
    """Decorator to require valid JWT token."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            kwargs['current_user'] = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def cleanup_expired_files():
    """Clean up expired files."""
    try:
        with lock:
            meta = load_json(META_FILE)
            expired_files = []
            current_time = time.time()
            
            for file_id, info in meta.items():
                if current_time - info.get("upload_time", 0) > FILE_EXPIRY_DAYS * 86400:
                    expired_files.append(file_id)
            
            for file_id in expired_files:
                info = meta.pop(file_id, {})
                file_path = Path(info.get("path", ""))
                if file_path.exists():
                    try:
                        file_path.unlink()
                        logger.info(f"Deleted expired file: {file_id}")
                    except Exception as e:
                        logger.error(f"Error deleting expired file {file_id}: {e}")
            
            if expired_files:
                save_json(META_FILE, meta)
                logger.info(f"Cleaned up {len(expired_files)} expired files")
                
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

# ===== ERROR HANDLERS =====
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413

@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ===== ROUTES =====
@app.route("/")
def index():
    return jsonify({
        "service": "PaL-HyperSecure Server",
        "status": "running",
        "version": "1.0.0"
    })

@app.route("/status")
def status():
    """Get server status and statistics."""
    try:
        meta = load_json(META_FILE)
        users = load_json(USER_FILE)
        
        # Clean up expired files during status check
        cleanup_expired_files()
        
        return jsonify({
            "status": "online",
            "files": len(meta),
            "users": len(users),
            "uptime": time.time(),
            "max_file_size_mb": MAX_FILE_SIZE // (1024 * 1024),
            "message": "Server is operational"
        })
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({"error": "Unable to get status"}), 500

@app.route("/register", methods=["POST"])
def register():
    """Register a new user."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        username = data.get("username", "").strip()
        public_key = data.get("public_key", "").strip()

        # Validation
        if not username or len(username) < 3 or len(username) > 50:
            return jsonify({"error": "Username must be 3-50 characters"}), 400
        
        if not username.replace('_', '').replace('-', '').isalnum():
            return jsonify({"error": "Username can only contain letters, numbers, hyphens, and underscores"}), 400
        
        if not public_key or len(public_key) < 100:
            return jsonify({"error": "Valid public key is required"}), 400

        with lock:
            users = load_json(USER_FILE)
            if username.lower() in [u.lower() for u in users.keys()]:
                return jsonify({"error": "Username already exists"}), 409
            
            users[username] = {
                "public_key": public_key,
                "registered_at": time.time(),
                "last_login": None
            }
            
            if not save_json(USER_FILE, users):
                return jsonify({"error": "Failed to save user data"}), 500

        # Generate JWT token
        token = jwt.encode(
            {
                'username': username,
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        
        logger.info(f"New user registered: {username}")
        return jsonify({
            "message": "Registration successful",
            "token": token,
            "username": username
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route("/login", methods=["POST"])
def login():
    """Login existing user."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        username = data.get("username", "").strip()
        
        if not username:
            return jsonify({"error": "Username is required"}), 400

        with lock:
            users = load_json(USER_FILE)
            user_found = None
            
            # Case-insensitive username lookup
            for stored_username in users.keys():
                if stored_username.lower() == username.lower():
                    user_found = stored_username
                    break
            
            if not user_found:
                return jsonify({"error": "Username not found"}), 404
            
            # Update last login
            users[user_found]["last_login"] = time.time()
            save_json(USER_FILE, users)

        # Generate JWT token
        token = jwt.encode(
            {
                'username': user_found,
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        
        logger.info(f"User logged in: {user_found}")
        return jsonify({
            "message": "Login successful",
            "token": token,
            "username": user_found
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

@app.route("/upload", methods=["POST"])
@token_required
def upload(current_user):
    """Upload a file."""
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if not allowed_file(file.filename):
            return jsonify({
                "error": f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
            }), 400

        # Secure filename
        original_filename = file.filename
        filename = secure_filename(original_filename)
        if not filename:
            filename = f"upload_{int(time.time())}"

        # Save uploaded file temporarily
        file_id = str(uuid.uuid4())
        temp_path = UPLOAD_FOLDER / f"temp_{file_id}"
        
        try:
            file.save(temp_path)
        except Exception as e:
            logger.error(f"Error saving uploaded file: {e}")
            return jsonify({"error": "Failed to save file"}), 500

        # Get file size
        file_size = temp_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": "File too large"}), 413

        # Compress the file
        compressed_path = UPLOAD_FOLDER / f"{file_id}.gz"
        
        if not compress_file(temp_path, compressed_path):
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": "Failed to compress file"}), 500
        
        # Remove temp file
        temp_path.unlink(missing_ok=True)

        # Save metadata
        with lock:
            meta = load_json(META_FILE)
            meta[file_id] = {
                "original_name": original_filename,
                "secure_name": filename,
                "path": str(compressed_path),
                "size": file_size,
                "downloads": 0,
                "upload_time": time.time(),
                "uploader": current_user,
                "mime_type": file.content_type or "application/octet-stream"
            }
            
            if not save_json(META_FILE, meta):
                compressed_path.unlink(missing_ok=True)
                return jsonify({"error": "Failed to save metadata"}), 500
        
        logger.info(f"File uploaded by {current_user}: {original_filename} ({file_id})")
        return jsonify({
            "message": "File uploaded successfully",
            "file_id": file_id,
            "original_name": original_filename,
            "size": file_size
        })
        
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({"error": "Upload failed"}), 500

@app.route("/download/<file_id>", methods=["GET"])
@token_required
def download(file_id, current_user):
    """Download a file."""
    try:
        if not file_id or len(file_id) != 36:  # UUID length check
            return jsonify({"error": "Invalid file ID"}), 400

        with lock:
            meta = load_json(META_FILE)
            if file_id not in meta:
                return jsonify({"error": "File not found"}), 404

            info = meta[file_id]
            
            # Check if file expired
            if time.time() - info.get("upload_time", 0) > FILE_EXPIRY_DAYS * 86400:
                return jsonify({"error": "File has expired"}), 410

            # Check download limit
            if info.get("downloads", 0) >= MAX_DOWNLOADS:
                return jsonify({"error": "Download limit exceeded"}), 403

            # Check if file still exists
            file_path = Path(info["path"])
            if not file_path.exists():
                return jsonify({"error": "File no longer available"}), 410

            # Update download count
            info["downloads"] = info.get("downloads", 0) + 1
            info["last_download"] = time.time()
            meta[file_id] = info
            save_json(META_FILE, meta)

        logger.info(f"File downloaded by {current_user}: {file_id}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=info.get("original_name", "download"),
            mimetype=info.get("mime_type", "application/octet-stream")
        )
        
    except Exception as e:
        logger.error(f"Download error: {e}")
        return jsonify({"error": "Download failed"}), 500

@app.route("/messages", methods=["POST"])
@token_required
def send_message(current_user):
    """Send a message to another user."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        recipient = data.get("recipient", "").strip()
        content = data.get("content", "").strip()

        if not recipient or not content:
            return jsonify({"error": "Recipient and content are required"}), 400
        
        if len(content) > 5000:
            return jsonify({"error": "Message too long (max 5000 characters)"}), 400

        # Check if recipient exists
        users = load_json(USER_FILE)
        recipient_found = None
        for username in users.keys():
            if username.lower() == recipient.lower():
                recipient_found = username
                break
                
        if not recipient_found:
            return jsonify({"error": "Recipient not found"}), 404

        with lock:
            messages = load_json(MESSAGES_FILE)
            if recipient_found not in messages:
                messages[recipient_found] = []
            
            messages[recipient_found].append({
                "id": str(uuid.uuid4()),
                "from": current_user,
                "content": content,
                "timestamp": time.time(),
                "read": False
            })
            
            if not save_json(MESSAGES_FILE, messages):
                return jsonify({"error": "Failed to save message"}), 500

        logger.info(f"Message sent from {current_user} to {recipient_found}")
        return jsonify({"message": "Message sent successfully"}), 201
        
    except Exception as e:
        logger.error(f"Send message error: {e}")
        return jsonify({"error": "Failed to send message"}), 500

@app.route("/messages/<username>", methods=["GET"])
@token_required
def get_messages(username, current_user):
    """Get messages for current user."""
    try:
        if username.lower() != current_user.lower():
            return jsonify({"error": "Unauthorized access"}), 403
        
        messages = load_json(MESSAGES_FILE)
        user_messages = messages.get(current_user, [])
        
        # Mark messages as read and clear them
        with lock:
            if current_user in messages:
                for msg in messages[current_user]:
                    msg["read"] = True
                # Clear messages after reading (as per original behavior)
                messages[current_user] = []
                save_json(MESSAGES_FILE, messages)

        logger.info(f"Messages retrieved by {current_user}: {len(user_messages)} messages")
        return jsonify({"messages": user_messages})
        
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        return jsonify({"error": "Failed to retrieve messages"}), 500

@app.route("/files", methods=["GET"])
@token_required
def list_files(current_user):
    """List files uploaded by current user."""
    try:
        meta = load_json(META_FILE)
        user_files = []
        
        for file_id, info in meta.items():
            if info.get("uploader") == current_user:
                user_files.append({
                    "file_id": file_id,
                    "original_name": info.get("original_name"),
                    "size": info.get("size"),
                    "upload_time": info.get("upload_time"),
                    "downloads": info.get("downloads", 0)
                })
        
        user_files.sort(key=lambda x: x.get("upload_time", 0), reverse=True)
        
        return jsonify({
            "files": user_files,
            "total": len(user_files)
        })
        
    except Exception as e:
        logger.error(f"List files error: {e}")
        return jsonify({"error": "Failed to list files"}), 500

if __name__ == "__main__":
    logger.info("Starting PaL-HyperSecure Server...")
    logger.info(f"Upload folder: {UPLOAD_FOLDER.absolute()}")
    logger.info(f"Data folder: {DATA_FOLDER.absolute()}")
    logger.info(f"Max file size: {MAX_FILE_SIZE // (1024*1024)}MB")
    
    # Run cleanup on startup
    cleanup_expired_files()
    
    # Run the server
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True
    )
