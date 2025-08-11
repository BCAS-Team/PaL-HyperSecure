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
            data = json.load(f)
            return data if data else {}
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading {file_path}: {e}")
        return {}

def save_json(file_path, data):
    """Save JSON file with error handling and atomic writes."""
    try:
        # Write to temporary file first
        temp_path = file_path.with_suffix('.tmp')
        with open(temp_path, "w", encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Atomic move
        temp_path.replace(file_path)
        return True
    except IOError as e:
        logger.error(f"Error saving {file_path}: {e}")
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
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

def validate_username(username):
    """Validate username format."""
    if not username or not isinstance(username, str):
        return False
    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        return False
    # Allow alphanumeric, underscore, hyphen
    return username.replace('_', '').replace('-', '').isalnum()

def find_user_case_insensitive(username, users_dict):
    """Find user in dict with case-insensitive lookup."""
    if not username:
        return None
    username_lower = username.lower()
    for stored_username in users_dict.keys():
        if stored_username.lower() == username_lower:
            return stored_username
    return None

def token_required(f):
    """Decorator to require valid JWT token."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            try:
                token = auth_header.split(' ', 1)[1]
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            username = data.get('username')
            if not username:
                return jsonify({'error': 'Invalid token payload'}), 401
            kwargs['current_user'] = username
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
            if not meta:
                return
            
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
        "version": "1.0.1"
    })

@app.route("/status")
def status():
    """Get server status and statistics."""
    try:
        meta = load_json(META_FILE)
        users = load_json(USER_FILE)
        messages = load_json(MESSAGES_FILE)
        
        # Clean up expired files during status check
        cleanup_expired_files()
        
        # Count total messages
        total_messages = 0
        for user_msgs in messages.values():
            if isinstance(user_msgs, list):
                total_messages += len(user_msgs)
        
        return jsonify({
            "status": "online",
            "files": len(meta),
            "users": len(users),
            "messages": total_messages,
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
        if not validate_username(username):
            return jsonify({"error": "Username must be 3-50 characters and contain only letters, numbers, hyphens, and underscores"}), 400
        
        if not public_key or len(public_key) < 200:  # RSA public keys are longer
            return jsonify({"error": "Valid public key is required"}), 400

        with lock:
            users = load_json(USER_FILE)
            
            # Check if username already exists (case-insensitive)
            if find_user_case_insensitive(username, users):
                return jsonify({"error": "Username already exists"}), 409
            
            # Store user with original case
            users[username] = {
                "public_key": public_key,
                "registered_at": time.time(),
                "last_login": None
            }
            
            if not save_json(USER_FILE, users):
                return jsonify({"error": "Failed to save user data"}), 500

        # Generate JWT token
        try:
            token = jwt.encode(
                {
                    'username': username,
                    'exp': datetime.utcnow() + timedelta(hours=24)
                },
                SECRET_KEY,
                algorithm="HS256"
            )
        except Exception as e:
            logger.error(f"Error generating JWT token: {e}")
            return jsonify({"error": "Failed to generate authentication token"}), 500
        
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
        public_key = data.get("public_key", "").strip()
        
        if not username:
            return jsonify({"error": "Username is required"}), 400
        
        if not public_key:
            return jsonify({"error": "Public key is required"}), 400

        with lock:
            users = load_json(USER_FILE)
            
            # Find user (case-insensitive)
            user_found = find_user_case_insensitive(username, users)
            
            if not user_found:
                return jsonify({"error": "Username not found"}), 404
            
            # Verify public key matches
            stored_key = users[user_found].get("public_key", "")
            if stored_key != public_key:
                return jsonify({"error": "Invalid credentials"}), 401
            
            # Update last login
            users[user_found]["last_login"] = time.time()
            save_json(USER_FILE, users)

        # Generate JWT token
        try:
            token = jwt.encode(
                {
                    'username': user_found,
                    'exp': datetime.utcnow() + timedelta(hours=24)
                },
                SECRET_KEY,
                algorithm="HS256"
            )
        except Exception as e:
            logger.error(f"Error generating JWT token: {e}")
            return jsonify({"error": "Failed to generate authentication token"}), 500
        
        logger.info(f"User logged in: {user_found}")
        return jsonify({
            "message": "Login successful",
            "token": token,
            "username": user_found
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

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
        recipient_found = find_user_case_insensitive(recipient, users)
                
        if not recipient_found:
            return jsonify({"error": "Recipient not found"}), 404

        with lock:
            messages = load_json(MESSAGES_FILE)
            
            # Initialize recipient's inbox if it doesn't exist
            if recipient_found not in messages:
                messages[recipient_found] = []
            
            # Ensure it's a list
            if not isinstance(messages[recipient_found], list):
                messages[recipient_found] = []
            
            # Add message
            message_id = str(uuid.uuid4())
            new_message = {
                "id": message_id,
                "from": current_user,
                "content": content,
                "timestamp": time.time(),
                "read": False
            }
            
            messages[recipient_found].append(new_message)
            
            if not save_json(MESSAGES_FILE, messages):
                return jsonify({"error": "Failed to save message"}), 500

        logger.info(f"Message sent from {current_user} to {recipient_found}")
        return jsonify({
            "message": "Message sent successfully",
            "message_id": message_id
        }), 201
        
    except Exception as e:
        logger.error(f"Send message error: {e}")
        return jsonify({"error": "Failed to send message"}), 500

@app.route("/messages/<username>", methods=["GET"])
@token_required
def get_messages(username, current_user):
    """Get messages for current user."""
    try:
        # Verify user can only access their own messages
        if username.lower() != current_user.lower():
            return jsonify({"error": "Unauthorized access"}), 403
        
        with lock:
            messages = load_json(MESSAGES_FILE)
            user_messages = messages.get(current_user, [])
            
            # Ensure it's a list
            if not isinstance(user_messages, list):
                user_messages = []
            
            # Sort messages by timestamp (newest first)
            user_messages.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

        logger.info(f"Messages retrieved by {current_user}: {len(user_messages)} messages")
        return jsonify({
            "messages": user_messages,
            "total": len(user_messages),
            "unread": len([m for m in user_messages if not m.get('read', False)])
        })
        
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        return jsonify({"error": "Failed to retrieve messages"}), 500

@app.route("/messages/<username>/mark-read", methods=["POST"])
@token_required
def mark_messages_read(username, current_user):
    """Mark messages as read."""
    try:
        # Verify user can only modify their own messages
        if username.lower() != current_user.lower():
            return jsonify({"error": "Unauthorized access"}), 403
        
        data = request.get_json() or {}
        message_ids = data.get("message_ids", [])
        
        with lock:
            messages = load_json(MESSAGES_FILE)
            user_messages = messages.get(current_user, [])
            
            if not isinstance(user_messages, list):
                user_messages = []
                messages[current_user] = user_messages
            
            marked_count = 0
            
            if message_ids:
                # Mark specific messages
                for message in user_messages:
                    if message.get('id') in message_ids:
                        message['read'] = True
                        marked_count += 1
            else:
                # Mark all messages as read
                for message in user_messages:
                    if not message.get('read', False):
                        message['read'] = True
                        marked_count += 1
            
            if marked_count > 0:
                messages[current_user] = user_messages
                if not save_json(MESSAGES_FILE, messages):
                    return jsonify({"error": "Failed to update messages"}), 500

        logger.info(f"Messages marked as read by {current_user}: {marked_count} messages")
        return jsonify({
            "message": f"Marked {marked_count} messages as read",
            "marked_count": marked_count
        })
        
    except Exception as e:
        logger.error(f"Mark messages read error: {e}")
        return jsonify({"error": "Failed to mark messages as read"}), 500

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
                "error": f"File type not allowed. Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
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
            return jsonify({"error": f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"}), 413

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
        # Validate file_id format (UUID)
        try:
            uuid.UUID(file_id)
        except ValueError:
            return jsonify({"error": "Invalid file ID format"}), 400

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
            info["last_downloader"] = current_user
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
                    "downloads": info.get("downloads", 0),
                    "expires_at": info.get("upload_time", 0) + (FILE_EXPIRY_DAYS * 86400)
                })
        
        # Sort by upload time (newest first)
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
