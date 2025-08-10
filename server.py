import os
import uuid
import json
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from threading import Lock, Thread
import jwt
import functools
import hashlib
from pathlib import Path
import sqlite3
from contextlib import contextmanager
import schedule

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
DATA_FOLDER = Path("data")
DATA_FOLDER.mkdir(exist_ok=True)

DB_FILE = DATA_FOLDER / "messaging.db"
MESSAGE_RETENTION_DAYS = 30
MAX_MESSAGE_LENGTH = 5000
MAX_USERNAME_LENGTH = 50
MIN_USERNAME_LENGTH = 3

# Secret key for JWTs - MUST be set in production
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
    logger.warning("Using generated SECRET_KEY. Set SECRET_KEY environment variable in production!")

app = Flask(__name__)
lock = Lock()

# ===== DATABASE SETUP =====
def init_database():
    """Initialize SQLite database with proper schema."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            );
            
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT 0,
                message_uuid TEXT UNIQUE NOT NULL,
                FOREIGN KEY (from_user) REFERENCES users (username),
                FOREIGN KEY (to_user) REFERENCES users (username)
            );
            
            CREATE INDEX IF NOT EXISTS idx_messages_to_user ON messages(to_user, is_read);
            CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        """)
        conn.commit()
    logger.info("Database initialized successfully")

@contextmanager
def get_db_connection():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# ===== HELPERS =====
def validate_username(username):
    """Validate username format and length."""
    if not username or len(username) < MIN_USERNAME_LENGTH or len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must be {MIN_USERNAME_LENGTH}-{MAX_USERNAME_LENGTH} characters long"
    
    if not username.replace('_', '').replace('-', '').isalnum():
        return False, "Username can only contain letters, numbers, hyphens, and underscores"
    
    return True, ""

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
            logger.warning(f"Invalid token attempt: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def cleanup_old_messages():
    """Clean up old messages to maintain database performance."""
    try:
        cutoff_date = datetime.now() - timedelta(days=MESSAGE_RETENTION_DAYS)
        
        with get_db_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM messages WHERE created_at < ? AND is_read = 1",
                (cutoff_date,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old messages")
            
    except Exception as e:
        logger.error(f"Error during message cleanup: {e}")

def get_user_stats():
    """Get database statistics."""
    try:
        with get_db_connection() as conn:
            users_count = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
            messages_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            unread_count = conn.execute("SELECT COUNT(*) FROM messages WHERE is_read = 0").fetchone()[0]
            
        return {
            'users': users_count,
            'total_messages': messages_count,
            'unread_messages': unread_count
        }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return {'users': 0, 'total_messages': 0, 'unread_messages': 0}

# ===== ERROR HANDLERS =====
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ===== ROUTES =====
@app.route("/")
def index():
    return jsonify({
        "service": "PaL-HyperSecure Messaging Server",
        "status": "running",
        "version": "2.0.0",
        "features": ["secure messaging", "user authentication", "message encryption"]
    })

@app.route("/status")
def status():
    """Get server status and statistics."""
    try:
        stats = get_user_stats()
        
        # Trigger cleanup during status check
        cleanup_old_messages()
        
        return jsonify({
            "status": "online",
            "users": stats['users'],
            "total_messages": stats['total_messages'],
            "unread_messages": stats['unread_messages'],
            "uptime": time.time(),
            "max_message_length": MAX_MESSAGE_LENGTH,
            "message_retention_days": MESSAGE_RETENTION_DAYS,
            "message": "Messaging server operational"
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
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            return jsonify({"error": error_msg}), 400
        
        if not public_key or len(public_key) < 100:
            return jsonify({"error": "Valid public key is required"}), 400

        with get_db_connection() as conn:
            # Check if username already exists (case-insensitive)
            existing = conn.execute(
                "SELECT username FROM users WHERE LOWER(username) = LOWER(?)",
                (username,)
            ).fetchone()
            
            if existing:
                return jsonify({"error": "Username already exists"}), 409
            
            # Insert new user
            conn.execute(
                "INSERT INTO users (username, public_key) VALUES (?, ?)",
                (username, public_key)
            )
            conn.commit()

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

        with get_db_connection() as conn:
            # Case-insensitive username lookup
            user = conn.execute(
                "SELECT username FROM users WHERE LOWER(username) = LOWER(?) AND is_active = 1",
                (username,)
            ).fetchone()
            
            if not user:
                return jsonify({"error": "Username not found"}), 404
            
            actual_username = user['username']
            
            # Update last login
            conn.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
                (actual_username,)
            )
            conn.commit()

        # Generate JWT token
        token = jwt.encode(
            {
                'username': actual_username,
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        
        logger.info(f"User logged in: {actual_username}")
        return jsonify({
            "message": "Login successful",
            "token": token,
            "username": actual_username
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
        
        if len(content) > MAX_MESSAGE_LENGTH:
            return jsonify({"error": f"Message too long (max {MAX_MESSAGE_LENGTH} characters)"}), 400

        # Prevent self-messaging
        if recipient.lower() == current_user.lower():
            return jsonify({"error": "Cannot send message to yourself"}), 400

        with get_db_connection() as conn:
            # Check if recipient exists (case-insensitive)
            recipient_user = conn.execute(
                "SELECT username FROM users WHERE LOWER(username) = LOWER(?) AND is_active = 1",
                (recipient,)
            ).fetchone()
                
            if not recipient_user:
                return jsonify({"error": "Recipient not found"}), 404
                
            actual_recipient = recipient_user['username']
            
            # Insert message
            message_uuid = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO messages (from_user, to_user, content, message_uuid) VALUES (?, ?, ?, ?)",
                (current_user, actual_recipient, content, message_uuid)
            )
            conn.commit()

        logger.info(f"Message sent from {current_user} to {actual_recipient} (ID: {message_uuid})")
        return jsonify({
            "message": "Message sent successfully",
            "message_id": message_uuid
        }), 201
        
    except Exception as e:
        logger.error(f"Send message error: {e}")
        return jsonify({"error": "Failed to send message"}), 500

@app.route("/messages/<username>", methods=["GET"])
@token_required
def get_messages(username, current_user):
    """Get messages for current user."""
    try:
        # Ensure user can only access their own messages
        if username.lower() != current_user.lower():
            return jsonify({"error": "Unauthorized access"}), 403
        
        with get_db_connection() as conn:
            # Get unread messages
            messages_cursor = conn.execute("""
                SELECT from_user, content, created_at, message_uuid, is_read
                FROM messages 
                WHERE to_user = ? 
                ORDER BY created_at DESC
                LIMIT 50
            """, (current_user,))
            
            messages = []
            message_ids_to_mark_read = []
            
            for row in messages_cursor:
                message_data = {
                    "id": row['message_uuid'],
                    "from": row['from_user'],
                    "content": row['content'],
                    "timestamp": time.mktime(datetime.fromisoformat(row['created_at'].replace('Z', '+00:00')).timetuple()) if row['created_at'] else time.time(),
                    "read": bool(row['is_read'])
                }
                messages.append(message_data)
                
                # Collect unread message IDs to mark as read
                if not row['is_read']:
                    message_ids_to_mark_read.append(row['message_uuid'])
            
            # Mark messages as read
            if message_ids_to_mark_read:
                placeholders = ','.join('?' * len(message_ids_to_mark_read))
                conn.execute(
                    f"UPDATE messages SET is_read = 1 WHERE message_uuid IN ({placeholders})",
                    message_ids_to_mark_read
                )
                conn.commit()

        logger.info(f"Messages retrieved by {current_user}: {len(messages)} messages, {len(message_ids_to_mark_read)} marked as read")
        return jsonify({
            "messages": messages,
            "total": len(messages),
            "new_messages": len(message_ids_to_mark_read)
        })
        
    except Exception as e:
        logger.error(f"Get messages error: {e}")
        return jsonify({"error": "Failed to retrieve messages"}), 500

@app.route("/messages/<username>/unread", methods=["GET"])
@token_required
def get_unread_count(username, current_user):
    """Get count of unread messages for user."""
    try:
        if username.lower() != current_user.lower():
            return jsonify({"error": "Unauthorized access"}), 403
        
        with get_db_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE to_user = ? AND is_read = 0",
                (current_user,)
            ).fetchone()[0]

        return jsonify({"unread_count": count})
        
    except Exception as e:
        logger.error(f"Get unread count error: {e}")
        return jsonify({"error": "Failed to get unread count"}), 500

@app.route("/users", methods=["GET"])
@token_required
def list_users(current_user):
    """List active users (excluding current user)."""
    try:
        with get_db_connection() as conn:
            users_cursor = conn.execute(
                "SELECT username, created_at FROM users WHERE is_active = 1 AND username != ? ORDER BY username",
                (current_user,)
            )
            
            users = []
            for row in users_cursor:
                users.append({
                    "username": row['username'],
                    "joined": row['created_at']
                })

        return jsonify({"users": users, "total": len(users)})
        
    except Exception as e:
        logger.error(f"List users error: {e}")
        return jsonify({"error": "Failed to list users"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    try:
        # Test database connection
        with get_db_connection() as conn:
            conn.execute("SELECT 1").fetchone()
        
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected"
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 503

# ===== BACKGROUND TASKS =====
def run_scheduled_tasks():
    """Run scheduled maintenance tasks."""
    schedule.every(1).hours.do(cleanup_old_messages)
    
    while True:
        schedule.run_pending()
        time.sleep(300)  # Check every 5 minutes

# ===== INITIALIZATION =====
def initialize_server():
    """Initialize server components."""
    logger.info("Initializing PaL-HyperSecure Messaging Server v2.0...")
    
    # Initialize database
    init_database()
    
    # Start background task thread
    bg_thread = Thread(target=run_scheduled_tasks, daemon=True)
    bg_thread.start()
    
    # Initial cleanup
    cleanup_old_messages()
    
    logger.info("Server initialization complete")

if __name__ == "__main__":
    initialize_server()
    
    # Run the server
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    logger.info(f"Starting server on port {port}")
    logger.info(f"Database: {DB_FILE.absolute()}")
    logger.info(f"Debug mode: {debug}")
    
    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
        threaded=True
    )
