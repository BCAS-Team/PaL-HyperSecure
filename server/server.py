#!/usr/bin/env python3
"""
Enhanced Encrypted Messenger Server
Optimized for Raspberry Pi with improved security, performance, and cross-platform client support.
"""

import os
import sys
import json
import threading
import time
import signal
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio
from contextlib import asynccontextmanager

# FastAPI and related imports
try:
    from fastapi import FastAPI, HTTPException, Request, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field, validator
    import uvicorn
except ImportError:
    print("❌ Error: Required packages not found. Please install them:")
    print("   pip install fastapi uvicorn python-multipart")
    sys.exit(1)

# System monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️ Warning: psutil not available. System monitoring disabled.")

# === CONFIGURATION ===
# Server configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8081
MAX_CONNECTIONS = 100
REQUEST_TIMEOUT = 30
MAX_MESSAGE_SIZE = 10 * 1024  # 10KB max message size
MAX_USERNAME_LENGTH = 20
MAX_MESSAGES_PER_USER = 1000

# Data directories
BASE_DATA_DIR = Path("server_data")
USERS_FILE = BASE_DATA_DIR / "users.json"
MESSAGES_FILE = BASE_DATA_DIR / "messages.json"
LOGS_DIR = BASE_DATA_DIR / "logs"
BACKUP_DIR = BASE_DATA_DIR / "backups"

# Security settings
RATE_LIMIT_REQUESTS = 60  # requests per minute per IP
RATE_LIMIT_WINDOW = 60   # window in seconds
ALLOWED_HOSTS = ["*"]    # Configure for production

# Create directories
for directory in [BASE_DATA_DIR, LOGS_DIR, BACKUP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# === LOGGING SETUP ===
def setup_logging():
    """Setup comprehensive logging system."""
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Main application log
    main_handler = logging.FileHandler(LOGS_DIR / "server.log")
    main_handler.setFormatter(logging.Formatter(log_format))
    
    # Security events log
    security_handler = logging.FileHandler(LOGS_DIR / "security.log")
    security_handler.setFormatter(logging.Formatter(log_format))
    
    # Console output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    
    # Configure loggers
    main_logger = logging.getLogger("messenger")
    main_logger.setLevel(logging.INFO)
    main_logger.addHandler(main_handler)
    main_logger.addHandler(console_handler)
    
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.WARNING)
    security_logger.addHandler(security_handler)
    security_logger.addHandler(console_handler)
    
    return main_logger, security_logger

logger, security_logger = setup_logging()

# === RATE LIMITING ===
class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}
        self.lock = threading.Lock()
    
    def is_allowed(self, identifier: str, limit: int = RATE_LIMIT_REQUESTS, window: int = RATE_LIMIT_WINDOW) -> bool:
        """Check if request is allowed based on rate limits."""
        current_time = time.time()
        
        with self.lock:
            if identifier not in self.requests:
                self.requests[identifier] = []
            
            # Remove old requests outside the window
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if current_time - req_time < window
            ]
            
            # Check if under limit
            if len(self.requests[identifier]) >= limit:
                return False
            
            # Add current request
            self.requests[identifier].append(current_time)
            return True
    
    def cleanup_old_entries(self):
        """Periodic cleanup of old rate limit entries."""
        current_time = time.time()
        with self.lock:
            for identifier in list(self.requests.keys()):
                self.requests[identifier] = [
                    req_time for req_time in self.requests[identifier]
                    if current_time - req_time < RATE_LIMIT_WINDOW
                ]
                if not self.requests[identifier]:
                    del self.requests[identifier]

rate_limiter = RateLimiter()

# === DATA MANAGEMENT ===
class DataManager:
    """Thread-safe data management with backup capabilities."""
    
    def __init__(self):
        self.lock = threading.RLock()
        self._users_cache: Optional[Dict] = None
        self._messages_cache: Optional[List] = None
        self.initialize_files()
    
    def initialize_files(self):
        """Initialize data files if they don't exist."""
        if not USERS_FILE.exists():
            with open(USERS_FILE, "w", encoding='utf-8') as f:
                json.dump({}, f)
            logger.info("Initialized users.json")
        
        if not MESSAGES_FILE.exists():
            with open(MESSAGES_FILE, "w", encoding='utf-8') as f:
                json.dump([], f)
            logger.info("Initialized messages.json")
    
    def create_backup(self, backup_type: str = "manual"):
        """Create backup of current data."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_subdir = BACKUP_DIR / f"{backup_type}_{timestamp}"
            backup_subdir.mkdir(exist_ok=True)
            
            # Backup users
            if USERS_FILE.exists():
                import shutil
                shutil.copy2(USERS_FILE, backup_subdir / "users.json")
            
            # Backup messages
            if MESSAGES_FILE.exists():
                import shutil
                shutil.copy2(MESSAGES_FILE, backup_subdir / "messages.json")
            
            logger.info(f"Backup created: {backup_subdir}")
            return True
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
    
    def load_users(self) -> Dict:
        """Load users data with caching."""
        with self.lock:
            try:
                with open(USERS_FILE, "r", encoding='utf-8') as f:
                    self._users_cache = json.load(f)
                return self._users_cache.copy()
            except Exception as e:
                logger.error(f"Error loading users: {e}")
                return {}
    
    def save_users(self, users: Dict) -> bool:
        """Save users data atomically."""
        with self.lock:
            try:
                # Write to temporary file first
                temp_file = USERS_FILE.with_suffix('.tmp')
                with open(temp_file, "w", encoding='utf-8') as f:
                    json.dump(users, f, indent=2, ensure_ascii=False)
                
                # Atomic move
                temp_file.replace(USERS_FILE)
                self._users_cache = users.copy()
                logger.info(f"Users data saved ({len(users)} users)")
                return True
            except Exception as e:
                logger.error(f"Error saving users: {e}")
                return False
    
    def load_messages(self) -> List:
        """Load messages data with caching."""
        with self.lock:
            try:
                with open(MESSAGES_FILE, "r", encoding='utf-8') as f:
                    self._messages_cache = json.load(f)
                return self._messages_cache.copy()
            except Exception as e:
                logger.error(f"Error loading messages: {e}")
                return []
    
    def save_messages(self, messages: List) -> bool:
        """Save messages data atomically."""
        with self.lock:
            try:
                # Limit messages per user to prevent storage bloat
                user_message_counts = {}
                filtered_messages = []
                
                # Process messages in reverse order (newest first)
                for message in reversed(messages):
                    recipient = message.get('recipient', '')
                    if recipient not in user_message_counts:
                        user_message_counts[recipient] = 0
                    
                    if user_message_counts[recipient] < MAX_MESSAGES_PER_USER:
                        filtered_messages.append(message)
                        user_message_counts[recipient] += 1
                
                # Reverse back to chronological order
                filtered_messages.reverse()
                
                # Write to temporary file first
                temp_file = MESSAGES_FILE.with_suffix('.tmp')
                with open(temp_file, "w", encoding='utf-8') as f:
                    json.dump(filtered_messages, f, indent=2, ensure_ascii=False)
                
                # Atomic move
                temp_file.replace(MESSAGES_FILE)
                self._messages_cache = filtered_messages.copy()
                
                removed_count = len(messages) - len(filtered_messages)
                if removed_count > 0:
                    logger.info(f"Messages saved ({len(filtered_messages)} kept, {removed_count} removed)")
                else:
                    logger.info(f"Messages saved ({len(filtered_messages)} messages)")
                
                return True
            except Exception as e:
                logger.error(f"Error saving messages: {e}")
                return False
    
    def get_user_stats(self) -> Dict:
        """Get user statistics."""
        users = self.load_users()
        messages = self.load_messages()
        
        user_message_counts = {}
        for message in messages:
            recipient = message.get('recipient', '')
            if recipient in user_message_counts:
                user_message_counts[recipient] += 1
            else:
                user_message_counts[recipient] = 1
        
        return {
            "total_users": len(users),
            "total_messages": len(messages),
            "user_message_counts": user_message_counts
        }

data_manager = DataManager()

# === PYDANTIC MODELS ===
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=MAX_USERNAME_LENGTH)
    public_key: str = Field(..., min_length=10)
    encrypted_privkey: str = Field(..., min_length=10)
    privkey_salt: str = Field(..., min_length=10)
    encrypted_contacts: str = Field(default="")
    contacts_salt: str = Field(default="")
    hashed_auth_passphrase: str = Field(..., min_length=10)
    auth_salt: str = Field(..., min_length=10)
    
    @validator('username')
    def validate_username(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username must be alphanumeric (with _ and - allowed)')
        return v

class LoginChallengeRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=MAX_USERNAME_LENGTH)

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=MAX_USERNAME_LENGTH)
    hashed_auth_passphrase_attempt: str = Field(..., min_length=10)

class SendMessageRequest(BaseModel):
    sender: str = Field(..., min_length=3, max_length=MAX_USERNAME_LENGTH)
    recipient: str = Field(..., min_length=3, max_length=MAX_USERNAME_LENGTH)
    ciphertext: str = Field(..., min_length=10, max_length=MAX_MESSAGE_SIZE)
    timestamp: str = Field(...)
    
    @validator('ciphertext')
    def validate_ciphertext_size(cls, v):
        # Rough check for base64 encoded data size
        if len(v) > MAX_MESSAGE_SIZE:
            raise ValueError(f'Message too large (max {MAX_MESSAGE_SIZE} chars)')
        return v

# === MIDDLEWARE ===
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware."""
    client_ip = request.client.host
    
    if not rate_limiter.is_allowed(client_ip):
        security_logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again later."}
        )
    
    response = await call_next(request)
    return response

# === FASTAPI APP SETUP ===
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    logger.info("🚀 Starting Encrypted Messenger Server")
    logger.info(f"📁 Data directory: {BASE_DATA_DIR}")
    
    # Create initial backup
    data_manager.create_backup("startup")
    
    # Start cleanup task
    cleanup_task = asyncio.create_task(periodic_cleanup())
    
    try:
        yield
    finally:
        logger.info("🛑 Shutting down server")
        cleanup_task.cancel()
        
        # Create shutdown backup
        data_manager.create_backup("shutdown")

app = FastAPI(
    title="Encrypted Messenger Server",
    description="Secure messaging server with end-to-end encryption",
    version="2.0.0",
    lifespan=lifespan
)

# Add middleware
app.middleware("http")(rate_limit_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

# === API ENDPOINTS ===
@app.post("/register")
async def register_user(req: RegisterRequest, request: Request):
    """Register a new user or update existing user data."""
    client_ip = request.client.host
    logger.info(f"Registration attempt for user '{req.username}' from {client_ip}")
    
    try:
        users = data_manager.load_users()
        
        # Check if this is an update for existing user
        is_update = req.username in users
        
        # Store user data
        users[req.username] = {
            "public_key": req.public_key,
            "encrypted_privkey": req.encrypted_privkey,
            "privkey_salt": req.privkey_salt,
            "encrypted_contacts": req.encrypted_contacts,
            "contacts_salt": req.contacts_salt,
            "hashed_auth_passphrase": req.hashed_auth_passphrase,
            "auth_salt": req.auth_salt,
            "registration_time": datetime.now(timezone.utc).isoformat(),
            "last_update": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip
        }
        
        if data_manager.save_users(users):
            action = "updated" if is_update else "registered"
            logger.info(f"User '{req.username}' {action} successfully")
            return {"status": "ok", "message": f"User {req.username} {action} successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to save user data")
            
    except Exception as e:
        logger.error(f"Registration error for '{req.username}': {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/login_challenge")
async def login_challenge(req: LoginChallengeRequest, request: Request):
    """Provide authentication salt for login challenge."""
    client_ip = request.client.host
    logger.info(f"Login challenge for user '{req.username}' from {client_ip}")
    
    try:
        users = data_manager.load_users()
        user_data = users.get(req.username)
        
        if not user_data:
            security_logger.warning(f"Login challenge failed - user not found: '{req.username}' from {client_ip}")
            raise HTTPException(status_code=404, detail="User not found")
        
        auth_salt = user_data.get("auth_salt")
        if not auth_salt:
            logger.error(f"Missing auth_salt for user '{req.username}'")
            raise HTTPException(status_code=500, detail="User data corrupted")
        
        return {"auth_salt": auth_salt}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login challenge error for '{req.username}': {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/login")
async def login_user(req: LoginRequest, request: Request):
    """Authenticate user and return encrypted user data."""
    client_ip = request.client.host
    logger.info(f"Login attempt for user '{req.username}' from {client_ip}")
    
    try:
        users = data_manager.load_users()
        user_data = users.get(req.username)
        
        if not user_data:
            security_logger.warning(f"Login failed - user not found: '{req.username}' from {client_ip}")
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify hashed passphrase
        stored_hash = user_data.get("hashed_auth_passphrase")
        if not stored_hash or stored_hash != req.hashed_auth_passphrase_attempt:
            security_logger.warning(f"Login failed - invalid passphrase: '{req.username}' from {client_ip}")
            raise HTTPException(status_code=401, detail="Invalid passphrase")
        
        # Update last login time
        user_data["last_login"] = datetime.now(timezone.utc).isoformat()
        user_data["last_login_ip"] = client_ip
        users[req.username] = user_data
        data_manager.save_users(users)
        
        logger.info(f"User '{req.username}' logged in successfully from {client_ip}")
        
        # Return user data (excluding sensitive auth info)
        return {
            "username": req.username,
            "public_key": user_data["public_key"],
            "encrypted_privkey": user_data["encrypted_privkey"],
            "privkey_salt": user_data["privkey_salt"],
            "encrypted_contacts": user_data.get("encrypted_contacts", ""),
            "contacts_salt": user_data.get("contacts_salt", "")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for '{req.username}': {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/get_public_key/{username}")
async def get_public_key(username: str, request: Request):
    """Retrieve a user's public key."""
    client_ip = request.client.host
    logger.info(f"Public key request for '{username}' from {client_ip}")
    
    try:
        if len(username) > MAX_USERNAME_LENGTH:
            raise HTTPException(status_code=400, detail="Invalid username length")
        
        users = data_manager.load_users()
        user_data = users.get(username)
        
        if not user_data or "public_key" not in user_data:
            logger.warning(f"Public key not found for user '{username}'")
            raise HTTPException(status_code=404, detail="User or public key not found")
        
        return {
            "username": username,
            "public_key": user_data["public_key"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting public key for '{username}': {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/send_message")
async def send_message(req: SendMessageRequest, request: Request):
    """Store an encrypted message for delivery."""
    client_ip = request.client.host
    logger.info(f"Message from '{req.sender}' to '{req.recipient}' from {client_ip}")
    
    try:
        # Verify both users exist
        users = data_manager.load_users()
        if req.sender not in users:
            security_logger.warning(f"Message from unknown sender: '{req.sender}' from {client_ip}")
            raise HTTPException(status_code=404, detail="Sender not found")
        
        if req.recipient not in users:
            logger.warning(f"Message to unknown recipient: '{req.recipient}'")
            raise HTTPException(status_code=404, detail="Recipient not found")
        
        # Validate timestamp
        try:
            datetime.fromisoformat(req.timestamp.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid timestamp format")
        
        # Load and update messages
        messages = data_manager.load_messages()
        
        message_data = {
            "sender": req.sender,
            "recipient": req.recipient,
            "ciphertext": req.ciphertext,
            "timestamp": req.timestamp,
            "server_timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip
        }
        
        messages.append(message_data)
        
        if data_manager.save_messages(messages):
            logger.info(f"Message stored: {req.sender} -> {req.recipient}")
            return {"status": "ok", "message": "Message sent successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to store message")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending message from '{req.sender}' to '{req.recipient}': {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/get_messages/{username}")
async def get_messages(username: str, request: Request):
    """Retrieve messages for a user."""
    client_ip = request.client.host
    logger.info(f"Message retrieval for '{username}' from {client_ip}")
    
    try:
        if len(username) > MAX_USERNAME_LENGTH:
            raise HTTPException(status_code=400, detail="Invalid username length")
        
        # Verify user exists
        users = data_manager.load_users()
        if username not in users:
            security_logger.warning(f"Message retrieval for unknown user: '{username}' from {client_ip}")
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get user's messages
        messages = data_manager.load_messages()
        user_messages = [
            {
                "sender": msg["sender"],
                "recipient": msg["recipient"],
                "ciphertext": msg["ciphertext"],
                "timestamp": msg["timestamp"]
            }
            for msg in messages
            if msg["recipient"] == username
        ]
        
        logger.info(f"Retrieved {len(user_messages)} messages for '{username}'")
        return {"messages": user_messages}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving messages for '{username}': {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/server_stats")
async def get_server_stats(request: Request):
    """Get server statistics (admin endpoint)."""
    client_ip = request.client.host
    logger.info(f"Server stats request from {client_ip}")
    
    try:
        stats = data_manager.get_user_stats()
        
        # System stats
        system_stats = {}
        if PSUTIL_AVAILABLE:
            system_stats = {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('.').percent,
                "process_count": len(psutil.pids())
            }
        
        return {
            "user_stats": stats,
            "system_stats": system_stats,
            "server_uptime": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0
        }
        
    except Exception as e:
        logger.error(f"Error getting server stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# === BACKGROUND TASKS ===
async def periodic_cleanup():
    """Periodic cleanup tasks."""
    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            
            # Clean up rate limiter
            rate_limiter.cleanup_old_entries()
            
            # Create periodic backup (every hour)
            current_hour = datetime.now().hour
            if current_hour != getattr(periodic_cleanup, 'last_backup_hour', -1):
                data_manager.create_backup("periodic")
                periodic_cleanup.last_backup_hour = current_hour
                
            logger.debug("Periodic cleanup completed")
            
        except asyncio.CancelledError:
            logger.info("Cleanup task cancelled")
            break
        except Exception as e:
            logger.error(f"Error in periodic cleanup: {e}")

# === SERVER MONITORING TUI ===
class ServerTUI:
    """Text-based user interface for server monitoring."""
    
    def __init__(self):
        self.running = False
    
    def clear_screen(self):
        """Clear the console screen."""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except:
            print('\n' * 50)
    
    def print_header(self):
        """Print the TUI header."""
        self.clear_screen()
        print("=" * 70)
        print("🚀 ENCRYPTED MESSENGER SERVER - MONITORING TUI 🚀".center(70))
        print("=" * 70)
        print(f"📊 Server Status: {'🟢 RUNNING' if self.running else '🔴 STOPPED'}")
        print(f"🌐 Address: http://{SERVER_HOST}:{SERVER_PORT}")
        print(f"📁 Data Directory: {BASE_DATA_DIR}")
        print("=" * 70)
    
    def show_menu(self):
        """Display the main menu."""
        options = [
            "👥 View Registered Users",
            "📧 View Recent Messages",
            "📊 Server Performance Stats",
            "📈 User Statistics",
            "💾 Create Backup",
            "📋 View Logs",
            "🔄 Restart Server",
            "❌ Exit TUI (Server continues)"
        ]
        
        print("\n📋 Available Options:")
        for i, option in enumerate(options, 1):
            print(f"   {i}. {option}")
        
        print("=" * 70)
        return len(options)
    
    def show_users(self):
        """Display registered users."""
        self.print_header()
        print("👥 REGISTERED USERS")
        print("=" * 70)
        
        try:
            users = data_manager.load_users()
            if not users:
                print("📝 No users registered yet.")
            else:
                print(f"📊 Total Users: {len(users)}\n")
                for username, user_data in users.items():
                    reg_time = user_data.get('registration_time', 'Unknown')
                    last_login = user_data.get('last_login', 'Never')
                    print(f"   👤 {username}")
                    print(f"      📅 Registered: {reg_time}")
                    print(f"      🔑 Last Login: {last_login}")
                    print(f"      🔐 Public Key: {user_data.get('public_key', '')[:30]}...")
                    print()
        except Exception as e:
            print(f"❌ Error loading users: {e}")
        
        print("=" * 70)
        input("\n⏎ Press Enter to continue...")
    
    def show_messages(self):
        """Display recent messages."""
        self.print_header()
        print("📧 RECENT MESSAGES (Last 20)")
        print("=" * 70)
        
        try:
            messages = data_manager.load_messages()
            if not messages:
                print("📝 No messages exchanged yet.")
            else:
                recent_messages = messages[-20:]  # Last 20 messages
                print(f"📊 Total Messages: {len(messages)} (showing last {len(recent_messages)})\n")
                
                for msg in recent_messages:
                    timestamp = msg.get('timestamp', 'Unknown')
                    sender = msg.get('sender', 'Unknown')
                    recipient = msg.get('recipient', 'Unknown')
                    ciphertext = msg.get('ciphertext', '')
                    
                    print(f"   📨 {timestamp}")
                    print(f"      From: {sender} → To: {recipient}")
                    print(f"      Content: {ciphertext[:50]}{'...' if len(ciphertext) > 50 else ''}")
                    print()
        except Exception as e:
            print(f"❌ Error loading messages: {e}")
        
        print("=" * 70)
        input("\n⏎ Press Enter to continue...")
    
    def show_performance(self):
        """Display server performance statistics."""
        self.print_header()
        print("📊 SERVER PERFORMANCE")
        print("=" * 70)
        
        try:
            if PSUTIL_AVAILABLE:
                # CPU Information
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                
                # Memory Information
                memory = psutil.virtual_memory()
                
                # Disk Information
                disk = psutil.disk_usage('.')
                
                # Network Information
                try:
                    net_io = psutil.net_io_counters()
                    network_available = True
                except:
                    network_available = False
                
                print("🖥️  System Information:")
                print(f"   Platform: {os.uname().sysname} {os.uname().release}")
                print(f"   Python: {sys.version.split()[0]}")
                print(f"   PID: {os.getpid()}")
                
                print(f"\n⚡ CPU Information:")
                print(f"   Cores: {cpu_count}")
                print(f"   Usage: {cpu_percent:.1f}%")
                
                print(f"\n💾 Memory Information:")
                print(f"   Total: {memory.total / (1024**3):.1f} GB")
                print(f"   Used: {memory.used / (1024**3):.1f} GB ({memory.percent:.1f}%)")
                print(f"   Available: {memory.available / (1024**3):.1f} GB")
                
                print(f"\n💿 Disk Information:")
                print(f"   Total: {disk.total / (1024**3):.1f} GB")
                print(f"   Used: {disk.used / (1024**3):.1f} GB ({disk.percent:.1f}%)")
                print(f"   Free: {disk.free / (1024**3):.1f} GB")
                
                if network_available:
                    print(f"\n🌐 Network Information:")
                    print(f"   Bytes Sent: {net_io.bytes_sent / (1024**2):.1f} MB")
                    print(f"   Bytes Received: {net_io.bytes_recv / (1024**2):.1f} MB")
                
            else:
                print("❌ System monitoring not available (psutil not installed)")
                
        except Exception as e:
            print(f"❌ Error getting performance stats: {e}")
        
        print("=" * 70)
        input("\n⏎ Press Enter to continue...")
    
    def show_user_statistics(self):
        """Display user statistics."""
        self.print_header()
        print("📈 USER STATISTICS")
        print("=" * 70)
        
        try:
            stats = data_manager.get_user_stats()
            
            print(f"📊 Overview:")
            print(f"   Total Users: {stats['total_users']}")
            print(f"   Total Messages: {stats['total_messages']}")
            
            if stats['user_message_counts']:
                print(f"\n📧 Messages per User:")
                sorted_users = sorted(
                    stats['user_message_counts'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                
                for username, count in sorted_users[:10]:  # Top 10
                    print(f"   {username}: {count} messages")
                
                if len(sorted_users) > 10:
                    print(f"   ... and {len(sorted_users) - 10} more users")
                    
        except Exception as e:
            print(f"❌ Error getting user statistics: {e}")
        
        print("=" * 70)
        input("\n⏎ Press Enter to continue...")
    
    def create_backup(self):
        """Create a manual backup."""
        self.print_header()
        print("💾 CREATE BACKUP")
        print("=" * 70)
        
        print("🔄 Creating backup...")
        if data_manager.create_backup("manual"):
            print("✅ Backup created successfully!")
        else:
            print("❌ Backup creation failed!")
        
        print("=" * 70)
        input("\n⏎ Press Enter to continue...")
    
    def view_logs(self):
        """View recent log entries."""
        self.print_header()
        print("📋 RECENT LOG ENTRIES")
        print("=" * 70)
        
        try:
            log_file = LOGS_DIR / "server.log"
            if log_file.exists():
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    recent_lines = lines[-20:]  # Last 20 lines
                    
                print("📝 Last 20 log entries:\n")
                for line in recent_lines:
                    print(f"   {line.strip()}")
            else:
                print("📝 No log file found.")
                
        except Exception as e:
            print(f"❌ Error reading logs: {e}")
        
        print("=" * 70)
        input("\n⏎ Press Enter to continue...")
    
    def run(self):
        """Run the TUI main loop."""
        self.running = True
        
        while True:
            try:
                self.print_header()
                max_options = self.show_menu()
                
                choice = input(f"\n👉 Enter choice (1-{max_options}): ").strip()
                
                if choice == '1':
                    self.show_users()
                elif choice == '2':
                    self.show_messages()
                elif choice == '3':
                    self.show_performance()
                elif choice == '4':
                    self.show_user_statistics()
                elif choice == '5':
                    self.create_backup()
                elif choice == '6':
                    self.view_logs()
                elif choice == '7':
                    print("\n🔄 Server restart functionality not implemented in TUI mode.")
                    print("💡 Please restart the server manually.")
                    input("\n⏎ Press Enter to continue...")
                elif choice == '8':
                    print("\n👋 Exiting TUI. Server continues running in background.")
                    break
                else:
                    print(f"\n❌ Invalid choice. Please enter 1-{max_options}.")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\n\n👋 Exiting TUI. Server continues running.")
                break
            except EOFError:
                print("\n\n👋 Exiting TUI. Server continues running.")
                break
            except Exception as e:
                print(f"\n❌ TUI Error: {e}")
                time.sleep(2)

# === SIGNAL HANDLERS ===
def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        # Create shutdown backup
        data_manager.create_backup("signal_shutdown")
        sys.exit(0)
    
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    except:
        pass  # Some signals might not be available on all platforms

# === MAIN EXECUTION ===
def run_server():
    """Run the FastAPI server."""
    logger.info("Starting FastAPI server...")
    
    app.state.start_time = time.time()
    
    config = uvicorn.Config(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        log_level="warning",  # Reduce uvicorn log noise
        access_log=False,     # Disable access logs (we have our own)
        server_header=False,  # Don't expose server info
        limit_max_requests=MAX_CONNECTIONS
    )
    
    server = uvicorn.Server(config)
    server.run()

def main():
    """Main entry point."""
    setup_signal_handlers()
    
    print("=" * 70)
    print("🔐 ENCRYPTED MESSENGER SERVER 🔐".center(70))
    print("=" * 70)
    print(f"📁 Data Directory: {BASE_DATA_DIR}")
    print(f"📋 Logs Directory: {LOGS_DIR}")
    print(f"💾 Backup Directory: {BACKUP_DIR}")
    print("=" * 70)
    
    # Check if we should run in TUI mode or server mode
    if len(sys.argv) > 1 and sys.argv[1] == "--tui-only":
        print("🖥️  Running in TUI-only mode (server not started)")
        tui = ServerTUI()
        tui.running = False
        tui.run()
        return
    
    # Start server in background thread
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    
    # Give server a moment to start
    time.sleep(2)
    
    # Run TUI on main thread
    print("🖥️  Starting server monitoring TUI...")
    tui = ServerTUI()
    try:
        tui.run()
    except KeyboardInterrupt:
        print("\n👋 Shutting down server...")
    
    logger.info("Server shutdown complete")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Server shutdown by user")
    except Exception as e:
        logger.error(f"Critical server error: {e}")
        print(f"❌ Critical error: {e}")
        sys.exit(1)
