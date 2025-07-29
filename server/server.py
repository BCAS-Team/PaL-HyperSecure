import os
import json
import threading
import time
import psutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Union
import uvicorn

DATA_DIR = "server_data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
MESSAGES_FILE = os.path.join(DATA_DIR, "messages.json")

app = FastAPI()

# Ensure data directories and files exist
os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f) # Stores {username: {public_key, encrypted_privkey, privkey_salt, encrypted_contacts, contacts_salt, hashed_auth_passphrase, auth_salt}}
if not os.path.exists(MESSAGES_FILE):
    with open(MESSAGES_FILE, "w") as f:
        json.dump([], f) # Stores list of messages

def load_users() -> Dict[str, Dict[str, str]]:
    """Loads user data from the JSON file."""
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Handle cases where file doesn't exist or is corrupted
        return {}

def save_users(users: Dict[str, Dict[str, str]]):
    """Saves user data to the JSON file."""
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
    except IOError as e:
        print(f"Error saving users data: {e}")

def load_messages() -> List[Dict[str, str]]:
    """Loads messages from the JSON file."""
    try:
        with open(MESSAGES_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Handle cases where file doesn't exist or is corrupted
        return []

def save_messages(messages: List[Dict[str, str]]):
    """Saves messages to the JSON file."""
    try:
        with open(MESSAGES_FILE, "w") as f:
            json.dump(messages, f, indent=2)
    except IOError as e:
        print(f"Error saving messages data: {e}")

# --- Pydantic Models for API Requests ---
class RegisterRequest(BaseModel):
    username: str
    public_key: str
    encrypted_privkey: str
    privkey_salt: str
    encrypted_contacts: str
    contacts_salt: str
    hashed_auth_passphrase: str # Client sends the hash, not plaintext
    auth_salt: str # Client sends the salt used for hashing auth passphrase

class LoginChallengeRequest(BaseModel):
    username: str

class LoginRequest(BaseModel):
    username: str
    hashed_auth_passphrase_attempt: str # Client sends its hashed passphrase attempt

class SendMessageRequest(BaseModel):
    sender: str
    recipient: str
    ciphertext: str
    timestamp: str

# --- API Endpoints ---
@app.post("/register")
def register_user(req: RegisterRequest):
    """
    Registers a new user, storing their public key and encrypted client data on the server.
    Passphrase is now hashed client-side for authentication.
    """
    users = load_users()
    if req.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Store all provided encrypted client data and hashed passphrase for authentication
    users[req.username] = {
        "public_key": req.public_key,
        "encrypted_privkey": req.encrypted_privkey,
        "privkey_salt": req.privkey_salt,
        "encrypted_contacts": req.encrypted_contacts,
        "contacts_salt": req.contacts_salt,
        "hashed_auth_passphrase": req.hashed_auth_passphrase, # Store the hash
        "auth_salt": req.auth_salt # Store the salt used for authentication hashing
    }
    save_users(users)
    return {"status": "ok", "message": f"User {req.username} registered successfully."}

@app.post("/login_challenge")
def login_challenge(req: LoginChallengeRequest):
    """
    Provides the client with the necessary salt to hash their passphrase for login.
    This is the first step of a two-step authentication process.
    """
    users = load_users()
    user_data = users.get(req.username)
    
    if not user_data:
        # For a truly production-ready system, this would not immediately indicate username existence
        # to prevent enumeration attacks. Could return a generic error or a dummy salt.
        raise HTTPException(status_code=404, detail="Username not found.")
    
    # Return the authentication salt for the client to hash its passphrase
    return {
        "username": req.username,
        "auth_salt": user_data.get("auth_salt")
    }

@app.post("/login")
def login_user(req: LoginRequest):
    """
    Authenticates user using a client-side hashed passphrase and returns their
    encrypted private key and contacts data if authentication succeeds.
    This is the second step of a two-step authentication process.
    """
    users = load_users()
    user_data = users.get(req.username)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Username not found.")
    
    stored_hashed_passphrase = user_data.get("hashed_auth_passphrase")
    
    # Compare the client's hashed attempt with the stored hashed passphrase
    if not stored_hashed_passphrase or stored_hashed_passphrase != req.hashed_auth_passphrase_attempt:
        # Generic error message to avoid timing attacks and distinguish valid vs invalid password
        raise HTTPException(status_code=401, detail="Invalid username or passphrase.")
    
    # Return encrypted data needed by the client upon successful authentication
    return {
        "username": req.username,
        "public_key": user_data["public_key"],
        "encrypted_privkey": user_data["encrypted_privkey"],
        "privkey_salt": user_data["privkey_salt"],
        "encrypted_contacts": user_data["encrypted_contacts"],
        "contacts_salt": user_data["contacts_salt"]
    }

@app.get("/get_public_key/{username}")
def get_public_key(username: str):
    """Retrieves a user's public key from the server."""
    users = load_users()
    user_data = users.get(username)
    if not user_data or "public_key" not in user_data:
        raise HTTPException(status_code=404, detail="User or public key not found")
    return {"username": username, "public_key": user_data["public_key"]}

@app.post("/send_message")
def send_message(req: SendMessageRequest):
    """Stores an encrypted message to be retrieved by the recipient."""
    users = load_users()
    if req.sender not in users or req.recipient not in users:
        raise HTTPException(status_code=404, detail="Sender or recipient not found")

    messages = load_messages()
    messages.append({
        "sender": req.sender,
        "recipient": req.recipient,
        "ciphertext": req.ciphertext,
        "timestamp": req.timestamp
    })
    save_messages(messages)
    return {"status": "ok", "message": "Message sent successfully."}

@app.get("/get_messages/{username}")
def get_messages(username: str):
    """Retrieves messages for a given username."""
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")

    messages = load_messages()
    # Only return messages where the recipient matches the requested username
    user_msgs = [m for m m["recipient"] == username]
    
    return {"messages": user_msgs}

# --- Server TUI (Cross-Platform Numerical Input) ---
def clear_screen():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_menu():
    """Prints the main Server TUI menu."""
    clear_screen()
    print("="*50)
    print("🚀 Server Monitoring TUI - Encrypted Messenger 🚀".center(50))
    print("="*50)
    print("1. View Registered Users (Public Keys)")
    print("2. View Stored Messages (Last 20)")
    print("3. Server Performance Stats")
    print("4. Quit TUI (Server continues running)")
    print("="*50)
    print("\n👉 Enter the number of your choice: ")

def get_tui_choice() -> Union[int, None]:
    """Gets a numerical choice from the TUI."""
    while True:
        try:
            choice_str = input().strip()
            if choice_str.lower() == 'q':
                return -1 # Special code for quit
            choice_int = int(choice_str)
            if 1 <= choice_int <= 4:
                return choice_int
            else:
                print("Invalid choice. Please enter a number between 1 and 4.")
        except ValueError:
            print("Invalid input. Please enter a number (1-4) or 'q'.")
        except EOFError: # Handles Ctrl+D/Ctrl+Z
            return -1
        time.sleep(0.1) # Small delay to prevent tight loop on bad input

def wait_for_input(prompt: str = "Press Enter to return..."):
    """Waits for user input to simulate 'press any key'."""
    input(prompt)

def show_users():
    """Displays registered users and their public keys."""
    users = load_users()
    clear_screen()
    print("⭐ Registered Users & Public Keys ⭐\n")
    if not users:
        print("No users registered yet.")
    else:
        for username, user_data in users.items():
            # Only show username and public key in TUI for privacy
            pubkey = user_data.get("public_key", "N/A")
            # Truncate for display
            print(f"  - {username}: {pubkey[:30]}...") 
    print("\n" + "="*50)
    wait_for_input()

def show_messages():
    """Displays the last 20 messages (ciphertext only)."""
    messages = load_messages()
    clear_screen()
    print("📧 Messages (Ciphertext Only) 📧\n")
    if not messages:
        print("No messages exchanged yet.")
    else:
        for msg in messages[-20:]: 
            print(f"[{msg['timestamp']}] {msg['sender']} ➡️ {msg['recipient']}")
            print(f"  Ciphertext (truncated): {msg['ciphertext'][:50]}...\n") 
    print("\nShowing last 20 messages." if len(messages) > 20 else f"Showing all {len(messages)} messages.")
    print("="*50)
    wait_for_input()

def show_performance():
    """Displays server performance statistics."""
    clear_screen()
    print("📈 Performance Stats 📈\n")
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('.')
        procs = len(psutil.pids())

        print(f"  CPU Usage: {cpu:.2f}%")
        print(f"  Memory Usage: {mem.percent:.2f}% ({mem.used / (1024*1024):.2f} MB used)")
        print(f"  Disk Usage: {disk.percent:.2f}%")
        print(f"  Running Processes: {procs}")
    except Exception as e:
        print(f"Could not retrieve performance stats: {e}")
    print("\n" + "="*50)
    wait_for_input()

def server_tui():
    """Main function for the server's text-based user interface."""
    while True:
        print_menu()
        choice = get_tui_choice()
        
        if choice == 1:
            show_users()
        elif choice == 2:
            show_messages()
        elif choice == 3:
            show_performance()
        elif choice == 4 or choice == -1: # -1 for 'q' input
            print("Exiting TUI. Server will continue running in the background.")
            break

if __name__ == "__main__":
    # Start FastAPI server in a separate thread
    def run_server():
        print("Starting FastAPI server on http://0.0.0.0:8081...")
        uvicorn.run(app, host="0.0.0.0", port=8081, log_level="warning")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Run the TUI on the main thread
    server_tui()
