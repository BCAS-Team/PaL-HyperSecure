import os
import sys
import json
import base64
import time
import datetime
import threading
import requests
import msvcrt # Re-introducing msvcrt for Windows-specific TUI control
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError
from nacl.utils import randombytes_deterministic
from nacl import pwhash # For stronger password hashing

SERVER = "http://127.0.0.1:8081"
LOCAL_DATA_DIR = "local_data"

os.makedirs(LOCAL_DATA_DIR, exist_ok=True)

# --- Utility functions ---
def clear_screen():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def b64encode(data: bytes) -> str:
    """Encodes bytes to a base64 string."""
    return base64.b64encode(data).decode('utf-8')

def b64decode(data: str) -> bytes:
    """Decodes a base64 string to bytes."""
    return base64.b64decode(data.encode('utf-8'))

def save_local_user_data(username, data):
    """Saves user-specific data to a local JSON file."""
    path = os.path.join(LOCAL_DATA_DIR, f"{username}_data.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_local_user_data(username):
    """Loads user-specific data from a local JSON file."""
    path = os.path.join(LOCAL_DATA_DIR, f"{username}_data.json")
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON from {path}. File might be corrupted.")
            return None
    return None

def wait_for_input(prompt="Press Enter to continue..."):
    """Waits for user input to simulate 'press any key'."""
    input(prompt)

def wait_key():
    """Reads a single keypress, handling arrow keys specifically (Windows only)."""
    while True:
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            if ch == b'\xe0':  # Arrow key prefix
                ch2 = msvcrt.getch()
                key_map = {b'H': 'UP', b'P': 'DOWN', b'K': 'LEFT', b'M': 'RIGHT'}
                return key_map.get(ch2, None)
            elif ch == b'\r': # Enter key
                return 'ENTER'
            else:
                try:
                    # Return character as string, e.g., for general text input
                    return ch.decode('utf-8')
                except UnicodeDecodeError:
                    return None # Ignore undecodable characters

def input_with_prompt(prompt):
    """Custom input function to ensure prompt is printed before input."""
    print(prompt, end="", flush=True)
    return input()

def menu(title, options):
    """
    Displays a menu with arrow key navigation and Enter selection.
    Returns the 0-indexed selected option.
    (Windows-specific due to msvcrt)
    """
    selected = 0
    while True:
        clear_screen()
        print("=" * 50)
        print(title.center(50))
        print("=" * 50)
        for i, opt in enumerate(options):
            if i == selected:
                print(f"👉 {opt}".ljust(49)) # Highlight selected option
            else:
                print(f"   {opt}".ljust(49))
        print("=" * 50)
        print("\nUse ↑↓ to navigate, Enter to select.")
        
        key = wait_key()
        if key == 'UP':
            selected = (selected - 1) % len(options)
        elif key == 'DOWN':
            selected = (selected + 1) % len(options)
        elif key == 'ENTER':
            return selected

# --- Encryption helpers ---
def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derives a 32-byte (SecretBox.KEY_SIZE) key from a passphrase using Scrypt.
    Returns (derived_key, salt).
    
    If salt is None, a new random salt is generated.
    """
    if salt is None:
        salt = pwhash.scrypt._salt(pwhash.scrypt.SALTBYTES) # Generate a new random salt

    # Use Scrypt for key derivation. Opslimit and memlimit are security parameters.
    # Adjust these based on desired security and performance.
    # These are defaults from PyNaCl's pwhash.scrypt.OPSLIMIT_MODERATE and pwhash.scrypt.MEMLIMIT_MODERATE
    opslimit = pwhash.scrypt.OPSLIMIT_MODERATE
    memlimit = pwhash.scrypt.MEMLIMIT_MODERATE

    derived_key = pwhash.scrypt.kdf(
        size=SecretBox.KEY_SIZE, # Ensure key size is appropriate for SecretBox (32 bytes)
        password=passphrase.encode('utf-8'),
        salt=salt,
        opslimit=opslimit,
        memlimit=memlimit
    )
    return derived_key, salt

def encrypt_private_key(privkey: PrivateKey, passphrase: str) -> tuple[str, str]:
    """Encrypts a PrivateKey object using a passphrase and a newly derived key with a fresh salt.
    Returns (encrypted_data_b64, salt_b64)."""
    key, salt = derive_key(passphrase) # Generate a new random salt
    box = SecretBox(key)
    encrypted = box.encrypt(privkey.encode())
    return b64encode(encrypted), b64encode(salt)

def decrypt_private_key(encrypted_str: str, salt_str: str, passphrase: str) -> PrivateKey | None:
    """Decrypts an encrypted private key string using a passphrase and the provided salt."""
    salt = b64decode(salt_str)
    key, _ = derive_key(passphrase, salt) # Derive key using the stored salt
    box = SecretBox(key)
    try:
        decrypted = box.decrypt(b64decode(encrypted_str))
        return PrivateKey(decrypted)
    except CryptoError:
        print("Decryption failed. Incorrect passphrase or corrupted data.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

def encrypt_contacts_data(contacts_dict: dict, passphrase: str) -> tuple[str, str]:
    """Encrypts the contacts dictionary using a newly derived key with a fresh salt."""
    contacts_json = json.dumps(contacts_dict).encode('utf-8')
    key, salt = derive_key(passphrase) # Generate a new random salt
    box = SecretBox(key)
    encrypted_contacts = box.encrypt(contacts_json)
    return b64encode(encrypted_contacts), b64encode(salt)

def decrypt_contacts_data(encrypted_str: str, salt_str: str, passphrase: str) -> dict | None:
    """Decrypts the contacts dictionary using the provided salt."""
    salt = b64decode(salt_str)
    key, _ = derive_key(passphrase, salt)
    box = SecretBox(key)
    try:
        decrypted_contacts = box.decrypt(b64decode(encrypted_str)).decode('utf-8')
        return json.loads(decrypted_contacts)
    except CryptoError:
        print("Failed to decrypt contacts. Incorrect passphrase or corrupted data.")
        return None
    except json.JSONDecodeError:
        print("Failed to parse decrypted contacts data. Corrupted data.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during contacts decryption: {e}")
        return None


# --- Core User functions ---
def register():
    """Handles user registration process."""
    clear_screen()
    print("=== 🔑 Register New Account 🔑 ===")
    username = input_with_prompt("Choose username: ").strip()
    if not username:
        print("Username cannot be empty.")
        time.sleep(1)
        return None

    while True:
        passphrase = input_with_prompt("Set a strong passphrase (min 8 chars, max 32 chars): ").strip()
        if 8 <= len(passphrase) <= 32:
            passphrase_confirm = input_with_prompt("Confirm passphrase: ").strip()
            if passphrase == passphrase_confirm:
                break
            else:
                print("Passphrases do not match. Please try again.")
        else:
            print("Passphrase length must be between 8 and 32 characters.")

    try:
        # Generate new keys
        privkey = PrivateKey.generate()
        pubkey_b64 = b64encode(privkey.public_key.encode())
        
        # Encrypt private key and generate salt
        encrypted_privkey, privkey_salt = encrypt_private_key(privkey, passphrase)
        
        # Encrypt an empty contacts dictionary initially
        encrypted_contacts, contacts_salt = encrypt_contacts_data({}, passphrase)

        # Structure of local user data (and what will be sent to server)
        local_data = {
            "username": username,
            "public_key": pubkey_b64,
            "encrypted_privkey": encrypted_privkey,
            "privkey_salt": privkey_salt,
            "encrypted_contacts": encrypted_contacts,
            "contacts_salt": contacts_salt
        }

        # Attempt to register with the server (sends all encrypted client-side data plus passphrase)
        # NOTE: Passphrase is still sent to the server for current cross-device login implementation.
        # This will be addressed in the next step for complete privacy.
        resp = requests.post(f"{SERVER}/register", json={
            "username": username,
            "public_key": pubkey_b64,
            "passphrase": passphrase, # WARNING: Passphrase sent to server for this simplified cross-device login!
            "encrypted_privkey": encrypted_privkey,
            "privkey_salt": privkey_salt,
            "encrypted_contacts": encrypted_contacts,
            "contacts_salt": contacts_salt
        })
        resp.raise_for_status()

        save_local_user_data(username, local_data) # Save locally for first device
        print(f"✅ User '{username}' registered successfully!")
        print("Your private key and contacts are encrypted with a stronger KDF and stored locally AND on the server for cross-device login.")
        time.sleep(2)
        return username, privkey, passphrase
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the server. Registration failed.")
        print("Please ensure the server is running.")
        time.sleep(2)
        return None
    except requests.exceptions.HTTPError as e:
        error_detail = e.response.json().get("detail", "Unknown error")
        print(f"❌ Server registration failed: {error_detail}")
        time.sleep(2)
        return None
    except Exception as e:
        print(f"❌ An unexpected error occurred during registration: {e}")
        time.sleep(2)
        return None

def login():
    """Handles user login process. Tries local data first, then server for cross-device."""
    clear_screen()
    print("=== 🔓 Login ===")
    username = input_with_prompt("Username: ").strip()
    passphrase = input_with_prompt("Passphrase: ").strip()

    data = load_local_user_data(username)
    
    if not data:
        print("Local user data not found. Attempting to fetch from server for cross-device login...")
        try:
            # NOTE: Passphrase is still sent to the server for current cross-device login implementation.
            # This will be addressed in the next step for complete privacy.
            resp = requests.post(f"{SERVER}/login", json={
                "username": username,
                "passphrase": passphrase
            })
            resp.raise_for_status()
            data = resp.json() # This 'data' now contains public_key, encrypted_privkey etc. from server
            print("Successfully fetched user data from server.")
            save_local_user_data(username, data) # Save to this device for future local logins
        except requests.exceptions.ConnectionError:
            print("❌ Error: Could not connect to the server. Cannot login.")
            time.sleep(2)
            return None
        except requests.exceptions.HTTPError as e:
            error_detail = e.response.json().get("detail", "Unknown error")
            print(f"❌ Server login failed: {error_detail}")
            time.sleep(2)
            return None
        except Exception as e:
            print(f"❌ An unexpected error occurred during server login: {e}")
            time.sleep(2)
            return None

    # Proceed with decryption using the (local or fetched) data
    encrypted_privkey = data.get("encrypted_privkey")
    privkey_salt = data.get("privkey_salt")
    if not encrypted_privkey or not privkey_salt:
        print("❌ Corrupted user data: private key or salt missing.")
        time.sleep(2)
        return None

    privkey = decrypt_private_key(encrypted_privkey, privkey_salt, passphrase)
    if not privkey:
        print("❌ Invalid passphrase or corrupted private key data.")
        time.sleep(2)
        return None
    
    # Decrypt contacts for session
    encrypted_contacts = data.get("encrypted_contacts")
    contacts_salt = data.get("contacts_salt")
    if not encrypted_contacts or not contacts_salt:
        print("❌ Corrupted contacts data or contacts salt missing. Initializing empty contacts for this session.")
        # If contacts data is corrupted, we assume empty. In a real app, might warn user.
        data["contacts"] = {}
        # Re-encrypt and save if corrupted.
        encrypted_contacts, contacts_salt = encrypt_contacts_data({}, passphrase)
        data["encrypted_contacts"] = encrypted_contacts
        data["contacts_salt"] = contacts_salt
        save_local_user_data(username, data)
    
    contacts = decrypt_contacts_data(encrypted_contacts, contacts_salt, passphrase)
    if contacts is None: # Decryption failed
        print("❌ Could not decrypt contacts. Check passphrase or data integrity. Logging out.")
        time.sleep(2)
        return None
    
    # Store decrypted contacts in memory for the session
    data["contacts"] = contacts
    # Not saving here, as it's just for session. Save only when contacts change (e.g., add_contact).

    print(f"🎉 Welcome back, {username}!")
    time.sleep(1)
    return username, privkey, passphrase # Passphrase needed for future decryption/re-encryption of contacts

def add_contact(username, passphrase):
    """Allows a user to add a new contact."""
    clear_screen()
    print("=== ➕ Add Contact ===")
    contact_username = input_with_prompt("Enter contact's username: ").strip()

    if contact_username == username:
        print("❌ You cannot add yourself as a contact.")
        time.sleep(2)
        return

    # Load and decrypt local data
    user_data = load_local_user_data(username)
    if not user_data:
        print("❌ Local user data not found. Please log in again.")
        time.sleep(2)
        return

    contacts = decrypt_contacts_data(user_data.get("encrypted_contacts"), user_data.get("contacts_salt"), passphrase)
    if contacts is None:
        print("❌ Failed to decrypt contacts data. Aborting add contact.")
        time.sleep(2)
        return

    if contact_username in contacts:
        print(f"ℹ️ Contact '{contact_username}' already exists in your list.")
        time.sleep(2)
        return

    # Fetch contact's public key from server
    try:
        resp = requests.get(f"{SERVER}/get_public_key/{contact_username}")
        resp.raise_for_status()
        contact_info = resp.json()
        contact_pubkey = contact_info["public_key"]
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the server to fetch contact's public key.")
        time.sleep(2)
        return
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"❌ Contact user '{contact_username}' not found on server. They might not be registered.")
        else:
            print(f"❌ Server error fetching contact's public key: {e.response.text}")
        time.sleep(2)
        return
    except Exception as e:
        print(f"❌ An unexpected error occurred fetching contact: {e}")
        time.sleep(2)
        return

    # Add contact to local contacts, re-encrypt, and save to local and server
    contacts[contact_username] = contact_pubkey
    encrypted_contacts, contacts_salt = encrypt_contacts_data(contacts, passphrase)
    
    user_data["encrypted_contacts"] = encrypted_contacts
    user_data["contacts_salt"] = contacts_salt
    save_local_user_data(username, user_data) # Update local copy

    # Also send updated encrypted contacts to the server
    try:
        # NOTE: Passphrase is still sent to the server for current cross-device login implementation.
        # This will be addressed in the next step for complete privacy.
        resp = requests.post(f"{SERVER}/register", json={ # Re-use register endpoint to update data on server
            "username": username,
            "public_key": user_data["public_key"], # Send existing public key
            "passphrase": passphrase, # WARNING: Plaintext passphrase
            "encrypted_privkey": user_data["encrypted_privkey"],
            "privkey_salt": user_data["privkey_salt"],
            "encrypted_contacts": encrypted_contacts, # Send updated encrypted contacts
            "contacts_salt": contacts_salt # Send updated contacts salt
        })
        resp.raise_for_status()
        print(f"✅ Contact '{contact_username}' added successfully and synced to server.")
    except requests.exceptions.ConnectionError:
        print("⚠️ Warning: Could not connect to server to sync contact list remotely. Contacts saved locally.")
    except requests.exceptions.HTTPError as e:
        print(f"⚠️ Warning: Server error syncing contact list remotely: {e.response.text}. Contacts saved locally.")
    except Exception as e:
        print(f"⚠️ Warning: An unexpected error occurred while syncing to server: {e}. Contacts saved locally.")
    time.sleep(2)

def list_contacts(username, passphrase):
    """Displays the current user's contact list."""
    clear_screen()
    print("=== 👥 Your Contacts ===")
    user_data = load_local_user_data(username)
    if not user_data:
        print("❌ Local user data not found. Please log in again.")
        wait_for_input()
        return

    contacts = decrypt_contacts_data(user_data.get("encrypted_contacts"), user_data.get("contacts_salt"), passphrase)
    if contacts is None:
        print("❌ Failed to decrypt contacts data. Cannot list contacts.")
        wait_for_input()
        return

    if not contacts:
        print("No contacts added yet. Add some to start chatting!")
    else:
        for c in sorted(contacts.keys()): # Sort for consistent display
            print(f"  - {c}")
    print("\n" + "="*50)
    wait_for_input()

def send_message(username, privkey, passphrase):
    """Allows a user to send an encrypted message to a contact."""
    clear_screen()
    user_data = load_local_user_data(username)
    contacts = decrypt_contacts_data(user_data.get("encrypted_contacts"), user_data.get("contacts_salt"), passphrase)
    
    if contacts is None:
        print("❌ Failed to decrypt contacts. Cannot send message.")
        time.sleep(2)
        return

    if not contacts:
        print("Please add contacts first to send messages.")
        time.sleep(2)
        return

    print("=== 💬 Send Message ===")
    options = sorted(list(contacts.keys())) # Sort contacts for consistent menu
    if not options:
        print("No contacts available to send messages to.")
        time.sleep(2)
        return

    idx = menu("Select contact to message:", options)
    recipient = options[idx]
    print(f"\n--- Chatting with {recipient} ---")
    print("Type your message and press Enter. Type '/exit' to return to main menu.")

    while True:
        try:
            msg = input(f"You ({username}) > ")
            if msg.strip().lower() == "/exit":
                break
            if not msg.strip():
                continue

            recipient_pub = PublicKey(b64decode(contacts[recipient]))
            box = Box(privkey, recipient_pub)
            encrypted = box.encrypt(msg.encode('utf-8'))
            ciphertext_b64 = b64encode(encrypted)

            timestamp = datetime.datetime.utcnow().isoformat() + "Z" # ISO 8601 with Z for UTC
            resp = requests.post(f"{SERVER}/send_message", json={
                "sender": username,
                "recipient": recipient,
                "ciphertext": ciphertext_b64,
                "timestamp": timestamp
            })
            resp.raise_for_status()
            print("Message sent.")
        except requests.exceptions.ConnectionError:
            print("❌ Error: Could not connect to the server. Message not sent.")
            break # Exit chat if server is down
        except requests.exceptions.HTTPError as e:
            print(f"❌ Server error sending message: {e.response.text}")
            # Consider if you want to break or let user retry
        except CryptoError as e:
            print(f"❌ Encryption error: {e}. Check keys or data.")
        except Exception as e:
            print(f"❌ An unexpected error occurred: {e}")
    print("\nReturning to main menu...")
    time.sleep(1)

def receive_messages(username, privkey, passphrase):
    """Retrieves and decrypts messages for the current user."""
    clear_screen()
    print("=== 📥 Receive Messages ===")
    print("Fetching messages from server...")
    try:
        resp = requests.get(f"{SERVER}/get_messages/{username}")
        resp.raise_for_status()
        messages = resp.json().get("messages", [])
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the server to fetch messages.")
        wait_for_input()
        return
    except requests.exceptions.HTTPError as e:
        print(f"❌ Server error fetching messages: {e.response.text}")
        wait_for_input()
        return
    except Exception as e:
        print(f"❌ An unexpected error occurred fetching messages: {e}")
        wait_for_input()
        return

    user_data = load_local_user_data(username)
    contacts = decrypt_contacts_data(user_data.get("encrypted_contacts"), user_data.get("contacts_salt"), passphrase)
    if contacts is None:
        print("❌ Failed to decrypt contacts. Cannot decrypt received messages.")
        wait_for_input()
        return

    print(f"\n--- Messages for {username} ---\n")
    if not messages:
        print("No new messages.")
    else:
        # Sort messages by timestamp for better readability
        messages.sort(key=lambda m: m["timestamp"])
        for msg in messages:
            sender = msg["sender"]
            ciphertext_b64 = msg["ciphertext"]
            timestamp = msg["timestamp"]

            print(f"[{timestamp}] From {sender}: ", end="")
            if sender not in contacts:
                print("⚠️ Cannot decrypt: Sender not in your contacts. Add them to decrypt.")
                continue

            try:
                # To decrypt messages sent *to* us, we need our private key and the sender's public key.
                # The sender's public key should be in our contacts list, as it's added during 'add_contact'.
                sender_pub = PublicKey(b64decode(contacts[sender]))
                # Create a Box with our private key and the sender's public key
                box = Box(privkey, sender_pub) 
                plaintext = box.decrypt(b64decode(ciphertext_b64)).decode('utf-8')
                print(f"✅ {plaintext}")
            except CryptoError:
                print("❌ Failed to decrypt message (possible incorrect key or corrupted message).")
            except Exception as e:
                print(f"❌ An error occurred during decryption: {e}")
            print("-" * 40) # Separator for messages

    wait_for_input()

def show_performance():
    """Displays local client system performance statistics."""
    import psutil
    clear_screen()
    print("=== 📊 Your System Performance ===\n")
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

def main_menu(username, privkey, passphrase):
    """Main menu for a logged-in user."""
    options = [
        "Add Contact",
        "List Contacts",
        "Send Message",
        "Receive Messages",
        "Show Performance",
        "Logout"
    ]
    while True:
        choice_idx = menu(f"Welcome, {username}! What would you like to do?", options)
        
        selected_option = options[choice_idx]

        if selected_option == "Add Contact":
            add_contact(username, passphrase)
        elif selected_option == "List Contacts":
            list_contacts(username, passphrase)
        elif selected_option == "Send Message":
            send_message(username, privkey, passphrase)
        elif selected_option == "Receive Messages":
            receive_messages(username, privkey, passphrase)
        elif selected_option == "Show Performance":
            show_performance()
        elif selected_option == "Logout":
            print("Logging out...")
            time.sleep(1)
            break

def main():
    """Entry point for the user application."""
    while True:
        clear_screen()
        choice_idx = menu("Welcome to Encrypted Messenger", ["Register", "Login", "Quit"])
        
        if choice_idx == 0: # Register
            result = register()
            if result:
                username, privkey, passphrase = result
                main_menu(username, privkey, passphrase)
        elif choice_idx == 1: # Login
            result = login()
            if result:
                username, privkey, passphrase = result
                main_menu(username, privkey, passphrase)
        elif choice_idx == 2: # Quit
            print("👋 Goodbye!")
            break

if __name__ == "__main__":
    main()