#!/usr/bin/env python3
"""
Simple CLI client with basic RSA helpers (generate keypair, register public key,
encrypt message to recipient's public key, send ciphertext, fetch inbox and decrypt).
"""

import argparse, os, json, requests, base64, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives import serialization

SERVER = os.getenv("SERVER_URL", "http://localhost:5000")
DATA_DIR = Path.home() / ".palcli"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PRIVATE_KEY_PATH = DATA_DIR / "private_key.pem"
PUBLIC_KEY_PATH = DATA_DIR / "public_key.pem"
TOKEN_PATH = DATA_DIR / "token.json"

def save_token(token, user_id, username):
    TOKEN_PATH.write_text(json.dumps({"token": token, "user_id": user_id, "username": username}))

def load_token():
    if not TOKEN_PATH.exists(): return None
    return json.loads(TOKEN_PATH.read_text())

def generate_keys(passphrase: str = None):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if passphrase:
        pem_priv = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=BestAvailableEncryption(passphrase.encode())
        )
    else:
        pem_priv = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
    pem_pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    PRIVATE_KEY_PATH.write_bytes(pem_priv)
    PUBLIC_KEY_PATH.write_bytes(pem_pub)
    print("Saved private key to", PRIVATE_KEY_PATH)
    print("Saved public key to", PUBLIC_KEY_PATH)

def load_private_key(passphrase: str = None):
    if not PRIVATE_KEY_PATH.exists():
        return None
    data = PRIVATE_KEY_PATH.read_bytes()
    try:
        if passphrase:
            priv = serialization.load_pem_private_key(data, password=passphrase.encode())
        else:
            priv = serialization.load_pem_private_key(data, password=None)
        return priv
    except Exception as e:
        print("Failed to load private key:", e)
        return None

def register(username):
    if not PUBLIC_KEY_PATH.exists():
        print("Public key missing. Run `generate-keys` first.")
        return
    pub = PUBLIC_KEY_PATH.read_text()
    r = requests.post(f"{SERVER}/auth/register", json={"username": username, "public_key": pub})
    print("Status:", r.status_code, r.text)
    if r.status_code == 201:
        j = r.json()
        save_token(j["token"], j["user_id"], j["username"])
        print("Registered and saved token.")

def login(username):
    r = requests.post(f"{SERVER}/auth/login", json={"username": username})
    print("Status:", r.status_code, r.text)
    if r.status_code == 200:
        j = r.json()
        save_token(j["token"], j["user_id"], j["username"])
        print("Logged in and saved token.")

def encrypt_for_recipient_pubkey(recipient_pub_pem: str, message: str) -> str:
    pub = serialization.load_pem_public_key(recipient_pub_pem.encode())
    ct = pub.encrypt(message.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(ct).decode()

def decrypt_ciphertext(cipher_b64: str, passphrase: str = None) -> str:
    priv = load_private_key(passphrase)
    if not priv:
        return None
    ct = base64.b64decode(cipher_b64)
    pt = priv.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt.decode()

def fetch_user_public_key(username_or_id: str):
    # No direct endpoint; instead attempt to call /admin/users if you have admin token is not ideal.
    # For simplicity, we will call /auth/login to check user existence and then fetch all users if admin.
    # Better: add API endpoint to fetch public key by username (server-side). For now attempt /admin/users (if token role admin)
    tok = load_token()
    headers = {}
    if tok:
        headers["Authorization"] = f"Bearer {tok['token']}"
    # Try a naive approach: fetch /admin/users (if admin)
    r = requests.get(f"{SERVER}/admin/users", headers=headers)
    if r.status_code == 200:
        for u in r.json().get("users", []):
            if u["username"].lower() == username_or_id.lower() or u["id"] == username_or_id:
                # need to fetch user public_key from DB - but admin endpoint doesn't return pubkey currently to avoid leakage
                print("Admin cannot fetch public key via this client. Please ask recipient to share public key or implement a /user/pubkey endpoint on server.")
                return None
    # If not admin/available, instruct user to obtain recipient public key out-of-band
    print("Please obtain recipient public key PEM file out-of-band and use --pubkeyfile option.")
    return None

def send(recipient, ciphertext_b64, sender_tag=None):
    tok = load_token()
    if not tok:
        print("Not logged in")
        return
    headers = {"Authorization": f"Bearer {tok['token']}"}
    payload = {"recipient": recipient, "ciphertext": ciphertext_b64}
    if sender_tag:
        payload["sender_tag"] = sender_tag
    r = requests.post(f"{SERVER}/messages/send", json=payload, headers=headers)
    print("Status:", r.status_code, r.text)

def inbox(passphrase=None):
    tok = load_token()
    if not tok:
        print("Not logged in")
        return
    headers = {"Authorization": f"Bearer {tok['token']}"}
    r = requests.get(f"{SERVER}/messages/inbox", headers=headers)
    if r.status_code != 200:
        print("Failed to fetch inbox:", r.status_code, r.text)
        return
    j = r.json()
    msgs = j.get("messages", [])
    for m in msgs:
        print("----")
        print("Message ID:", m["id"])
        print("From tag:", m.get("sender_tag"))
        print("Created:", m.get("created_at"))
        try:
            pt = decrypt_ciphertext(m["ciphertext"], passphrase)
            print("Decrypted:", pt)
        except Exception as e:
            print("Decryption failed. Save ciphertext to file to decrypt later.")
            print("Ciphertext:", m["ciphertext"][:120], "...")
    print("---- End inbox ----")

def mark_all_read():
    tok = load_token()
    if not tok:
        print("Not logged in")
        return
    headers = {"Authorization": f"Bearer {tok['token']}"}
    r = requests.post(f"{SERVER}/messages/mark-read", json={}, headers=headers)
    print(r.status_code, r.text)

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("generate-keys")
    p = sub.add_parser("register"); p.add_argument("username")
    p = sub.add_parser("login"); p.add_argument("username")
    p = sub.add_parser("send"); p.add_argument("recipient"); p.add_argument("pubkeyfile", nargs="?"); p.add_argument("--message", "-m", help="message text"); p.add_argument("--sender-tag", help="optional opaque tag")
    sub.add_parser("inbox").add_argument("--passphrase", "-p", required=False)
    sub.add_parser("mark-all-read")
    args = parser.parse_args()

    if args.cmd == "generate-keys":
        generate_keys()
    elif args.cmd == "register":
        register(args.username)
    elif args.cmd == "login":
        login(args.username)
    elif args.cmd == "send":
        if not args.pubkeyfile:
            print("You must supply recipient public key file path (recipient shares their public key PEM out-of-band).")
            sys.exit(1)
        pubpem = open(args.pubkeyfile).read()
        message = args.message or input("Message: ")
        ct = encrypt_for_recipient_pubkey(pubpem, message)
        send(args.recipient, ct, sender_tag=args.sender_tag)
    elif args.cmd == "inbox":
        inbox(args.passphrase)
    elif args.cmd == "mark-all-read":
        mark_all_read()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
