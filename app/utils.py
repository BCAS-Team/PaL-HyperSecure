import jwt, functools
from flask import request, jsonify, g
from .config import Config
from datetime import datetime, timedelta

SECRET = Config.SECRET_KEY

def make_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=Config.TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET, algorithm=Config.JWT_ALGORITHM)

def verify_token(token):
    try:
        data = jwt.decode(token, SECRET, algorithms=[Config.JWT_ALGORITHM])
        return data
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None

def token_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization","")
        if auth.startswith("Bearer "):
            token = auth.split(" ",1)[1]
        else:
            return jsonify({"error": "Token required"}), 401
        data = verify_token(token)
        if not data:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.user_id = data["user_id"]
        g.role = data.get("role","user")
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if getattr(g, "role", None) != "admin":
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return wrapper
