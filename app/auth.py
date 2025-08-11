from flask import Blueprint, request, jsonify
from .db import SessionLocal
from .models import User
from .utils import make_token

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username","").strip()
    public_key = data.get("public_key","").strip()
    if not username or len(username) < 3:
        return jsonify({"error":"invalid username"}), 400
    if not public_key or len(public_key) < 100:
        return jsonify({"error":"invalid public_key"}), 400

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username.ilike(username)).first()
        if existing:
            return jsonify({"error":"username exists"}), 409
        user = User(username=username, public_key=public_key)
        db.add(user)
        db.commit()
        token = make_token(user.id, user.role)
        return jsonify({"token": token, "user_id": user.id, "username": user.username}), 201
    finally:
        db.close()

@bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username","").strip()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username.ilike(username)).first()
        if not user:
            return jsonify({"error":"user not found"}), 404
        if user.disabled:
            return jsonify({"error":"account disabled"}), 403
        token = make_token(user.id, user.role)
        return jsonify({"token": token, "user_id": user.id, "username": user.username})
    finally:
        db.close()
