from flask import Blueprint, request, jsonify, g
from .db import SessionLocal
from .utils import token_required, admin_required
from .models import User, Message
from datetime import datetime

bp = Blueprint("admin", __name__, url_prefix="/admin")

@bp.route("/users", methods=["GET"])
@token_required
@admin_required
def list_users():
    db = SessionLocal()
    try:
        users = db.query(User).all()
        out = []
        for u in users:
            out.append({
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "disabled": u.disabled,
                "created_at": u.created_at
            })
        return jsonify({"users": out})
    finally:
        db.close()

@bp.route("/users/<user_id>/disable", methods=["POST"])
@token_required
@admin_required
def disable_user(user_id):
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == user_id).first()
        if not u:
            return jsonify({"error":"not found"}), 404
        u.disabled = True
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()

@bp.route("/messages/cleanup", methods=["POST"])
@token_required
@admin_required
def cleanup_messages():
    data = request.get_json() or {}
    older_than_days = int(data.get("older_than_days", 30))
    cutoff = datetime.utcnow().timestamp() - older_than_days * 86400
    db = SessionLocal()
    try:
        q = db.query(Message).filter(Message.created_at < cutoff)
        count = q.count()
        q.delete(synchronize_session=False)
        db.commit()
        return jsonify({"deleted": count})
    finally:
        db.close()
