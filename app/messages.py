from flask import Blueprint, request, jsonify, g
from .db import SessionLocal
from .models import Message, User
from .utils import token_required

bp = Blueprint("messages", __name__, url_prefix="/messages")

@bp.route("/send", methods=["POST"])
@token_required
def send_message():
    j = request.get_json() or {}
    recipient = j.get("recipient") or j.get("recipient_id")
    ciphertext = j.get("ciphertext")
    sender_tag = j.get("sender_tag")
    if not recipient or not ciphertext:
        return jsonify({"error":"recipient and ciphertext required"}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter((User.username.ilike(recipient)) | (User.id == recipient)).first()
        if not user:
            return jsonify({"error":"recipient not found"}), 404
        msg = Message(recipient_id=user.id, ciphertext=ciphertext, sender_tag=sender_tag)
        db.add(msg)
        db.commit()
        return jsonify({"message":"sent","message_id":msg.id}), 201
    finally:
        db.close()

@bp.route("/inbox", methods=["GET"])
@token_required
def inbox():
    db = SessionLocal()
    try:
        msgs = db.query(Message).filter(Message.recipient_id == g.user_id).order_by(Message.created_at.desc()).all()
        out = []
        for m in msgs:
            out.append({
                "id": m.id,
                "ciphertext": m.ciphertext,
                "created_at": m.created_at,
                "read": m.read,
                "sender_tag": m.sender_tag
            })
        return jsonify({"messages": out})
    finally:
        db.close()

@bp.route("/mark-read", methods=["POST"])
@token_required
def mark_read():
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        ids = data.get("message_ids") or []
        if not ids:
            db.query(Message).filter(Message.recipient_id == g.user_id, Message.read == False).update({"read": True})
            db.commit()
            return jsonify({"marked":"all"})
        else:
            db.query(Message).filter(Message.recipient_id == g.user_id, Message.id.in_(ids)).update({"read": True}, synchronize_session=False)
            db.commit()
            return jsonify({"marked": len(ids)})
    finally:
        db.close()
