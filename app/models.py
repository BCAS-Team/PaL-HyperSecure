import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, Text
from datetime import datetime
from .db import Base

def gen_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    username = Column(String(128), unique=True, nullable=False)
    public_key = Column(Text, nullable=False)
    role = Column(String(32), default="user")
    disabled = Column(Boolean, default=False)
    created_at = Column(Float, default=lambda: datetime.utcnow().timestamp())

class Message(Base):
    __tablename__ = "messages"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    recipient_id = Column(String(36), nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)
    created_at = Column(Float, default=lambda: datetime.utcnow().timestamp())
    read = Column(Boolean, default=False)
    ttl_days = Column(Integer, nullable=True)
    sender_tag = Column(String(128), nullable=True)

class Friend(Base):
    __tablename__ = "friends"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    owner_id = Column(String(36), nullable=False, index=True)
    friend_id = Column(String(36), nullable=False, index=True)
