import os
import uvicorn
import json
from typing import List
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean, Enum
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from jose import JWTError, jwt
import psycopg2

# Database Configuration for Railway
# Use a default URL for local development if the environment variable isn't set.
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost/paL_hypersecure")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    public_key = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    encrypted_content = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

# Enum to define friendship status
class FriendshipStatus(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"

class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    friend_id = Column(Integer, ForeignKey("users.id"))
    
    # FIX: The Enum constructor requires a list of string literals.
    status = Column(Enum("pending", "accepted", name="friendship_status"), default="pending")
    
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships to enable easy access to user and friend details
    user = relationship("User", foreign_keys=[user_id])
    friend = relationship("User", foreign_keys=[friend_id])

# Security and App Setup
app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = os.environ.get("SECRET_KEY", "your-super-secret-key")
ALGORITHM = "HS256"

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Helper functions for password handling
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

@app.post("/register")
def register_user(request: Request, db: Session = Depends(get_db)):
    try:
        user_data = json.loads(request.body.decode())
        username = user_data["username"]
        password = user_data["password"]
        public_key = user_data["public_key"]
    except (KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid request payload")

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already exists")

    hashed_password = get_password_hash(password)
    db_user = User(username=username, hashed_password=hashed_password, public_key=public_key)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/{username}/public-key")
def get_public_key(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"public_key": user.public_key}

@app.post("/messages/send")
def send_message(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        message_data = json.loads(request.body.decode())
        recipient_username = message_data["recipient_username"]
        encrypted_content = message_data["encrypted_content"]
    except (KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid request payload")

    recipient = db.query(User).filter(User.username == recipient_username).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    new_message = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        encrypted_content=encrypted_content,
        is_read=False
    )
    db.add(new_message)
    db.commit()
    return {"message": "Message sent successfully"}

@app.get("/messages/inbox")
def get_inbox(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    messages = db.query(Message).filter(Message.recipient_id == current_user.id).all()
    inbox = [{"sender_id": msg.sender_id, "encrypted_content": msg.encrypted_content, "timestamp": msg.timestamp} for msg in messages]
    return inbox

@app.post("/friends/add")
def add_friend(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        friend_data = json.loads(request.body.decode())
        friend_username = friend_data["friend_username"]
    except (KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid request payload")

    friend = db.query(User).filter(User.username == friend_username).first()
    if not friend:
        raise HTTPException(status_code=404, detail="User not found")
    
    if current_user.id == friend.id:
        raise HTTPException(status_code=400, detail="Cannot add yourself as a friend")

    existing_request = db.query(Friendship).filter(Friendship.user_id == current_user.id, Friendship.friend_id == friend.id).first()
    if existing_request:
        raise HTTPException(status_code=409, detail="Friend request already sent")

    new_request = Friendship(user_id=current_user.id, friend_id=friend.id, status=FriendshipStatus.PENDING)
    db.add(new_request)
    db.commit()
    return {"message": "Friend request sent"}

@app.get("/friends/requests")
def get_friend_requests(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    requests = db.query(Friendship).filter(Friendship.friend_id == current_user.id, Friendship.status == FriendshipStatus.PENDING).all()
    request_senders = [{"id": req.user.id, "username": req.user.username} for req in requests]
    return request_senders

@app.post("/friends/accept/{friend_id}")
def accept_friend_request(friend_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    request = db.query(Friendship).filter(Friendship.user_id == friend_id, Friendship.friend_id == current_user.id, Friendship.status == FriendshipStatus.PENDING).first()
    if not request:
        raise HTTPException(status_code=404, detail="Friend request not found")

    request.status = FriendshipStatus.ACCEPTED
    
    # Create the reciprocal friendship entry
    reciprocal_request = Friendship(user_id=current_user.id, friend_id=friend_id, status=FriendshipStatus.ACCEPTED)
    db.add(reciprocal_request)
    
    db.commit()
    return {"message": "Friend request accepted"}

@app.get("/friends/list")
def get_friends_list(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    accepted_friends = db.query(Friendship).filter(Friendship.user_id == current_user.id, Friendship.status == FriendshipStatus.ACCEPTED).all()
    friends_list = [{"id": f.friend.id, "username": f.friend.username} for f in accepted_friends]
    return friends_list
    
def create_db_and_tables():
    try:
        print("Attempting to connect to the database and create tables...")
        Base.metadata.create_all(bind=engine)
        print("Database tables created successfully.")
    except psycopg2.OperationalError as e:
        print("Failed to connect to the database!")
        print("Please ensure the DATABASE_URL environment variable is set correctly.")
        print(f"Error details: {e}")
        # Re-raise the exception to stop the application startup if the DB isn't available
        raise e

if __name__ == "__main__":
    create_db_and_tables()
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
