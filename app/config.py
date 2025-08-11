import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or "dev-secret-change-in-prod"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'data' / 'pal.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER") or str(BASE_DIR / "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))
    JWT_ALGORITHM = "HS256"
    TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", 24))
    ALLOWED_EXTENSIONS = set(os.getenv("ALLOWED_EXTENSIONS", "txt,pdf,png,jpg,jpeg,gif,mp3,mp4").split(","))
