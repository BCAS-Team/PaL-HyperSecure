import os, time
from pathlib import Path
from .config import Config
from werkzeug.utils import secure_filename
import gzip
import shutil

UPLOAD_DIR = Path(Config.UPLOAD_FOLDER)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED = Config.ALLOWED_EXTENSIONS

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED

def save_and_compress(file_storage, max_size_bytes):
    filename = secure_filename(file_storage.filename) or f"upload-{int(time.time())}"
    temp_path = UPLOAD_DIR / filename
    file_storage.save(temp_path)
    if temp_path.stat().st_size > max_size_bytes:
        temp_path.unlink(missing_ok=True)
        raise ValueError("File too large")
    gz_path = UPLOAD_DIR / f"{filename}.gz"
    with open(temp_path, 'rb') as f_in, gzip.open(gz_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    temp_path.unlink(missing_ok=True)
    return str(gz_path)
