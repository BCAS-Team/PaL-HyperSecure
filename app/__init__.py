from flask import Flask, jsonify
from .config import Config
from .db import init_db
from .auth import bp as auth_bp
from .messages import bp as msg_bp
from .admin import bp as admin_bp
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()

    app.register_blueprint(auth_bp)
    app.register_blueprint(msg_bp)
    app.register_blueprint(admin_bp)

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error":"file too large"}), 413

    @app.route("/")
    def index():
        return jsonify({"service":"PaL-HyperSecure","status":"running"})

    return app

if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=(os.getenv("DEBUG","")=="1"))
