"""
app/__init__.py — Flask application factory for WRAITH

Creates and configures the Flask app instance, registers blueprints,
applies ProxyFix middleware for correct IP detection behind Docker,
and ensures required directories exist before the app starts.
"""
import os
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
import config


def create_app():
    """
    Application factory. Call this to get a fully configured Flask app.
    Used by main.py to start the server.
    """
    app = Flask(__name__)

    app.config["SECRET_KEY"] = config.FLASK_SECRET_KEY
    app.config["DEBUG"] = config.FLASK_DEBUG
    app.config["DATABASE_PATH"] = config.DATABASE_PATH
    app.config["MODEL_PATH"] = config.MODEL_PATH
    app.config["QUEUE_MAXSIZE"] = config.QUEUE_MAXSIZE

    db_dir = os.path.dirname(config.DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # Trust X-Forwarded-* headers from Docker/Reverse Proxies
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1
    )

    # -----------------------------------------------------------------------
    # JSON Error Handlers (Maintains API persona deception)
    # -----------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found", "status": 404}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error", "status": 500}), 500

    # -----------------------------------------------------------------------
    # Database & Logger Initialization
    # -----------------------------------------------------------------------
    try:
        from app.database import init_db
        init_db(app.config["DATABASE_PATH"])
    except ImportError as e:
        print(f"[WRAITH WARNING] Could not import database: {e}")

    try:
        # Start the background worker thread that processes the async queue
        from app.logger import start_background_worker
        start_background_worker()
    except ImportError as e:
        print(f"[WRAITH WARNING] Could not import logger: {e}")

    # -----------------------------------------------------------------------
    # Blueprints
    # -----------------------------------------------------------------------
    try:
        from app.honeypot import honeypot_bp
        app.register_blueprint(honeypot_bp)
    except ImportError as e:
        print(f"[WRAITH WARNING] Could not import honeypot blueprint: {e}") 

    try:
        from app.api import api_bp
        # No prefix needed; proposal dictates /logs, /classify, /stream directly
        app.register_blueprint(api_bp)
    except ImportError as e:
        print(f"[WRAITH WARNING] Could not import api blueprint: {e}") 
    
    try:
        from app.admin import admin_bp
        # CHANGED: Avoids collision with honeypot's /admin/login decoy
        app.register_blueprint(admin_bp, url_prefix="/dashboard")
    except ImportError as e:
        print(f"[WRAITH WARNING] Could not import admin blueprint: {e}") 

    return app