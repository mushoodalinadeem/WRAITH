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
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

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

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({"error": "Payload too large", "status": 413}), 413

    # -----------------------------------------------------------------------
    # Database & Logger Initialization
    # -----------------------------------------------------------------------
    from app.database import init_db
    init_db(app.config["DATABASE_PATH"])

    # Start the background worker thread that processes the async queue
    from app.logger import start_background_worker
    start_background_worker()

    # -----------------------------------------------------------------------
    # Blueprints
    # -----------------------------------------------------------------------
    from app.api import api_bp
    # No prefix needed; proposal dictates /logs, /classify, /stream directly
    app.register_blueprint(api_bp)
    
    from app.admin import admin_bp
    # CHANGED: Avoids collision with honeypot's /admin/login decoy
    app.register_blueprint(admin_bp, url_prefix="/dashboard")

    from app.sse import sse_bp
    app.register_blueprint(sse_bp)

    from app.honeypot import honeypot_bp
    # MUST BE REGISTERED LAST so its catch_all doesn't shadow the above blueprints
    app.register_blueprint(honeypot_bp)

    return app