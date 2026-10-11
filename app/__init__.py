"""
app/__init__.py — Flask application factory for WRAITH

Creates and configures the Flask app instance, registers blueprints,
applies ProxyFix middleware for correct IP detection behind Docker,
and ensures required directories exist before the app starts.
"""
import logging
import os
from datetime import timedelta

from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

import config


def create_app():
    """
    Application factory. Call this to get a fully configured Flask app.
    Used by main.py to start the server.
    """
    config.validate_runtime_config()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    app = Flask(__name__)

    app.config["SECRET_KEY"] = config.FLASK_SECRET_KEY
    app.config["DEBUG"] = config.FLASK_DEBUG
    app.config["DATABASE_PATH"] = config.DATABASE_PATH
    app.config["MODEL_PATH"] = config.MODEL_PATH
    app.config["QUEUE_MAXSIZE"] = config.QUEUE_MAXSIZE
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    app.config["SESSION_COOKIE_NAME"] = "wraith_session"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=config.SESSION_HOURS)
    app.config["SESSION_REFRESH_EACH_REQUEST"] = True

    db_dir = os.path.dirname(config.DATABASE_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1
    )

    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = response.headers.get(
            "Cache-Control", "no-store"
        )
        if request.path.startswith("/dashboard"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; "
                "img-src 'self' data:; "
                "connect-src 'self'"
            )
        return response

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found", "status": 404}), 404

    @app.errorhandler(500)
    def internal_error(e):
        logging.exception("Unhandled server error")
        return jsonify({"error": "Internal server error", "status": 500}), 500

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({"error": "Payload too large", "status": 413}), 413

    from app.database import init_db
    init_db(app.config["DATABASE_PATH"])

    from app.classifier import load_model
    load_model()

    from app.logger import start_background_worker
    start_background_worker()

    @app.route("/healthz", methods=["GET"])
    def healthz():
        return jsonify({"status": "ok"}), 200

    from app.auth import enforce_operator_auth
    from app.api import api_bp
    api_bp.before_request(enforce_operator_auth)
    app.register_blueprint(api_bp)

    from app.admin import admin_bp
    admin_bp.before_request(enforce_operator_auth)
    app.register_blueprint(admin_bp, url_prefix="/dashboard")

    from app.sse import sse_bp
    sse_bp.before_request(enforce_operator_auth)
    app.register_blueprint(sse_bp)

    from app.honeypot import honeypot_bp
    app.register_blueprint(honeypot_bp)

    return app
