"""
main.py — Entry point for the WRAITH Honeypot.

Bootstraps the Flask application using the factory pattern.
"""

from app import create_app
import config

app = create_app()

if __name__ == "__main__":
    print("[WRAITH] Booting server on http://0.0.0.0:5000...")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=config.FLASK_DEBUG,
        use_reloader=False
    )
