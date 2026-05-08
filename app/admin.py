"""
app/admin.py — Admin dashboard blueprint for WRAITH.

Serves the forensic monitoring dashboard at /dashboard/.
The dashboard HTML/JS calls these API endpoints (defined in api.py and sse.py):
    - GET  /stream  (SSE live feed)
    - GET  /logs    (REST historical logs)
    - GET  /stats   (summary statistics)
    - POST /classify (on-demand classification)

Registered in __init__.py with url_prefix="/dashboard".
"""

import os
from flask import Blueprint, send_from_directory, jsonify

admin_bp = Blueprint("admin", __name__)

# Absolute path to dashboard directory — avoids relative path issues
_DASHBOARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dashboard"
)

if not os.path.isdir(_DASHBOARD_DIR):
    print(f"[WRAITH WARNING] Dashboard directory not found: {_DASHBOARD_DIR}")


@admin_bp.route("/", strict_slashes=False)
def dashboard():
    """
    Serve the main forensic dashboard page.

    Access at: http://localhost:5000/dashboard/
    """
    return send_from_directory(_DASHBOARD_DIR, "index.html")


@admin_bp.route("/health", strict_slashes=False)
def health():
    """
    Simple health check endpoint.
    Confirms the admin blueprint is registered and reachable.
    """
    return jsonify({"status": "ok", "blueprint": "admin"}), 200


@admin_bp.route("/<path:filename>")
def dashboard_static(filename):
    """
    Serve any static assets from the dashboard directory.
    Supports CSS, JS, images, fonts, etc.

    This catch-all ensures the dashboard can load additional
    assets without needing Flask's static folder system.
    """
    # Prevent path traversal — critical for a security-focused project
    if ".." in filename:
        return jsonify({"error": "Forbidden"}), 403
    return send_from_directory(_DASHBOARD_DIR, filename)
