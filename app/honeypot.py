"""
app/honeypot.py — 9 fake vulnerable HTTP endpoints for WRAITH honeypot.

Every endpoint:
    1. Extracts request data (IP, method, path, headers, payload, user-agent)
    2. Calls log_request() — drops into bounded queue, returns immediately
    3. Returns a fake realistic JSON response — maintains deception

The attacker sees a real API. WRAITH logs and classifies everything silently.
"""

from flask import Blueprint, request, jsonify
from app.logger import log_request

honeypot_bp = Blueprint("honeypot", __name__)

@honeypot_bp.after_request
def add_deceptive_headers(response):
    """
    Adds deceptive headers to make the honeypot look like a Node.js backend.
    """
    response.headers["X-Powered-By"] = "Express"
    return response

def _extract_request_data() -> dict:
    """
    Extract all relevant fields from the current Flask request object.
    Returns a plain dict ready for log_request() and the classifier pipeline.
    """
    return {
        "source_ip": request.remote_addr or "0.0.0.0",
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode('utf-8', errors='ignore'),
        "headers": dict(request.headers),
        "payload": request.get_data(as_text=True),
        "user_agent": request.headers.get("User-Agent", "")
    }

# strict_slashes=False so POSTs to /admin/login/ (trailing slash) are handled
# here instead of being 308-redirected — otherwise they never reach the
# logging pipeline and the brute-force counter never sees them.
@honeypot_bp.route("/admin/login", methods=["GET", "POST"], strict_slashes=False)
def admin_login():
    data = _extract_request_data()
    log_request(data)
    if request.method == "POST":
        return jsonify({
            "status": "error",
            "message": "Invalid credentials"
        }), 401
    return jsonify({
        "status": "ok",
        "message": "Admin login portal",
        "version": "2.4.1"
    }), 200

@honeypot_bp.route("/api/users", methods=["GET", "POST"])
def api_users():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "users":[
            {"id": 1, "username": "admin", "role": "superuser"},
            {"id": 2, "username": "dbuser", "role": "readonly"}
        ],
        "total": 2
    }), 200

@honeypot_bp.route("/config/database", methods=["GET", "POST"])
def config_database():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "host": "db.internal",
        "port": 5432,
        "name": "production_db",
        "ssl": True
    }), 200

@honeypot_bp.route("/backup", methods=["GET", "POST"])
def backup():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "last_backup": "2026-05-01T03:00:00Z",
        "size_mb": 2048,
        "location": "/var/backups/prod"
    }), 200

@honeypot_bp.route("/api/orders", methods=["GET","POST"])
def api_orders():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "orders": [
            {"id": 1001, "amount": 250.00,"status": "shipped"},
            {"id": 1002, "amount": 89.99, "status": "pending"}
        ],
        "total": 2
    }), 200

@honeypot_bp.route("/api/payments", methods=["GET", "POST"])
def api_payments():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "gateway": "stripe",
        "last_transaction": "txn_3Nt8Xy2eZvKYlo2C",
        "currency": "USD"
    }), 200

@honeypot_bp.route("/api/admin/export", methods=["GET", "POST"])
def admin_export():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "export_url": "/var/exports/users_2026.csv",
        "rows": 15842
    }), 200

@honeypot_bp.route("/api/logs", methods=["GET"])
def honeypot_logs():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "logs": [
            {"timestamp": "2026-05-01T10:00:00Z",
            "event": "login_success", "user": "admin"},
            {"timestamp": "2026-05-01T09:58:00Z",
            "event": "config_change", "user": "system"}
        ]
    }), 200

@honeypot_bp.route("/api/search", methods=["GET", "POST"])
def api_search():
    data = _extract_request_data()
    log_request(data)
    return jsonify({
        "status": "ok",
        "query": "[Redacted for security]",
        "results": [],
        "total": 0
    }), 200

@honeypot_bp.route("/", defaults={"unknown_path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@honeypot_bp.route("/<path:unknown_path>",
                    methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(unknown_path):
    data = _extract_request_data()
    # Single source of truth for "unknown path": the router landed here, so no
    # registered route matched. Used by the enumeration rule in logger.py.
    data["is_catchall"] = True
    log_request(data)
    return jsonify({
        "status": "error",
        "message": "Resource not found",
        "path": f"/{unknown_path}"
    }), 404