"""
app/api.py — REST API endpoints for WRAITH dashboard.

Endpoints:
    GET /logs — recent log entries (paginated)
    GET /logs/<int:log_id> - detailed log entry
    POST /classify — on-demand single request classification
    POST /demo/run — trigger full attack simulation sequence
    GET /stats — summary statistics for dashboard header

All routes registered on api_bp, mounted at root in __init__.py.
SSE stream lives in sse.py at /stream — not duplicated here.
"""

from datetime import datetime, timezone
from flask import Blueprint, jsonify, request
import config
from app.database import get_db_connection
from app.classifier import run_pipeline
from app.logger import persist_log

api_bp = Blueprint("api", __name__)


@api_bp.route("/logs", methods=["GET"])
def get_logs():
    requested_limit = request.args.get("limit", 50, type=int)
    limit = min(max(requested_limit, 1), config.API_MAX_LIMIT)
    since_id = request.args.get("since_id", 0, type=int)
    
    conn = None
    try:
        conn = get_db_connection(config.DATABASE_PATH)
        logs = conn.execute(
            "SELECT id, timestamp, ip_address, method, path, attack_type, threat_score, layer FROM logs WHERE id > ? AND is_simulation = 0 ORDER BY id DESC LIMIT ?", 
            (since_id, limit)
        ).fetchall()
        
        return jsonify({
            "status": "ok",
            "logs": [dict(row) for row in logs],
            "count": len(logs)
        }), 200
    except Exception as e:
        print(f"[WRAITH ERROR] /logs failed: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()

@api_bp.route("/logs/<int:log_id>", methods=["GET"])
def get_log_detail(log_id):
    conn = None
    try:
        conn = get_db_connection(config.DATABASE_PATH)
        log = conn.execute(
            "SELECT id, timestamp, ip_address, method, path, headers, payload, user_agent, attack_type, threat_score, confidence, layer, report FROM logs WHERE id = ?", 
            (log_id,)
        ).fetchone()
        
        if not log:
            return jsonify({"status": "error", "message": "Log not found"}), 404
            
        return jsonify({
            "status": "ok",
            "log": dict(log)
        }), 200
    except Exception as e:
        print(f"[WRAITH ERROR] /logs/<id> failed: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()

@api_bp.route("/classify", methods=["POST"])
def classify():
    request_data = request.get_json() or {}
    
    # Ensure all required keys exist to prevent ML feature extraction crashes
    request_data.setdefault("source_ip", "127.0.0.1")
    request_data.setdefault("path", "/")
    request_data.setdefault("query_string", "")
    request_data.setdefault("payload", "")
    # Default to POST if a payload is explicitly provided in the classification request
    default_method = "POST" if request_data["payload"] else "GET"
    request_data.setdefault("method", default_method)
    request_data.setdefault("user_agent", "")
    request_data.setdefault("headers", {})
    request_data.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))

    # skip_rules=True prevents polluting in-memory rate counters
    result = run_pipeline(request_data, skip_rules=True)
    persist_log(request_data, result)

    return jsonify({
        "status": "ok",
        **result
    }), 200

@api_bp.route("/demo/run", methods=["POST"])
def demo_run():
    if not config.ENABLE_DEMO:
        return jsonify({
            "status": "error",
            "message": "Demo simulation is disabled"
        }), 403

    import subprocess
    import sys
    import threading
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    script = project_root / "demo" / "simulate_attack.py"
    if not script.is_file():
        return jsonify({"status": "error", "message": "Demo script is missing"}), 500

    def _run():
        subprocess.run(
            [
                sys.executable,
                str(script),
                "--url",
                f"http://127.0.0.1:{config.FLASK_PORT}",
            ],
            cwd=str(project_root),
            check=False,
        )

    threading.Thread(target=_run, name="wraith-demo", daemon=True).start()
    return jsonify({
        "status": "ok",
        "message": "Simulation started against local honeypot routes"
    }), 202

@api_bp.route("/stats", methods=["GET"])
def get_stats():
    conn = None
    try:
        conn = get_db_connection(config.DATABASE_PATH)
        
        total_requests = conn.execute("SELECT COUNT(*) FROM logs WHERE is_simulation = 0").fetchone()[0] or 0
        total_attacks = conn.execute("SELECT COUNT(*) FROM logs WHERE attack_type != 'Normal' AND is_simulation = 0").fetchone()[0] or 0
        ml_hits = conn.execute("SELECT COUNT(*) FROM logs WHERE layer = 'ml' AND is_simulation = 0").fetchone()[0] or 0
        rule_hits = conn.execute("SELECT COUNT(*) FROM logs WHERE layer = 'rule' AND is_simulation = 0").fetchone()[0] or 0
        fallback_hits = conn.execute("SELECT COUNT(*) FROM logs WHERE layer = 'fallback' AND is_simulation = 0").fetchone()[0] or 0
        # Fix 4: ML won while the fallback ALSO fired with a different keyword
        # label (from the signals line in the report text). Rows where the
        # fallback stayed Normal don't count — there was nothing to override.
        ml_overrides = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE layer = 'ml' AND is_simulation = 0 "
            "AND report NOT LIKE '%fallback: Normal,%' "
            "AND report NOT LIKE '%fallback: ' || attack_type || ',%'"
        ).fetchone()[0] or 0
        
        attack_counts = conn.execute(
            "SELECT attack_type, COUNT(*) as count FROM logs WHERE attack_type != 'Normal' AND is_simulation = 0 GROUP BY attack_type"
        ).fetchall()
        
        attacks_by_type = {row["attack_type"]: row["count"] for row in attack_counts}
        
        # Threat level logic using rolling 5-minute window
        cursor = conn.execute(
            "SELECT MAX(threat_score) FROM logs WHERE timestamp > datetime('now', '-5 minutes') AND is_simulation = 0"
        )
        max_score = cursor.fetchone()[0] or 0

        if max_score >= config.THRESHOLD_ALERT:
            level = "Alert"
        elif max_score >= config.THRESHOLD_WARNING:
            level = "Warning"
        else:
            level = "Normal"
            
        return jsonify({
            "status": "ok",
            "stats": {
                "total_requests": total_requests,
                "total_attacks": total_attacks,
                "attacks_by_type": attacks_by_type,
                "current_threat_level": level,
                "max_score": max_score,
                "ml_hits": ml_hits,
                "ml_overrides": ml_overrides,
                "rule_hits": rule_hits,
                "fallback_hits": fallback_hits
            }
        }), 200
    except Exception as e:
        print(f"[WRAITH ERROR] /stats failed: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()