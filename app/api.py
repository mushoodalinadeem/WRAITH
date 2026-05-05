"""
app/api.py — REST API and real-time SSE stream for the WRAITH dashboard.

Responsibilities:
    - Serve historical forensic logs to the frontend via /logs.
    - Provide a real-time Server-Sent Events (SSE) stream via /stream.
    - Expose a manual /classify endpoint for demo purposes.
"""

import json
import time
from flask import Blueprint, jsonify, request, Response

import config
from app.database import get_db_connection

api_bp = Blueprint('api', __name__)

# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------
@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """
    Fetch historical logs for the dashboard.
    Defaults to the last 100 events to prevent massive payload sizes.
    """
    limit = request.args.get('limit', 100, type=int)
    
    conn = None
    try:
        conn = get_db_connection(config.DATABASE_PATH)
        # Fetch descending so the newest logs are at the top
        logs = conn.execute(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ?", 
            (limit,)
        ).fetchall()
        
        # Convert sqlite3.Row objects to standard dictionaries for JSON serialization
        return jsonify([dict(row) for row in logs]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@api_bp.route('/classify', methods=['POST'])
def manual_classify():
    """
    Manual classification endpoint for Demo Step 5.
    Allows testing payloads directly against the pipeline.
    """
    data = request.get_json() or {}
    
    # We drop it into the logger queue just like a real request, 
    # but we spoof the source IP so we know it was a manual test.
    test_request = {
        "source_ip": data.get("ip", "127.0.0.1 (Manual Test)"),
        "method": data.get("method", "POST"),
        "path": data.get("path", "/api/test"),
        "headers": data.get("headers", {}),
        "payload": data.get("payload", ""),
        "user_agent": "WRAITH Manual Tester"
    }
    
    from app.logger import log_request
    log_request(test_request)
    
    return jsonify({"status": "queued", "message": "Test payload sent to WRAITH engine."}), 202


