"""
app/sse.py — Server-Sent Events stream for WRAITH live dashboard.

Responsibilities:
    - get_logs_since(last_id) — fetch only new rows from logs table (delta update)
    - _event_stream() — generator that polls DB and yields SSE events
    - stream() — Flask route at /stream, keeps connection open forever

Dashboard JS connects with:
    const source = new EventSource('/stream');
    source.onmessage = (e) => { const log = JSON.parse(e.data); ...}
"""

import json
import time
import sqlite3
import traceback
from flask import Blueprint, Response, current_app, request
import config
from app.database import get_db_connection

sse_bp = Blueprint("sse", __name__)

def get_logs_since(last_id: int, db_path: str) -> list:
    """
    Fetch all log rows with id > last_id.
    Called by the SSE generator on every poll cycle.

    Args:
        last_id: The highest log id the browser has already received
        db_path: Path to the SQLite database file

    Returns:
        List of dicts — one per new log row, ordered by id ASC
        Empty list if no new rows or on database error
    """
    conn = None
    try:
        conn = get_db_connection(db_path)
        cursor = conn.execute(
            """
            SELECT id, timestamp, ip_address, method, path,
                   headers, payload, user_agent, attack_type, 
                   threat_score, confidence, layer, report
            FROM logs
            WHERE id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (last_id, config.SSE_BATCH_LIMIT)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        print(f"[WRAITH ERROR] DB error in get_logs_since: {e}")
        return []
    except Exception as e:
        print(f"[WRAITH ERROR] Unexpected error: {e}")
        traceback.print_exc()
        return []
    finally:
        if conn:
            conn.close()

def _format_sse(data: dict, event_id: int) -> str:
    """
    Format a single dict as an SSE event string.

    SSE protocol format (required by browser EventSource API):
        id: <event_id>
        data: <json string>\n\n

    The double newline signals end of one event to the browser.
    """
    return f"id: {event_id}\ndata: {json.dumps(data)}\n\n"

def _event_stream(db_path: str, start_id: int = 0):
    """
    Generator that yields SSE events forever.
    Starts at start_id so first poll delivers all existing rows to the
    dashboard on page load, then delivers only new rows on every poll.

    Poll interval: config.SSE_RETRY_MS milliseconds (default 2000ms = 2s)
    Heartbeat: sent every cycle to keep connection alive through proxies
    """
    last_id = start_id

    while True:
        try:
            new_rows = get_logs_since(last_id, db_path)

            for row in new_rows:
                last_id = row["id"]
                yield _format_sse(row, last_id)
        except GeneratorExit:
            # Client disconnected cleanly, break the infinite loop
            break
        except Exception as e:
            print(f"[WRAITH ERROR] SSE generator error: {e}")

        
        yield ": heartbeat\n\n"

        time.sleep(config.SSE_RETRY_MS / 1000)

@sse_bp.route("/stream")
def stream():
    """
    SSE endpoint consumed by dashboard JavaScript.

    Connect from JS:
        const source = new EventSource('/stream');
        source.onmessage = (e) => {
            const log = JSON.parse(e.data);
            // log.attack_type, log.threat_score, log.ip_address etc.
        };

    Returns a streaming Response — connection stays open indefinitely.
    """
    db_path = current_app.config["DATABASE_PATH"]
    last_event_id = request.headers.get("Last-Event-ID", "0")
    try:
        last_event_id = int(last_event_id)
    except (ValueError, TypeError):
        last_event_id = 0

    return Response(
        _event_stream(db_path, last_event_id),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive"
        }
    )