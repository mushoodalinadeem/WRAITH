"""
app/logger.py — Async bounded request queue and background processing worker.

Responsibilities:
    - Receive HTTP request from Flask thread via log_request()
    - Drop requests into bounded collections.deque(maxlen=1000)
    - Background thread processes queue in pipeline:
        1. Rule layer (_check_rules)
        2. Fallback (_quick_classify)
        3. ML layer (classifier.classify_request)
    - Rate counters use in-memory collections — never SQLite
"""

import collections
import threading
import sqlite3
import json
import time
from datetime import datetime, timezone
from collections import defaultdict

import config
from app.database import get_db_connection

# ---------------------------------------------------------------------------
# Architecture: Bounded Async Queue
# ---------------------------------------------------------------------------
# The deque natively drops the *oldest* item when maxlen is reached,
# guaranteeing we always capture the freshest attack data during an HTTP flood.
_request_queue = collections.deque(maxlen=config.QUEUE_MAXSIZE)

# ---------------------------------------------------------------------------
# Architecture: In-Memory Rate Counters
# ---------------------------------------------------------------------------
_flood_counter = defaultdict(list)
_enum_counter = defaultdict(dict)  # Maps IP -> {path: last_seen_timestamp}
_bruteforce_counter = defaultdict(list)
_counter_lock = threading.Lock()

# Initialize global thread state
_worker_thread = None

def log_request(request_data: dict) -> bool:
    """
    Drop a request into the bounded queue.
    Returns immediately — Flask thread never blocks.

    Args: 
        request_data: dict with keys: source_ip, method, path,
                      headers, payload, user_agent
    
    Returns:
        True always, since deque naturally drops oldest if full.
    """
    request_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    _request_queue.append(request_data)
    return True

def _check_rules(request_data: dict) -> tuple:
    """
    Check three rate-based attack patterns using in-memory counters.
    Never queries SQLite — counters live in memory for accuracy.

    Returns:
        (attack_type: str, threat_score: int)
        ("Normal", 0) if no rule fires
    """
    ip = request_data.get("source_ip", "unknown")
    path = request_data.get("path", "/")
    method = request_data.get("method", "GET")
    now = datetime.now(timezone.utc).timestamp()

    with _counter_lock:
        # 1. HTTP Flood
        _flood_counter[ip] = [
            t for t in _flood_counter[ip]
            if now - t < config.RATE_FLOOD_WINDOW
        ]
        _flood_counter[ip].append(now)

        if len(_flood_counter[ip]) > config.RATE_FLOOD_THRESHOLD:
            return ("HTTP Flood", config.THREAT_SCORE_RULE_BASELINE)

        # 2. Directory Enumeration
        if any(path.startswith(s) or s in path for s in config.ENUM_SENSITIVE_PATHS):
            _enum_counter[ip] = {
                p: t for p, t in _enum_counter[ip].items()
                if now - t < config.RATE_ENUM_WINDOW
            }
            _enum_counter[ip][path] = now
            
            if len(_enum_counter[ip]) > config.RATE_ENUM_THRESHOLD:
                return ("Directory Enumeration", config.THREAT_SCORE_RULE_BASELINE)

        # 3. Web Brute Force
        if method == "POST" and path == config.BRUTEFORCE_TARGET:
            _bruteforce_counter[ip] = [
                t for t in _bruteforce_counter[ip]
                if now - t < config.RATE_BRUTEFORCE_WINDOW
            ]
            _bruteforce_counter[ip].append(now)

            if len(_bruteforce_counter[ip]) > config.RATE_BRUTEFORCE_THRESHOLD:
                return ("Web Brute Force", config.THREAT_SCORE_RULE_BASELINE)

    return ("Normal", 0)

def _quick_classify(request_data: dict) -> tuple:
    """
    Keyword-based fallback scanner.
    Guarantees demo output even if model.pkl is missing or corrupted.
    Issue M2 fix from proposal review.
    
    Note: Query string blind spot. This only checks payload and path.
    A GET request with SQLi in the query string won't trigger fallback.
    The ML layer will catch this via feature extraction.

    Returns:
        (attack_type: str, threat_score: int)
        ("Normal", 0) if no pattern matches
    """
    payload = (request_data.get("payload") or "").lower()
    path = (request_data.get("path") or "").lower()
    combined = payload + " " + path

    SQL_KEYWORDS = ["select ", "union ", "insert ", "drop ", "' or ",
                    "1=1", "--", "xp_", "exec(", "cast("]
    XSS_KEYWORDS = ["<script", "javascript:", "onerror=",
                    "onload=", "alert(", "document.cookie"]
    TRAVERSAL_KEYWORDS = ["../", "..\\", "%2e%2e",
                          "/etc/passwd", "/etc/shadow", "/proc/"]
    CRLF_KEYWORDS = ["%0d%0a", "%0a", "%0d", "\r\n", "content-type:"]

    if any(k in combined for k in SQL_KEYWORDS):
        return ("SQL Injection", 85)

    if any(k in combined for k in XSS_KEYWORDS):
        return ("XSS", 80)

    if any(k in combined for k in TRAVERSAL_KEYWORDS):
        return ("File Disclosure", 80)

    if any(k in combined for k in CRLF_KEYWORDS):
        return ("CRLF Injection", 78)

    # Buffer overflows are characterized by massive input, not specific keywords
    if len(payload) > 5000:
        return ("Buffer Overflow", 75)

    return ("Normal", 0)

def _generate_report(attack_type: str, threat_score: int, layer: str,
                     confidence: float, request_data: dict) -> str:
    """
    Generate plain-English forensic report shown in dashboard.
    """
    ip = request_data.get("source_ip", "unknown")
    path = request_data.get("path", "/")
    method = request_data.get("method", "GET")

    if attack_type == "Normal":
        return (
            f"Normal request from {ip} to {method} {path}. "
            f"No threat detected."
        )

    layer_desc = {
        "rule": "Rule-based detection (rate/pattern analysis)",
        "fallback": "Keyword-based fallback detection",
        "ml": f"Machine Learning model (confidence: {confidence:.0%})"
    }.get(layer, "Unknown detection method")

    return (
        f"THREAT DETECTED — {attack_type} | "
        f"Score: {threat_score}/100 | "
        f"Source: {ip} | "
        f"Target: {method} {path} | "
        f"Detected by: {layer_desc}"
    )

def _write_to_db(request_data: dict, attack_type: str, threat_score: int,
                confidence: float, layer: str, report: str) -> None:
    """
    Write all request fields in a single INSERT.
    Connection opened and closed per write — WAL mode handles concurrency.
    """
    conn = None
    try:
        conn = get_db_connection(config.DATABASE_PATH)
        conn.execute("""
            INSERT INTO logs (
                timestamp, ip_address, method, path,
                headers, payload, user_agent,
                attack_type, threat_score, confidence,
                layer, report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_data.get("timestamp"),
            request_data.get("source_ip"),
            request_data.get("method"),
            request_data.get("path"),
            json.dumps(request_data.get("headers", {})),
            request_data.get("payload"),
            request_data.get("user_agent"),
            attack_type,
            threat_score,
            confidence,
            layer,
            report
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"[WRAITH ERROR] DB write failed: {e}")
    finally:
        if conn:
            conn.close()

def _background_worker() -> None:
    """
    Infinite loop running in daemon thread.
    Pulls from queue and processes each request through the full pipeline:
        1. Rule layer
        2. Fallback classifier
        3. ML classifier
        4. Report generation
        5. Single INSERT
    """
    # Import gracefully so we don't crash if ML isn't built yet
    try:
        from app.classifier import classify_request
    except ImportError:
        classify_request = None

    while True:
        try:
            # deque.popleft() raises IndexError if empty
            request_data = _request_queue.popleft()
        except IndexError:
            time.sleep(0.1) # Polling delay to prevent CPU spin
            continue

        try:
            attack_type, threat_score = _check_rules(request_data)
            layer = "rule" if attack_type != "Normal" else None
            confidence = 0.0

            if attack_type == "Normal":
                attack_type, threat_score = _quick_classify(request_data)
                layer = "fallback" if attack_type != "Normal" else None
                confidence = 0.0

            if attack_type == "Normal" and classify_request is not None:
                # classifier.py returns exactly (attack_type, confidence) to keep ML pure
                ml_attack, ml_confidence = classify_request(request_data)
                
                # Enforce the ML Confidence Threshold
                if ml_attack != "Normal" and ml_confidence >= config.ML_CONFIDENCE_THRESHOLD:
                    attack_type = ml_attack
                    confidence = ml_confidence
                    threat_score = int(confidence * config.THREAT_SCORE_ML_MULTIPLIER)
                    layer = "ml"
            
            report = _generate_report(
                attack_type, threat_score, layer, confidence, request_data
            )

            _write_to_db(
                request_data, attack_type, threat_score,
                confidence, layer, report
            )

        except Exception as e:
            print(f"[WRAITH ERROR] Worker processing error: {e}")

def start_background_worker():
    """
    Start the background daemon thread.
    Called once by app/__init__.py at startup.
    Guard prevents duplicate threads if called more than once.
    """
    global _worker_thread

    if _worker_thread is not None and _worker_thread.is_alive():
        print("[WRAITH] Background worker already running.")
        return

    _worker_thread = threading.Thread(
        target=_background_worker,
        name="wraith-worker",
        daemon=True
    )
    _worker_thread.start()
    print("[WRAITH] Background worker started.")