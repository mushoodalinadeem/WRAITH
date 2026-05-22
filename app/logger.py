"""
app/logger.py — Async bounded request queue and background processing worker.

Responsibilities:
    - Receive HTTP request from Flask thread via log_request()
    - Drop requests into bounded queue.Queue(maxsize=1000)
    - Background thread processes queue in pipeline:
        1. Rule layer (_check_rules)
        2. Fallback (_quick_classify)
        3. ML layer (classifier.classify_request)
    - Rate counters use in-memory collections — never SQLite
"""

import collections
import queue
import threading
import sqlite3
import json
import time
from datetime import datetime, timezone
from collections import defaultdict

import config
from app.database import get_db_connection

try:
    from app.classifier import classify_request as _classify_request
except ImportError:
    _classify_request = None

# Uses a custom evicting queue instead of queue.Queue(maxsize=1000).
# queue.Queue blocks or raises Full — neither drops oldest.
# BoundedEvictingQueue uses deque(maxlen) which atomically evicts oldest on overflow.
class BoundedEvictingQueue:
    """
    Thread-safe, memory-bounded FIFO queue using collections.deque.
    Auto-evicts the oldest item when capacity is reached, preventing
    blocking or dropping new requests under an HTTP flood.
    """
    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self.deque = collections.deque(maxlen=maxsize)
        self.lock = threading.Lock()
        self.not_empty = threading.Condition(self.lock)

    def put(self, item) -> None:
        with self.lock:
            self.deque.append(item)
            self.not_empty.notify()

    def put_nowait(self, item) -> None:
        self.put(item)

    def get(self, timeout: float = None):
        with self.lock:
            if not self.deque:
                if timeout is None:
                    while not self.deque:
                        self.not_empty.wait()
                else:
                    end_time = time.time() + timeout
                    while not self.deque:
                        remaining = end_time - time.time()
                        if remaining <= 0:
                            raise queue.Empty
                        self.not_empty.wait(remaining)
            return self.deque.popleft()

_request_queue = BoundedEvictingQueue(maxsize=config.QUEUE_MAXSIZE)

# NOTE: Rate-limiting counters live in local volatile memory.
# In a multi-worker production environment (e.g. Gunicorn with multiple workers),
# requests are load-balanced across isolated worker processes. Because state is
# not shared, rate limiting will fail to accurately track request thresholds.
# WRAITH must be pinned to a single WSGI worker process (e.g., `gunicorn -w 1 main:app`)
# to ensure rate-limiting accuracy, or these counters must be refactored to use
# an external shared-memory store like Redis.
_flood_counter = defaultdict(list)
_enum_counter = defaultdict(dict)
_bruteforce_counter = defaultdict(list)
_counter_lock = threading.Lock()
_last_cleanup = 0.0

_worker_thread = None

def log_request(request_data: dict) -> bool:
    """
    Drop a request into the bounded queue.
    Returns immediately — Flask thread never blocks.

    Args: 
        request_data: dict with keys: source_ip, method, path,
                      headers, payload, user_agent
    
    Returns:
        True
    """
    request_data["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    _request_queue.put(request_data)
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
        # EMERGENCY BRAKE: Prevent OOM from distributed burst scans
        if len(_flood_counter) > config.EMERGENCY_COUNTER_LIMIT:
            _flood_counter.clear()
            _enum_counter.clear()
            _bruteforce_counter.clear()

        _flood_counter[ip] = [
            t for t in _flood_counter[ip]
            if now - t < config.RATE_FLOOD_WINDOW
        ]
        _flood_counter[ip].append(now)

        if len(_flood_counter[ip]) > config.RATE_FLOOD_THRESHOLD:
            return ("HTTP Flood", config.THREAT_SCORE_RULE_BASELINE)

        _enum_counter[ip] = {
            p: t for p, t in _enum_counter[ip].items()
            if now - t < config.RATE_ENUM_WINDOW
        }

        _ENUM_IGNORE = {"/favicon.ico", "/robots.txt"}
        if path not in _ENUM_IGNORE:
            _enum_counter[ip][path] = now
            
            if len(_enum_counter[ip]) > config.RATE_ENUM_THRESHOLD:
                return ("Directory Enumeration", config.THREAT_SCORE_RULE_BASELINE)

        if method.upper() == "POST" and path == config.BRUTEFORCE_TARGET:
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
    query_string = (request_data.get("query_string") or "").lower()
    combined = payload + " " + path + ("?" + query_string if query_string else "")

    SQL_KEYWORDS = ["select ", "union ", "insert ", "drop ", "' or ",
                    "1=1", "--", "xp_", "exec(", "cast("]
    XSS_KEYWORDS = ["<script", "javascript:", "onerror=",
                    "onload=", "alert(", "document.cookie"]
    TRAVERSAL_KEYWORDS = ["../", "..\\", "%2e%2e",
                          "/etc/passwd", "/etc/shadow", "/proc/"]
    CRLF_KEYWORDS = ["%0d%0a", "%0a", "%0d", "\r\n", "content-type:"]

    if any(k in combined for k in SQL_KEYWORDS):
        return ("SQL Injection", config.FALLBACK_SCORE_SQLI)

    if any(k in combined for k in XSS_KEYWORDS):
        return ("XSS", config.FALLBACK_SCORE_XSS)

    if any(k in combined for k in TRAVERSAL_KEYWORDS):
        return ("File Disclosure", config.FALLBACK_SCORE_TRAVERSAL)

    if any(k in combined for k in CRLF_KEYWORDS):
        return ("CRLF Injection", config.FALLBACK_SCORE_CRLF)

    if len(payload) > config.BUFFER_OVERFLOW_PAYLOAD_THRESHOLD:
        return ("Buffer Overflow", config.FALLBACK_SCORE_OVERFLOW)

    return ("Normal", 0)

def _generate_report(attack_type: str, threat_score: int, layer: str,
                     confidence: float, request_data: dict) -> str:
    """
    Generate plain-English forensic report shown in dashboard.
    """
    ip = request_data.get("source_ip", "unknown")
    path = request_data.get("path", "/")
    query_string = request_data.get("query_string", "")
    full_path = path + ("?" + query_string if query_string else "")
    method = request_data.get("method", "GET")

    if attack_type == "Normal":
        return (
            f"Normal request from {ip} to {method} {full_path}. "
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
        f"Target: {method} {full_path} | "
        f"Detected by: {layer_desc}"
    )

def _write_to_db(request_data: dict, attack_type: str, threat_score: int,
                confidence: float, layer: str, report: str,
                is_simulation: bool = False) -> None:
    """
    Write all request fields in a single INSERT.
    Connection opened and closed per write — WAL mode handles concurrency.

    Args:
        is_simulation: If True, marks this row as test/simulation data
                       so forensic queries can filter it out.
    """
    conn = None
    try:
        conn = get_db_connection(config.DATABASE_PATH)
        conn.execute("""
            INSERT INTO logs (
                timestamp, ip_address, method, path,
                headers, payload, user_agent,
                attack_type, threat_score, confidence,
                layer, report, is_simulation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_data.get("timestamp"),
            request_data.get("source_ip"),
            request_data.get("method"),
            request_data.get("path", "") + ("?" + request_data.get("query_string") if request_data.get("query_string") else ""),
            json.dumps(request_data.get("headers", {})),
            request_data.get("payload"),
            request_data.get("user_agent"),
            attack_type,
            threat_score,
            confidence,
            layer,
            report,
            1 if is_simulation else 0
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"[WRAITH ERROR] DB write failed: {e}")
    finally:
        if conn:
            conn.close()

def persist_log(request_data: dict, result: dict) -> None:
    """Public wrapper for _write_to_db. Used by api.py /classify.
    Marks the entry as simulation data so forensic queries can exclude it."""
    _write_to_db(
        request_data,
        result["attack_type"],
        result["threat_score"],
        result["confidence"],
        result["layer"],
        result["report"],
        is_simulation=True
    )

def run_pipeline(request_data: dict, skip_rules: bool = False) -> dict:
    """
    Public interface for the full classification pipeline.
    Used by both the background worker and the /classify API endpoint.

    Pipeline order:
        1. Rule layer (_check_rules) — skipped if skip_rules=True
        2. Fallback (_quick_classify)
        3. ML layer (classifier.classify_request)
        4. Report generation

    Args:
        request_data: dict with keys — source_ip, method, path, payload, etc.
        skip_rules: If True, skip rate-based rules to avoid polluting
                    in-memory counters (used by /classify endpoint).

    Returns:
        dict with keys: attack_type, threat_score, confidence, layer, report
    """
    attack_type = "Normal"
    threat_score = 0
    layer = None
    confidence = 0.0

    # 1. Rule layer (rate-based detection)
    if not skip_rules:
        attack_type, threat_score = _check_rules(request_data)
        layer = "rule" if attack_type != "Normal" else None

    # 2. Fallback (keyword-based detection)
    if attack_type == "Normal":
        attack_type, threat_score = _quick_classify(request_data)
        layer = "fallback" if attack_type != "Normal" else None

    # 3. ML layer
    if attack_type == "Normal" and _classify_request is not None:
        ml_attack, ml_confidence = _classify_request(request_data)
        if ml_attack != "Normal" and ml_confidence >= config.ML_CONFIDENCE_THRESHOLD:
            attack_type = ml_attack
            confidence = ml_confidence
            threat_score = int(confidence * config.THREAT_SCORE_ML_MULTIPLIER)
            layer = "ml"

    # 4. Report generation
    report = _generate_report(attack_type, threat_score, layer, confidence, request_data)

    return {
        "attack_type": attack_type,
        "threat_score": threat_score,
        "confidence": confidence,
        "layer": layer,
        "report": report
    }

def _cleanup_stale_counters() -> None:
    """
    Remove IP keys whose sliding windows have fully expired.
    Prevents unbounded memory growth from distributed scans
    where thousands of unique IPs each leave an empty list/dict.

    Runs every COUNTER_CLEANUP_INTERVAL seconds (default 300 = 5 min).
    Called from _background_worker(), NOT from _check_rules() — avoids
    adding cleanup cost to the per-request hot path.
    """
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < config.COUNTER_CLEANUP_INTERVAL:
        return
    _last_cleanup = now

    with _counter_lock:
        for ip in list(_flood_counter):
            _flood_counter[ip] = [
                t for t in _flood_counter[ip]
                if now - t < config.RATE_FLOOD_WINDOW
            ]
            if not _flood_counter[ip]:
                del _flood_counter[ip]

        for ip in list(_enum_counter):
            _enum_counter[ip] = {
                p: t for p, t in _enum_counter[ip].items()
                if now - t < config.RATE_ENUM_WINDOW
            }
            if not _enum_counter[ip]:
                del _enum_counter[ip]

        for ip in list(_bruteforce_counter):
            _bruteforce_counter[ip] = [
                t for t in _bruteforce_counter[ip]
                if now - t < config.RATE_BRUTEFORCE_WINDOW
            ]
            if not _bruteforce_counter[ip]:
                del _bruteforce_counter[ip]


def _background_worker() -> None:
    """
    Infinite loop running in daemon thread.
    Pulls from queue and processes each request through run_pipeline(),
    then writes the result to the database.

    Cleanup runs on a loop counter (every 500 iterations) to avoid
    calling _cleanup_stale_counters() on every single iteration.
    A fallback check also runs when the queue is idle.
    """
    loop_count = 0
    while True:
        loop_count += 1
        if loop_count >= 500:
            _cleanup_stale_counters()
            loop_count = 0

        try:
            request_data = _request_queue.get(timeout=0.1)
        except queue.Empty:
            _cleanup_stale_counters()
            continue

        try:
            result = run_pipeline(request_data, skip_rules=False)

            _write_to_db(
                request_data,
                result["attack_type"],
                result["threat_score"],
                result["confidence"],
                result["layer"],
                result["report"],
                is_simulation=False
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