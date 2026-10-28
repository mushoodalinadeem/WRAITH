"""
app/logger.py — Async bounded SQLite write queue (locked structure).

Responsibilities:
    - Receive HTTP request from Flask thread via log_request()
    - Drop requests into a bounded evicting queue (maxsize=QUEUE_MAXSIZE)
    - Background thread pulls each request, hands it to
      app.classifier.run_pipeline(), and writes the result with ONE INSERT
    - Owns SQLite connection/WAL setup, get-free storage counters and
      persist_log() for the /classify endpoint

All detection logic (rule layer, keyword fallback, ML, priority logic,
rate counters and their cleanup) lives in app/classifier.py. This module
imports classifier — never the reverse.
"""

import collections
import queue
import threading
import sqlite3
import json
import time
from datetime import datetime, timezone

import config
from app.database import get_db_connection
from app.classifier import run_pipeline, _cleanup_stale_counters

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

def _background_worker() -> None:
    """
    Infinite loop running in daemon thread.
    Pulls from the bounded queue and calls app.classifier.run_pipeline()
    for each request, then writes the result to the database with ONE INSERT.

    Counter cleanup (owned by classifier) runs on a loop counter (every 500
    iterations) to avoid calling _cleanup_stale_counters() on every single
    iteration. A fallback check also runs when the queue is idle.
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
