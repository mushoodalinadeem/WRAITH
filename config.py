"""
config.py — Central configuration for WRAITH honeypot.
All thresholds, color codes, paths, math logic, and constants live here.
No magic numbers or magic strings anywhere else in the codebase.
"""

import os

# ---------------------------------------------------------------------------
# Flask Settings
# ---------------------------------------------------------------------------
FLASK_SECRET_KEY = os.getenv("SECRET_KEY", "wraith-dev-secret-key")
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Project Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.getenv("WRAITH_DB_PATH", os.path.join(BASE_DIR, "data", "wraith.db"))
MODEL_PATH = os.getenv("WRAITH_MODEL_PATH", os.path.join(BASE_DIR, "ml", "model.pkl"))

# ---------------------------------------------------------------------------
# Threat Score & Dashboard Thresholds
# ---------------------------------------------------------------------------
THRESHOLD_WARNING = int(os.getenv("THRESHOLD_WARNING", 40))
THRESHOLD_ALERT = int(os.getenv("THRESHOLD_ALERT", 70))

COLOR_NORMAL = "#0ea5e9"     # Sky-blue  — threat score < 40
COLOR_WARNING = "#f59e0b"    # Amber     — threat score 40–70
COLOR_ALERT = "#ef4444"      # Red       — threat score > 70

# ---------------------------------------------------------------------------
# Threat Score Computation Strategy
# ---------------------------------------------------------------------------
THREAT_SCORE_ML_MULTIPLIER = 100         # e.g., ML confidence 0.82 -> score 82
THREAT_SCORE_RULE_BASELINE = 95          # Rule-based attacks are binary facts -> score 95
ML_CONFIDENCE_THRESHOLD = float(os.getenv("ML_CONFIDENCE_THRESHOLD", 0.75)) # Ignore ML < 75%
CLASSIFICATION_PRIORITY = os.getenv("CLASSIFICATION_PRIORITY", "rule") # "rule" | "ml"

# ---------------------------------------------------------------------------
# Architecture Limits & Queue Strategy
# ---------------------------------------------------------------------------
QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", 1000))
# To support "drop oldest" behavior under flood, logger.py MUST use:
# collections.deque(maxlen=QUEUE_MAXSIZE) instead of queue.Queue()

# ---------------------------------------------------------------------------
# Rule-Based Detection Thresholds & Windows
# ---------------------------------------------------------------------------
RATE_FLOOD_THRESHOLD = int(os.getenv("RATE_FLOOD_THRESHOLD", 20))    # requests
RATE_FLOOD_WINDOW = int(os.getenv("RATE_FLOOD_WINDOW", 1))           # per second

RATE_ENUM_THRESHOLD = int(os.getenv("RATE_ENUM_THRESHOLD", 5))       # unique paths
RATE_ENUM_WINDOW = int(os.getenv("RATE_ENUM_WINDOW", 60))            # per 60 seconds

RATE_BRUTEFORCE_THRESHOLD = int(os.getenv("RATE_BRUTEFORCE_THRESHOLD", 3)) # failed POSTs
RATE_BRUTEFORCE_WINDOW = int(os.getenv("RATE_BRUTEFORCE_WINDOW", 120))     # per 120 seconds

# ---------------------------------------------------------------------------
# Decoy Topology
# TODO: Expand to all 9 honeypot endpoints once finalized in honeypot.py
# ---------------------------------------------------------------------------
HONEYPOT_ROUTES = [
    '/admin/login',
    '/api/users',
    '/config/database',
    '/backup',
]

# Specifically tracked by the Brute Force rule layer
BRUTEFORCE_TARGET = '/admin/login'

# ---------------------------------------------------------------------------
# Centralized Attack Labels
# ---------------------------------------------------------------------------
ML_ATTACK_TYPES = [
    "SQL Injection",
    "XSS",
    "Buffer Overflow",
    "CRLF Injection",
    "File Disclosure",
]

RULE_ATTACK_TYPES = [
    "HTTP Flood",
    "Directory Enumeration",
    "Web Brute Force",
]

ALL_ATTACK_TYPES = ML_ATTACK_TYPES + RULE_ATTACK_TYPES

# ---------------------------------------------------------------------------
# SSE / Streaming
# ---------------------------------------------------------------------------
SSE_RETRY_MS = 2000