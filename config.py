"""
config.py — Central configuration for WRAITH honeypot.
All thresholds, color codes, paths, math logic, and constants live here.
No magic numbers or magic strings anywhere else in the codebase.
"""

import os

FLASK_SECRET_KEY = os.getenv("SECRET_KEY", "wraith-dev-secret-key")
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.getenv("WRAITH_DB_PATH", os.path.join(BASE_DIR, "data", "wraith.db"))
MODEL_PATH = os.getenv("WRAITH_MODEL_PATH", os.path.join(BASE_DIR, "ml", "model.pkl"))

THRESHOLD_WARNING = int(os.getenv("THRESHOLD_WARNING", 40))
THRESHOLD_ALERT = int(os.getenv("THRESHOLD_ALERT", 70))

COLOR_NORMAL = "#0ea5e9"
COLOR_WARNING = "#f59e0b"
COLOR_ALERT = "#ef4444"

THREAT_SCORE_ML_MULTIPLIER = 100
THREAT_SCORE_RULE_BASELINE = 95
ML_CONFIDENCE_THRESHOLD = float(os.getenv("ML_CONFIDENCE_THRESHOLD", 0.75))
CLASSIFICATION_PRIORITY = os.getenv("CLASSIFICATION_PRIORITY", "rule")

QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", 1000))


RATE_FLOOD_THRESHOLD = int(os.getenv("RATE_FLOOD_THRESHOLD", 20))    # requests
RATE_FLOOD_WINDOW = int(os.getenv("RATE_FLOOD_WINDOW", 1))           # per second

RATE_ENUM_THRESHOLD = int(os.getenv("RATE_ENUM_THRESHOLD", 5))       # unique paths
RATE_ENUM_WINDOW = int(os.getenv("RATE_ENUM_WINDOW", 60))            # per 60 seconds
ENUM_SENSITIVE_PATHS = [
    '/admin', '/config', '/backup', '/api',
    '/.env', '/etc', '/proc', '/phpmyadmin',
]

RATE_BRUTEFORCE_THRESHOLD = int(os.getenv("RATE_BRUTEFORCE_THRESHOLD", 3)) # failed POSTs
RATE_BRUTEFORCE_WINDOW = int(os.getenv("RATE_BRUTEFORCE_WINDOW", 120))     # per 120 seconds


BRUTEFORCE_TARGET = '/admin/login'

HONEYPOT_ROUTES = [
    "/admin/login",
    "/api/users",
    "/config/database",
    "/backup",
    "/api/orders",
    "/api/payments",
    "/api/admin/export",
    "/api/logs",
    "/api/search",
]

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

SSE_RETRY_MS = 2000