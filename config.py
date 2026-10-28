"""
config.py — Central configuration for WRAITH honeypot.
All thresholds, color codes, paths, math logic, and constants live here.
No magic numbers or magic strings anywhere else in the codebase.
"""

import os

WRAITH_ENV = os.getenv("WRAITH_ENV", "development").strip().lower()
IS_PRODUCTION = WRAITH_ENV in ("production", "prod")
IS_TEST = WRAITH_ENV in ("test", "testing")

FLASK_SECRET_KEY = os.getenv("SECRET_KEY", "wraith-dev-secret-key")
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true" and not IS_PRODUCTION
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))

DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "operator")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
DASHBOARD_PASSWORD_HASH = os.getenv("DASHBOARD_PASSWORD_HASH", "")

SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
SESSION_HOURS = int(os.getenv("SESSION_HOURS", 8))
ENABLE_DEMO = os.getenv("ENABLE_DEMO", "false").lower() == "true"

LOGIN_RATE_THRESHOLD = int(os.getenv("LOGIN_RATE_THRESHOLD", 5))
LOGIN_RATE_WINDOW = int(os.getenv("LOGIN_RATE_WINDOW", 300))
MIN_PASSWORD_LENGTH = 12
DEV_SECRET_KEY = "wraith-dev-secret-key"

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

QUEUE_MAXSIZE = int(os.getenv("QUEUE_MAXSIZE", 1000))


RATE_FLOOD_THRESHOLD = int(os.getenv("RATE_FLOOD_THRESHOLD", 20))    # requests
RATE_FLOOD_WINDOW = int(os.getenv("RATE_FLOOD_WINDOW", 1))           # per second

RATE_ENUM_THRESHOLD = int(os.getenv("RATE_ENUM_THRESHOLD", 5))       # unique paths
RATE_ENUM_WINDOW = int(os.getenv("RATE_ENUM_WINDOW", 60))            # per 60 seconds

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

API_MAX_LIMIT = int(os.getenv("API_MAX_LIMIT", 1000))
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 1 * 1024 * 1024))  # 1 MB
COUNTER_CLEANUP_INTERVAL = int(os.getenv("COUNTER_CLEANUP_INTERVAL", 300))  # 5 minutes
SSE_BATCH_LIMIT = int(os.getenv("SSE_BATCH_LIMIT", 500))

FALLBACK_SCORE_SQLI = int(os.getenv("FALLBACK_SCORE_SQLI", 85))
FALLBACK_SCORE_XSS = int(os.getenv("FALLBACK_SCORE_XSS", 80))
FALLBACK_SCORE_TRAVERSAL = int(os.getenv("FALLBACK_SCORE_TRAVERSAL", 80))
FALLBACK_SCORE_CRLF = int(os.getenv("FALLBACK_SCORE_CRLF", 78))
FALLBACK_SCORE_OVERFLOW = int(os.getenv("FALLBACK_SCORE_OVERFLOW", 75))
BUFFER_OVERFLOW_PAYLOAD_THRESHOLD = int(os.getenv("BUFFER_OVERFLOW_PAYLOAD_THRESHOLD", 5000))
# NEW (Fix 5): how many URL-decode passes the keyword fallback applies when
# scanning. 2 catches double encoding: %253Cscript -> %3Cscript -> <script.
MAX_URL_DECODE_PASSES = int(os.getenv("MAX_URL_DECODE_PASSES", 2))
EMERGENCY_COUNTER_LIMIT = int(os.getenv("EMERGENCY_COUNTER_LIMIT", 10000))

# Secret values that must never reach production. Checked in
# validate_runtime_config(): exact match, or any value starting with the
# example placeholder prefix ("replace-with-...").
PLACEHOLDER_SECRETS = ("replace-with-a-long-random-string", "replace-with")


def validate_runtime_config() -> None:
    """Refuse to start in production with placeholder secrets."""
    if IS_TEST:
        return
    if not IS_PRODUCTION:
        return
    if (not FLASK_SECRET_KEY
            or FLASK_SECRET_KEY == DEV_SECRET_KEY
            or FLASK_SECRET_KEY in PLACEHOLDER_SECRETS
            or FLASK_SECRET_KEY.startswith(PLACEHOLDER_SECRETS)):
        raise RuntimeError(
            "SECRET_KEY must be set to a unique value in production "
            "(placeholder and dev-default values are rejected)"
        )
    if len(FLASK_SECRET_KEY) < 32:
        raise RuntimeError("SECRET_KEY must be at least 32 characters in production")
    if FLASK_DEBUG:
        raise RuntimeError("FLASK_DEBUG cannot be enabled in production")
    if not DASHBOARD_PASSWORD_HASH:
        if not DASHBOARD_PASSWORD or len(DASHBOARD_PASSWORD) < MIN_PASSWORD_LENGTH:
            raise RuntimeError(
                "DASHBOARD_PASSWORD (12+ chars) or DASHBOARD_PASSWORD_HASH is required in production"
            )