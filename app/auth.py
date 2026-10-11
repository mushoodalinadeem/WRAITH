"""
Operator authentication for dashboard and forensic APIs.

Honeypot routes stay public. Session cookies are HttpOnly and are sent
to /logs, /stream, and /dashboard on the same origin.
"""

from __future__ import annotations

import time
from collections import defaultdict
from functools import wraps
from threading import Lock

from flask import jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config

_login_attempts = defaultdict(list)
_login_lock = Lock()
_password_hash = None
_hash_lock = Lock()


def password_hash() -> str:
    """Resolve the operator password hash once per process."""
    global _password_hash
    with _hash_lock:
        if _password_hash:
            return _password_hash
        if config.DASHBOARD_PASSWORD_HASH:
            _password_hash = config.DASHBOARD_PASSWORD_HASH
            return _password_hash
        if config.DASHBOARD_PASSWORD:
            _password_hash = generate_password_hash(config.DASHBOARD_PASSWORD)
            return _password_hash
        if not config.IS_PRODUCTION:
            _password_hash = generate_password_hash("wraith-dev-password")
            return _password_hash
        raise RuntimeError("DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH is required")


def reset_password_hash_cache() -> None:
    """Used by tests when env credentials change."""
    global _password_hash
    with _hash_lock:
        _password_hash = None


def operator_authenticated() -> bool:
    return bool(session.get("operator"))


def _wants_json() -> bool:
    if request.path.startswith("/logs") or request.path in ("/classify", "/stats", "/stream", "/demo/run"):
        return True
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return best == "application/json" and request.accept_mimetypes[best] >= request.accept_mimetypes["text/html"]


def _origin_ok() -> bool:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    origin = request.headers.get("Origin")
    if not origin:
        return True
    expected = request.host_url.rstrip("/")
    return origin.rstrip("/") == expected


def login_rate_limited(ip: str) -> bool:
    now = time.time()
    window = config.LOGIN_RATE_WINDOW
    with _login_lock:
        _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < window]
        return len(_login_attempts[ip]) >= config.LOGIN_RATE_THRESHOLD


def record_login_failure(ip: str) -> None:
    now = time.time()
    with _login_lock:
        _login_attempts[ip].append(now)


def verify_credentials(username: str, password: str) -> bool:
    if not username or not password:
        return False
    if username != config.DASHBOARD_USERNAME:
        check_password_hash(password_hash(), password)
        return False
    return check_password_hash(password_hash(), password)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if operator_authenticated():
            if not _origin_ok():
                return jsonify({"status": "error", "message": "Invalid origin"}), 403
            return view(*args, **kwargs)
        if _wants_json():
            return jsonify({"status": "error", "message": "Unauthorized"}), 401
        return redirect(url_for("admin.login"))

    return wrapped


def enforce_operator_auth():
    """Blueprint before_request hook."""
    if request.endpoint in ("admin.login", "admin.logout", "admin.csrf_token"):
        return None
    path = request.path or ""
    if path.endswith((".css", ".js", ".map", ".ico", ".png", ".svg", ".woff", ".woff2")):
        return None
    if operator_authenticated():
        if not _origin_ok():
            return jsonify({"status": "error", "message": "Invalid origin"}), 403
        return None
    if _wants_json() or path.startswith("/logs") or path in ("/classify", "/stats", "/stream", "/demo/run"):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    return redirect(url_for("admin.login"))
