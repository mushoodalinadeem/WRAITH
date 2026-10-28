"""
app/admin.py — Admin dashboard blueprint for WRAITH.

Serves the forensic monitoring dashboard at /dashboard/.
Login is required for HTML pages. CSS/JS stay public so the login page can load.
"""

import html as htmllib
import os
import secrets

from flask import (
    Blueprint,
    jsonify,
    redirect,
    request,
    send_from_directory,
    session,
    url_for,
)

import config
from app.auth import login_rate_limited, record_login_failure, verify_credentials

admin_bp = Blueprint("admin", __name__)

_DASHBOARD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dashboard"
)

if not os.path.isdir(_DASHBOARD_DIR):
    print(f"[WRAITH WARNING] Dashboard directory not found: {_DASHBOARD_DIR}")


def _inject_runtime_config(html: str) -> str:
    demo = "true" if config.ENABLE_DEMO else "false"
    flag = f"<script>window.__WRAITH_CONFIG__={{demoEnabled:{demo}}};</script>"
    return html.replace("</head>", flag + "\n</head>", 1)


def _login_page(error: str = ""):
    session["csrf_token"] = secrets.token_urlsafe(32)
    path = os.path.join(_DASHBOARD_DIR, "login.html")
    with open(path, encoding="utf-8") as handle:
        html = handle.read()
    html = html.replace("__CSRF_TOKEN__", session["csrf_token"])
    # HTML-escape the error value so the placeholder can never become an
    # injection point (today the values are fixed strings; this guarantees it).
    html = html.replace("__LOGIN_ERROR__", htmllib.escape(error))
    return html


@admin_bp.route("/login", methods=["GET", "POST"], strict_slashes=False)
def login():
    if request.method == "GET":
        if session.get("operator"):
            return redirect(url_for("admin.dashboard"))
        error = "Invalid credentials." if request.args.get("error") else ""
        return _login_page(error)

    ip = request.remote_addr or "0.0.0.0"
    if login_rate_limited(ip):
        return _login_page("Too many login attempts. Try again later."), 429

    form_token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not form_token or not secrets.compare_digest(expected, form_token):
        return _login_page("Invalid session. Refresh and try again."), 400

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not verify_credentials(username, password):
        record_login_failure(ip)
        return redirect(url_for("admin.login", error=1))

    session.clear()
    session["operator"] = username
    session.permanent = True
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/logout", methods=["GET", "POST"], strict_slashes=False)
def logout():
    session.clear()
    return redirect(url_for("admin.login"))


@admin_bp.route("/csrf", methods=["GET"], strict_slashes=False)
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify({"csrf_token": session["csrf_token"]}), 200


@admin_bp.route("/", strict_slashes=False)
def dashboard():
    index_path = os.path.join(_DASHBOARD_DIR, "index.html")
    with open(index_path, encoding="utf-8") as handle:
        html = handle.read()
    return _inject_runtime_config(html)


@admin_bp.route("/<path:filename>")
def dashboard_static(filename):
    if ".." in filename or filename.startswith("/"):
        return jsonify({"error": "Forbidden"}), 403
    if filename == "login.html":
        # login.html is a template with __CSRF_TOKEN__/__LOGIN_ERROR__
        # placeholders, not a finished page — redirect to the real login
        # route so the shared renderer fills them in. Redirect (not local
        # rendering) keeps this a one-liner and avoids duplicating the
        # substitution logic; the login route already redirects
        # authenticated visitors to the dashboard.
        return redirect(url_for("admin.login"))
    return send_from_directory(_DASHBOARD_DIR, filename)
