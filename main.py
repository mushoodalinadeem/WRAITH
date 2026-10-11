"""
main.py — Entry point for WRAITH honeypot.

Usage:
    python3 main.py
    gunicorn --config gunicorn.conf.py main:app
"""

from dotenv import load_dotenv
load_dotenv()

from app import create_app
from app.classifier import load_model
import config

app = create_app()


def _print_startup_banner(model_loaded: bool) -> None:
    print("\n" + "=" * 60)
    print(" WRAITH — Intelligent HTTP Honeypot")
    print("=" * 60)
    print(f" Environment: {config.WRAITH_ENV}")
    print(f" Database   : {config.DATABASE_PATH}")
    print(f" Model      : {'LOADED' if model_loaded else 'NOT LOADED — rule + fallback only'}")
    print(f" Queue size : {config.QUEUE_MAXSIZE}")
    print(f" Debug mode : {config.FLASK_DEBUG}")
    print(f" Demo mode  : {config.ENABLE_DEMO}")
    print("-" * 60)
    print(" Honeypot endpoints active:")
    routes = getattr(config, "HONEYPOT_ROUTES", [])
    for i in range(0, len(routes), 2):
        col1 = f"   {routes[i]:<20}"
        col2 = f"{routes[i+1]}" if i + 1 < len(routes) else ""
        print((col1 + col2).rstrip())
    print("   ... plus dynamic catch-all for unknown paths")
    print("-" * 60)
    print(" Detection layers:")
    print("   [ACTIVE]   Rule layer — Flood / Enumeration / Brute Force")
    print("   [ACTIVE]   Fallback   — SQLi / XSS / CRLF / File Disclosure")
    ml_status = "ACTIVE  " if model_loaded else "DISABLED"
    print(f"   [{ml_status}] ML layer   — Random Forest (CSIC 2010)")
    print("-" * 60)
    print(" Operator endpoints (authentication required):")
    print("   GET  /dashboard      — forensic console")
    print("   GET  /logs           — recent log entries")
    print("   GET  /logs/<id>      — forensic detail")
    print("   POST /classify       — on-demand classification")
    print("   GET  /stream         — SSE live stream")
    print("   GET  /stats          — summary statistics")
    print("   GET  /healthz        — liveness probe")
    print("-" * 60)
    print(f" Listening  : http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    _print_startup_banner(load_model())
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
        threaded=True
    )
