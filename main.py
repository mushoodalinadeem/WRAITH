"""
main.py — Entry point for WRAITH honeypot.

Usage:
    python3 main.py

What this file does:
    1. Create the Flask app via create_app() factory
    2. Attempts to load model.pkl via load_model()
    3. Prints startup banner showing system state
    4. Starts Flask development server

Do not import this file — run it directly.
"""

from dotenv import load_dotenv
load_dotenv()

from app import create_app
from app.classifier import load_model
import config


def _print_startup_banner(model_loaded: bool) -> None:
    """
    Print formatted startup summary to terminal.
    Shown every time WRAITH starts — communicates full system state at a glance.
    """
    print("\n" + "=" * 60)
    print(" WRAITH — Intelligent HTTP Honeypot")
    print("=" * 60)
    print(f" Database   : {config.DATABASE_PATH}")
    print(f" Model      : {'LOADED' if model_loaded else 'NOT LOADED — rule + fallback only'}")
    print(f" Queue size : {config.QUEUE_MAXSIZE}")
    print(f" Debug mode : {config.FLASK_DEBUG}")
    print("-" * 60)
    print(" Honeypot endpoints active:")
    routes = getattr(config, 'HONEYPOT_ROUTES', [])
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
    print(" API endpoints:")
    print("   GET  /logs           — recent log entries")
    print("   GET  /logs/<id>      — forensic detail")
    print("   POST /classify       — on-demand classification")
    print("   GET  /stream         — SSE live stream")
    print("   GET  /stats          — summary statistics")
    print("   POST /demo/run       — trigger simulation")
    print("-" * 60)
    print(f" Listening  : http://{config.FLASK_HOST}:{config.FLASK_PORT}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    model_loaded = load_model()
    app = create_app()
    _print_startup_banner(model_loaded)

    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,   # CRITICAL — reloader starts 2 processes = 2 background workers
        threaded=True         # Handle concurrent honeypot requests
    )
