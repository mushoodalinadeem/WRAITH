"""
app/classifier.py — Classification pipeline for WRAITH (locked structure).

Owns all detection logic:
    - Rule layer (_check_rules) — rate-based, in-memory counters
    - Fallback (_quick_classify) — keyword scan incl. Fix 5 URL-decoding
    - ML layer (classify_request) — model.pkl Random Forest, lazy-loaded
    - run_pipeline() — all three stages, priority logic, threat_score, report
    - _cleanup_stale_counters() — counter expiry sweep, called by logger's worker

Import direction (no circular imports): this module imports config only.
app/logger.py imports THIS module — never the reverse.
"""

import collections
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import config
import os
import math
import re
import pickle

# NOTE: Rate-limiting counters live in local volatile memory.
# In a multi-worker production environment (e.g. Gunicorn with multiple workers),
# requests are load-balanced across isolated worker processes. Because state is
# not shared, rate limiting will fail to accurately track request thresholds.
# WRAITH must be pinned to a single WSGI worker process (e.g., `gunicorn -w 1 main:app`)
# to ensure rate-limiting accuracy, or these counters must be refactored to use
# an external shared-memory store like Redis.
_flood_counter = collections.defaultdict(list)
_enum_counter = collections.defaultdict(dict)
_bruteforce_counter = collections.defaultdict(list)
_counter_lock = threading.Lock()
_last_cleanup = 0.0

_ENUM_IGNORE = frozenset({"/favicon.ico", "/robots.txt"})

def _check_rules(request_data: dict) -> tuple:
    """
    Check three rate-based attack patterns using in-memory counters.
    Never queries SQLite — counters live in memory for accuracy.

    Fix 2: rules are evaluated most-specific first (Brute Force: method + exact
    path), then HTTP Flood (rate spike), then Directory Enumeration (many
    distinct unknown paths). A generic chatter rule must never mask a precise
    signature, so Brute Force is checked before the generic rules.

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

        # 1. Web Brute Force — most specific: repeated POSTs to the fake
        #    admin login. Checked first so a hot generic rule can never
        #    prevent the brute counter from being consulted.
        if method.upper() == "POST" and path == config.BRUTEFORCE_TARGET:
            _bruteforce_counter[ip] = [
                t for t in _bruteforce_counter[ip]
                if now - t < config.RATE_BRUTEFORCE_WINDOW
            ]
            _bruteforce_counter[ip].append(now)

            if len(_bruteforce_counter[ip]) > config.RATE_BRUTEFORCE_THRESHOLD:
                return ("Web Brute Force", config.THREAT_SCORE_RULE_BASELINE)

        # 2. HTTP Flood — request-rate spike from one IP.
        _flood_counter[ip] = [
            t for t in _flood_counter[ip]
            if now - t < config.RATE_FLOOD_WINDOW
        ]
        _flood_counter[ip].append(now)

        if len(_flood_counter[ip]) > config.RATE_FLOOD_THRESHOLD:
            return ("HTTP Flood", config.THREAT_SCORE_RULE_BASELINE)

        # 3. Directory Enumeration — most generic: many distinct unknown paths.
        _enum_counter[ip] = {
            p: t for p, t in _enum_counter[ip].items()
            if now - t < config.RATE_ENUM_WINDOW
        }

        # Fix 1: only unknown paths (served by the catch-all route) count as
        # directory enumeration. Registered honeypot routes, dashboard pages,
        # statics and /stream never reach the catch-all, so they are never counted.
        if request_data.get("is_catchall") and path not in _ENUM_IGNORE:
            _enum_counter[ip][path] = now

            if len(_enum_counter[ip]) > config.RATE_ENUM_THRESHOLD:
                return ("Directory Enumeration", config.THREAT_SCORE_RULE_BASELINE)

    return ("Normal", 0)

def _safe_decode(text: str, plus: bool = False) -> str:
    """
    Fix 5: URL-decode that can never raise. urllib.parse.unquote does not
    raise on malformed input (lone %, %ZZ stay literal, invalid UTF-8 bytes
    become U+FFFD), but the guard guarantees the background worker can never
    crash on hostile input regardless of stdlib behavior.
    """
    try:
        return urllib.parse.unquote_plus(text) if plus else urllib.parse.unquote(text)
    except Exception:
        return text

def _quick_classify(request_data: dict) -> tuple:
    """
    Keyword-based fallback scanner.
    Guarantees demo output even if model.pkl is missing or corrupted.
    Issue M2 fix from proposal review.

    Note: Checks payload, path, and query string — raw AND URL-decoded forms
    (Fix 5). Feature extraction for ML still reads the raw request data.

    Returns:
        (attack_type: str, threat_score: int)
        ("Normal", 0) if no pattern matches
    """
    raw_payload = (request_data.get("payload") or "").lower()
    path = (request_data.get("path") or "").lower()
    query_string = (request_data.get("query_string") or "").lower()
    combined = raw_payload + " " + path + ("?" + query_string if query_string else "")

    # Fix 5: also scan URL-decoded forms, so nothing that matched the raw
    # text before stops matching. Decode choice per component: payload and
    # path use unquote ('+' is a literal plus there); the query string uses
    # unquote_plus ('+' means space in query syntax). MAX_URL_DECODE_PASSES
    # (2) catches double encoding: %253Cscript -> %3Cscript -> <script.
    dec_payload, dec_path, dec_query = raw_payload, path, query_string
    for _ in range(config.MAX_URL_DECODE_PASSES):
        dec_payload = _safe_decode(dec_payload)
        dec_path = _safe_decode(dec_path)
        dec_query = _safe_decode(dec_query, plus=True)
    combined_decoded = dec_payload + " " + dec_path + ("?" + dec_query if dec_query else "")

    SQL_KEYWORDS = ["select ", "union ", "insert ", "drop ", "' or ",
                    "1=1", "--", "xp_", "exec(", "cast(", "'or'"]
    XSS_KEYWORDS = ["<script", "javascript:", "onerror=",
                    "onload=", "alert(", "document.cookie"]
    TRAVERSAL_KEYWORDS = ["../", "..\\", "%2e%2e",
                          "/etc/passwd", "/etc/shadow", "/proc/"]
    CRLF_KEYWORDS = ["%0d%0a", "%0a", "%0d", "\r\n", "content-type:"]

    if any(k in combined or k in combined_decoded for k in SQL_KEYWORDS):
        return ("SQL Injection", config.FALLBACK_SCORE_SQLI)

    if any(k in combined or k in combined_decoded for k in XSS_KEYWORDS):
        return ("XSS", config.FALLBACK_SCORE_XSS)

    if any(k in combined or k in combined_decoded for k in TRAVERSAL_KEYWORDS):
        return ("File Disclosure", config.FALLBACK_SCORE_TRAVERSAL)

    if any(k in combined or k in combined_decoded for k in CRLF_KEYWORDS):
        return ("CRLF Injection", config.FALLBACK_SCORE_CRLF)

    if len(raw_payload) > config.BUFFER_OVERFLOW_PAYLOAD_THRESHOLD:
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

def run_pipeline(request_data: dict, skip_rules: bool = False) -> dict:
    """
    Public interface for the full classification pipeline.
    Used by both the background worker (app/logger.py) and the /classify
    API endpoint (app/api.py).

    Fix 3: no early returns — every request runs all three stages and each
    stage produces a separate signal. One final label is chosen by priority:
        a) HTTP Flood / Web Brute Force from rules — behavior attacks a
           payload scan cannot see, so the rule label is final.
        b) A payload label from ML or fallback — beats Directory
           Enumeration (a real attack payload is more specific evidence
           than a path-counting signal).
        c) Directory Enumeration from rules.
        d) Normal.
    Fix 4: within (b), high-confidence ML overrides the keyword fallback —
    the fallback is the safety net (used when model.pkl is missing, the ML
    confidence is below ML_CONFIDENCE_THRESHOLD, or ML raises), not the
    main classifier. Disagreements stay visible in the signals line.
    threat_score is the HIGHEST score among the signals that fired. A
    missing or failing model.pkl never crashes the pipeline.

    Args:
        request_data: dict with keys — source_ip, method, path, payload, etc.
        skip_rules: If True, skip rate-based rules to avoid polluting
                    in-memory counters (used by /classify endpoint).

    Returns:
        dict with keys: attack_type, threat_score, confidence, layer, report
    """
    # 1. Rule layer (rate-based detection)
    rule_label, rule_score = "Normal", 0
    confidence = 0.0
    if not skip_rules:
        rule_label, rule_score = _check_rules(request_data)

    # 2. Fallback (keyword-based detection) — always runs
    fb_label, fb_score = _quick_classify(request_data)

    # 3. ML layer — always attempted; failures are a signal, never a crash.
    #    (First call lazily loads model.pkl.) Below-threshold predictions
    #    stay visible in the signals line but never decide.
    ml_label, ml_score, ml_confidence, ml_raw = "Normal", 0, 0.0, "Normal"
    try:
        ml_raw, ml_confidence = classify_request(request_data)
        if ml_raw != "Normal" and ml_confidence >= config.ML_CONFIDENCE_THRESHOLD:
            ml_label = ml_raw
            ml_score = int(ml_confidence * config.THREAT_SCORE_ML_MULTIPLIER)
    except Exception:
        ml_raw, ml_confidence = "Normal", 0.0

    # ML signal text: not loaded / fired with confidence / fired below threshold
    if not _model_loaded:
        ml_txt = "not loaded"
    elif ml_label != "Normal":
        ml_txt = f"{ml_label} ({ml_confidence:.2f})"
    elif ml_raw != "Normal":
        ml_txt = f"{ml_raw} ({ml_confidence:.2f}, below threshold)"
    else:
        ml_txt = "Normal"

    # Payload signal — Fix 4: high-confidence ML overrides the keyword
    # fallback; the fallback is only the safety net. When both fired and
    # disagree, ML wins and the disagreement stays visible in the signals.
    if ml_label != "Normal":
        payload_label, payload_layer = ml_label, "ml"
    elif fb_label != "Normal":
        payload_label, payload_layer = fb_label, "fallback"
    else:
        payload_label = None

    # Final label priority (a)–(d)
    if rule_label in ("HTTP Flood", "Web Brute Force"):
        attack_type, layer, decider = rule_label, "rule", "rule"
    elif payload_label:
        attack_type, layer, decider = payload_label, payload_layer, payload_layer
        if payload_layer == "ml":
            confidence = ml_confidence
    elif rule_label != "Normal":
        attack_type, layer, decider = rule_label, "rule", "rule"
    else:
        attack_type, layer, decider = "Normal", None, "none"

    # Highest score among the signals that fired (all are 0 when nothing fired)
    threat_score = max(rule_score, fb_score, ml_score)

    # 4. Report generation — every layer's signal stays visible for forensics
    rule_txt = "skipped" if skip_rules else rule_label

    report = _generate_report(attack_type, threat_score, layer, confidence, request_data)
    report += (
        f" | Signals — rule: {rule_txt}, fallback: {fb_label}, "
        f"ml: {ml_txt}, final: {attack_type}, decided by: {decider}"
    )

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
    Called from app/logger.py's _background_worker(), NOT from _check_rules()
    — avoids adding cleanup cost to the per-request hot path.
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

# --- ML layer ------------------------------------------------------------

_model = None
_label_encoder = None
_model_loaded = False
_load_attempted = False

def load_model() -> bool:
    """
    Load model.pkl and LabelEncoder from disk into module-level variables.
    Fails gracefully if the model asset has not been compiled yet.
    """
    global _model, _label_encoder, _model_loaded, _load_attempted

    if _load_attempted:
        return _model_loaded

    _load_attempted = True

    if not os.path.exists(config.MODEL_PATH):
        print(
            f"[WRAITH] model.pkl not found at {config.MODEL_PATH} - "
            f"ML layer disabled, running on rule + fallback only."
        )
        _model_loaded = False
        return False

    try:
        with open(config.MODEL_PATH, "rb") as f:
            data = pickle.load(f)
        _model = data["model"]
        _label_encoder = data["label_encoder"]
        _model_loaded = True
        print(f"[WRAITH] ML model loaded successfully from {config.MODEL_PATH}")
    except Exception as e:
        print(f"[WRAITH ERROR] Failed to deserialize ML model bundle: {e}")
        _model_loaded = False

    return _model_loaded

def extract_features(request_data: dict) -> list:
    """
    Extract 8 mathematical HTTP features from request dict.
    Feature order is permanently locked to preserve training array alignment.
    """
    path = request_data.get("path", "/")
    payload = request_data.get("payload", "")
    method = request_data.get("method", "GET")
    user_agent = request_data.get("user_agent", "")
    query_string = request_data.get("query_string", "")

    full_url = path + ("?" + query_string if query_string else "")
    url_length = float(len(full_url))
    payload_length = float(len(payload))

    payload_entropy = 0.0
    if payload:
        char_counts = {}
        for char in payload:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p = count / len(payload)
            payload_entropy -= p * math.log2(p)

    combined_text = full_url + " " + payload

    non_alphanum = sum(1 for c in payload if not c.isalnum() and not c.isspace())
    non_alphanum_ratio = float(non_alphanum) / len(payload) if payload else 0.0

    url_encoded_count = float(len(re.findall(r'%[0-9A-Fa-f]{2}', combined_text)))
    path_depth = float(path.count('/'))
    method_is_post = 1.0 if method.upper() == "POST" else 0.0
    user_agent_length = float(len(user_agent))

    return [
        url_length,
        payload_length,
        payload_entropy,
        non_alphanum_ratio,
        url_encoded_count,
        path_depth,
        method_is_post,
        user_agent_length
    ]

def classify_request(request_data: dict) -> tuple:
    """
    Run multi-class machine learning inference against production requests.
    """
    if not _load_attempted:
        load_model()

    if not _model_loaded:
        return ("Normal", 0.0)

    try:
        features = extract_features(request_data)
        probabilities = _model.predict_proba([features])[0]
        max_prob_idx = probabilities.argmax()
        confidence = float(probabilities[max_prob_idx])

        predicted_label_encoded = _model.classes_[max_prob_idx]
        predicted_label = _label_encoder.inverse_transform([predicted_label_encoded])[0]

        return (str(predicted_label), confidence)
    except Exception as e:
        print(f"[WRAITH ERROR] ML classification failed: {e}")
        return ("Normal", 0.0)
