"""
app/classifier.py — ML classification layer for WRAITH.

Week 1 STATUS: STUB — correct signatures, no ML logic yet.
Week 2: Feature extraction functions implemented.
Week 3: RandomForest loaded from model.pkl, full inference pipeline.

Called by logger.py background worker AFTER:
    1. Rule layer (_check_rules)
    2. Fallback (_quick_classify)

Returns: (attack_type: str, confidence: float)
logger.py computes threat_score from confidence using config.THREAT_SCORE_ML_MULTIPLIER.
"""

import config
import os
import math
import re

_model = None
_label_encoder = None
_model_loaded = False
_load_attempted = False

def load_model() -> bool:
    """
    Load model.pkl and LabelEncoder from disk into module-level variables.
    Safe to call if model.pkl does not exist — returns False gracefully.

    Week 1: Always returns False (model not trained yet).
    Week 3: Loads RandomForest + LabelEncoder via pickle.

    Returns:
        True if model loaded successfully, False otherwise
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

    # TODO (Week 3): Implement pickle loading of RandomForest + LabelEncoder
    _model_loaded = False
    return False

def extract_features(request_data: dict) -> list:
    """
    Extract 8 mathematical HTTP features from request dict.
    Feature order is LOCKED — must match training data column order exactly.

    Features:
        Index 0 — url_length
        Index 1 — payload_length
        Index 2 — payload_entropy (Shannon entropy)
        Index 3 — non_alphanum_ratio
        Index 4 — url_encoded_count (%XX hex sequences via regex)
        Index 5 — path_depth
        Index 6 — method_is_post
        Index 7 — user_agent_length

    Week 2: Fully implemented — all 8 features extracted mathematically.

    Returns:
        List of 8 numeric features in the order above
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
    Run ML classification on a single request.

    Position in pipeline (logger.py):
        Rule layer -> quick_classify() -> THIS FUNCTION

    Only reached if both rule layer and fallback returned 'Normal'.
    Returns ('Normal', 0.0) immediately if model is not loaded.

    Args:
        request_data: dict with keys — path, payload, method,
                      user_agent, headers, source_ip, timestamp

    Returns:
        (attack_type: str, confidence: float)

    Week 2: Feature extraction is active (extract_features() computes
             all 8 mathematical features). Inference is stubbed until
             Week 3 when model.pkl is trained and loaded.
    """
    if not _load_attempted:
        load_model()
        
    if not _model_loaded:
        return ("Normal", 0.0)

    # TODO (Week 3): Run inference here
    features = extract_features(request_data)
    # prediction = _model.predict_proba([features])
    # ...
    return ("Normal", 0.0)  # Placeholder until Week 3