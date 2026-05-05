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
        Index 0 — url_length : int — len(path)
        Index 1 — payload_length : int — len(payload body)
        Index 2 — payload_entropy : float — Shannon entropy of payload
        Index 3 — non_alphanum_ratio : float — special chars / total chars
        Index 4 — url_encoded_count : int — count of %XX in path
        Index 5 — path_depth : int — path.count('/')
        Index 6 — method_is_post : int — 1 if POST else 0
        Index 7 — user_agent_length : int — len(User-Agent header)

    Week 1: Returns 8 Zeros — placeholder.
    Week 3: Full implementation with Shannon entropy calculation.

    Returns:
        List of 8 numeric features in the order above
    """

    return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

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
        attack_type is one of config.ML_ATTACK_TYPES or 'Normal'
        confidence is 0.0 to 1.0 — used by logger.py to compute threat_score

    Week 1: Always returns ('Normal', 0.0).
    Week 3: extract_features() -> model.predict_proba() -> label_encoder.
    """
    if not _load_attempted:
        load_model()
        
    if not _model_loaded:
        return ("Normal", 0.0)

    # TODO (Week 3): Run inference here
    # features = extract_features(request_data)
    # prediction = _model.predict_proba([features])
    # ...
    return ("Normal", 0.0)  # Placeholder until Week 3