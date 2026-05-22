"""
app/classifier.py — ML classification layer for WRAITH.

Deserializes the compiled Random Forest binary array via pickle and
executes multi-class matrix evaluation on incoming request signatures.
"""

import config
import os
import math
import re
import pickle

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
    # Extract raw values
    path = request_data.get("path", "/")
    payload = request_data.get("payload", "")
    method = request_data.get("method", "GET")
    user_agent = request_data.get("user_agent", "")
    query_string = request_data.get("query_string", "")

    # Neutralize path name and user agent to eliminate proxy variable bias and training-serving skew.
    # This ensures the model classifies based on payload content and query string presence/length
    # rather than specific directory/path names or client software footprints.
    neutral_path = "/api/data"
    neutral_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    full_url = neutral_path + ("?" + query_string if query_string else "")
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
    path_depth = float(neutral_path.count('/'))
    method_is_post = 1.0 if method.upper() == "POST" else 0.0
    user_agent_length = float(len(neutral_ua))

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