"""
ml/train.py — WRAITH ML training pipeline.

Loads and combines the CSIC 2010 and HttpParams datasets using
direct application code imports to guarantee absolute feature parity.
"""

import os
import sys
import pickle
import warnings
from urllib.parse import urlparse, unquote_plus

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

warnings.filterwarnings("ignore")

# Force injection of project root into ecosystem execution paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from app.classifier import extract_features  # Imports live production math directly

LABEL_MAP = {
    "norm":           "Normal",
    "sqli":           "SQL Injection",
    "xss":            "XSS",
    "path-traversal": "File Disclosure",
}

FEATURE_NAMES = [
    "url_length",
    "payload_length",
    "payload_entropy",
    "non_alphanum_ratio",
    "url_encoded_count",
    "path_depth",
    "method_is_post",
    "user_agent_length",
]

def _auto_label_csic(content: str, raw_url: str) -> str:
    """Heuristic keyword matching pipeline to map labels onto CSIC anomalies."""
    text = unquote_plus(str(content or "")).lower()
    text += " " + unquote_plus(str(raw_url or "")).lower()

    if any(k in text for k in ["../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/", ".git/", "~"]):
        return "File Disclosure"
    if any(k in text for k in ["select ", "union ", "drop ", "insert ", "waitfor", "' or ", "1=1", "--", "xp_", "exec(", "cast(", "sleep("]):
        return "SQL Injection"
    if any(k in text for k in ["<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie", "document.location"]):
        return "XSS"
    if any(k in text for k in ["\r\n", "set-cookie:", "%0d%0a", "content-type:"]):
        return "CRLF Injection"
    return "SQL Injection"

def _load_csic(path: str) -> pd.DataFrame:
    print(f"[TRAIN] Processing CSIC dataset from {path}")
    df = pd.read_csv(path)

    rows = []
    for _, row in df.iterrows():
        method = str(row.get("Method", "GET") or "GET").upper()
        user_agent = str(row.get("User-Agent", "") or "")
        content = str(row.get("content", "") or "") if pd.notna(row.get("content")) else ""
        raw_url = str(row.get("URL", "/") or "/")
        label_raw = row.get("classification", 0)

        # Retain query string segments during data parsing to support parameter extraction parity
        try:
            clean_url = raw_url.split(" ")[0]
            parsed_url = urlparse(clean_url)
            url_path = parsed_url.path or "/"
            query_string = parsed_url.query or ""
        except Exception:
            url_path, query_string = "/", ""

        attack_type = "Normal" if label_raw == 0 else _auto_label_csic(content, raw_url)
        
        request_data = {
            "path": url_path,
            "query_string": query_string,
            "payload": content,
            "method": method,
            "user_agent": user_agent
        }
        features = extract_features(request_data)
        rows.append(features + [attack_type])

    return pd.DataFrame(rows, columns=FEATURE_NAMES + ["attack_type"])

def _load_payloads(train_path: str, test_path: str) -> pd.DataFrame:
    print(f"[TRAIN] Processing payload datasets...")
    df = pd.concat([pd.read_csv(train_path), pd.read_csv(test_path)], ignore_index=True)

    # Context Homogenization: Neutralize metadata footprints across raw payload sets 
    # to force the Forest to analyze the actual properties of the attack string.
    UNIFIED_PATH = "/api/data"
    UNIFIED_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    UNIFIED_METHOD = "POST"

    rows = []
    for _, row in df.iterrows():
        payload = str(row.get("payload", "") or "")
        label_raw = str(row.get("attack_type", "norm"))
        
        if label_raw == "cmdi":
            continue # Drop command injection payloads completely to prevent taxonomy pollution

        attack_type = LABEL_MAP.get(label_raw, "Normal")

        request_data = {
            "path": UNIFIED_PATH,
            "query_string": "",
            "payload": payload,
            "method": UNIFIED_METHOD,
            "user_agent": UNIFIED_UA
        }
        features = extract_features(request_data)
        rows.append(features + [attack_type])

    return pd.DataFrame(rows, columns=FEATURE_NAMES + ["attack_type"])

def train():
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    df_csic = _load_csic(os.path.join(data_dir, "csic_database.csv"))
    df_payload = _load_payloads(os.path.join(data_dir, "payload_train.csv"), os.path.join(data_dir, "payload_test.csv"))
    
    df = pd.concat([df_csic, df_payload], ignore_index=True).dropna()

    print(f"\n[TRAIN] Combined matrix balance:\n{df['attack_type'].value_counts()}\n")

    le = LabelEncoder()
    y = le.fit_transform(df["attack_type"])
    X = df[FEATURE_NAMES].values.astype(float)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[TRAIN] Training Random Forest Classifier (Balanced Weights)...")
    rf = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    print("\n[TRAIN] === Parity Evaluation Matrix ===")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    print("[TRAIN] === Aligned Feature Importance ===")
    for name, importance in sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: x[1], reverse=True):
        print(f"  {name:<22} {importance:.4f}")

    os.makedirs(os.path.dirname(config.MODEL_PATH), exist_ok=True)
    saved = {
        "model": rf,
        "label_encoder": le,
        "feature_names": FEATURE_NAMES,
        "classes": list(le.classes_)
    }
    with open(config.MODEL_PATH, "wb") as f:
        pickle.dump(saved, f)

    print(f"\n[TRAIN] Model serialized cleanly to → {config.MODEL_PATH}")

if __name__ == "__main__":
    train()
