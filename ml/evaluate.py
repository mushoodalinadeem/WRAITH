"""
ml/evaluate.py — Evaluation script for WRAITH ML model.

Loads the compiled model bundle from disk, loads the test split of
the combined dataset, and runs performance metrics evaluation.
"""

import os
import sys
import pickle
import warnings
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

warnings.filterwarnings("ignore")

# Force injection of project root into ecosystem execution paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ml.train import _load_csic, _load_payloads, FEATURE_NAMES

def _load_model() -> tuple:
    """Loads the serialized model bundle from the configured path."""
    if not os.path.exists(config.MODEL_PATH):
        print(f"[EVAL ERROR] Compiled model not found at {config.MODEL_PATH}. Run 'python ml/train.py' first.")
        sys.exit(1)

    print(f"[EVAL] Loading compiled ML model bundle from {config.MODEL_PATH}...")
    with open(config.MODEL_PATH, "rb") as f:
        saved = pickle.load(f)
    return saved["model"], saved["label_encoder"], saved.get("feature_names", FEATURE_NAMES)

def _get_test_data(feature_names: list, le) -> tuple:
    """Loads CSIC and Payloads, computes features, and extracts the test split."""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    csic_path = os.path.join(data_dir, "csic_database.csv")
    payload_train = os.path.join(data_dir, "payload_train.csv")
    payload_test = os.path.join(data_dir, "payload_test.csv")

    if not all(os.path.exists(p) for p in [csic_path, payload_train, payload_test]):
        print("[EVAL ERROR] Datasets not found in ml/data/. Make sure CSV files are present.")
        sys.exit(1)

    df_csic = _load_csic(csic_path)
    df_payload = _load_payloads(payload_train, payload_test)
    df = pd.concat([df_csic, df_payload], ignore_index=True).dropna()

    # Filter out any unexpected/unseen labels before transformation
    known_labels = set(le.classes_)
    df = df[df["attack_type"].isin(known_labels)]

    y = le.transform(df["attack_type"])
    X = df[feature_names].values.astype(float)

    # Reconstruct the exact same test split using the identical seed
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    return X_test, y_test

def _print_confusion_matrix(cm: np.ndarray, class_names: list):
    """Prints the confusion matrix with alignment and highlighted diagonals."""
    col_width = max(len(c) for c in class_names) + 4
    header = f"{'Actual \\ Predicted':<{col_width}}" + "".join(f"{c:>{col_width}}" for c in class_names)
    print(header)
    print("-" * len(header))
    for i, row_name in enumerate(class_names):
        row = f"{row_name:<{col_width}}"
        for j, val in enumerate(cm[i]):
            cell = f"[{val}]" if i == j else str(val)
            row += f"{cell:>{col_width}}"
        print(row)

def _analyze_confidence(model, X_test: np.ndarray, y_test: np.ndarray, class_names: list):
    """Analyzes prediction confidence distribution per class."""
    print("[EVAL] === Confidence Distribution Analysis ===")
    probas = model.predict_proba(X_test)
    Y_pred = model.classes_[probas.argmax(axis=1)]

    for i, class_name in enumerate(class_names):
        class_idx = model.classes_[i]
        mask = (Y_pred == class_idx)
        total_pred = mask.sum()

        support = (y_test == class_idx).sum()

        if total_pred == 0:
            print(f"Class: {class_name} (Support: {support}) (No predictions)")
            continue

        correct_mask = (y_test[mask] == class_idx)
        correct_count = correct_mask.sum()
        acc = correct_count / total_pred if total_pred > 0 else 0.0

        confidences = probas[mask, i]
        avg_conf = confidences.mean()

        # Split confidences for correct vs incorrect predictions
        conf_correct = confidences[correct_mask]
        conf_incorrect = confidences[~correct_mask]

        avg_conf_correct = conf_correct.mean() if len(conf_correct) > 0 else 0.0
        avg_conf_incorrect = conf_incorrect.mean() if len(conf_incorrect) > 0 else 0.0

        print(f"Class: {class_name}")
        print(f"  Support (Actual Samples):          {support}")
        print(f"  Total Predictions:                 {total_pred} ({correct_count} correct, {total_pred - correct_count} incorrect)")
        print(f"  Precision/Accuracy on predictions: {acc:.2%}")
        print(f"  Avg Confidence (Overall):          {avg_conf:.4f}")
        print(f"  Avg Confidence (Correct):          {avg_conf_correct:.4f}")
        print(f"  Avg Confidence (Incorrect):        {avg_conf_incorrect:.4f}")

def evaluate() -> float:
    """Runs the full ML evaluation pipeline."""
    model, le, feature_names = _load_model()
    class_names = list(le.classes_)

    X_test, y_test = _get_test_data(feature_names, le)

    print(f"\n[EVAL] Running inference on validation test split ({len(X_test)} samples)...")
    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print("\n==================================================")
    print(" WRAITH ML Model Evaluation Results")
    print("==================================================")
    print(f"Overall Accuracy: {accuracy:.4%}")
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    print("--- Confusion Matrix ---")
    cm = confusion_matrix(y_test, y_pred)
    _print_confusion_matrix(cm, class_names)

    print("\n[EVAL] === Feature Importance ===")
    max_imp = max(model.feature_importances_)
    for name, imp in sorted(zip(feature_names, model.feature_importances_), key=lambda x: x[1], reverse=True):
        bar_len = int((imp / max_imp) * 20)
        bar = "█" * bar_len
        print(f"  {name:<22} {imp:.4f} {bar}")

    print()
    _analyze_confidence(model, X_test, y_test, class_names)
    print("==================================================\n")
    return accuracy

if __name__ == "__main__":
    evaluate()
