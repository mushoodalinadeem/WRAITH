"""
ml/evaluate.py — Full evaluation of the trained WRAITH Random Forest model.

Loads model.pkl, recreates the identical test split from training,
and produces a complete forensic performance report.

Usage:
    cd ~/Documants/WRAITH
    source venv/bin/activate
    python3 ml/evaluate.py

Output:
    - Overall accuracy
    - Per-class precision, recall, F1-scorce, support
    - Confusion matrix with class name lables
    - Feature importance ranking
    - Per-class confidence distribution
"""

import os
import sys
import pickle
import warnings

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from ml.train import _load_csic, _load_payloads, FEATURE_NAMES


def _load_model() -> tuple:
    """
    Load trained model and LabelEncoder from model.pkl.
    Exits with clear message if model not found.

    Returns:
        (RandomForestClassifier, LabelEncoder)
    """
    if not os.path.exists(config.MODEL_PATH):
        print(f"[EVAL] model.pkl not found at {config.MODEL_PATH}")
        print(f"[EVAL] Run: python3 ml/train.py")
        sys.exit(1)

    with open(config.MODEL_PATH, "rb") as f:
        saved = pickle.load(f)

    print(f"[EVAL] Model loaded: {config.MODEL_PATH}")
    print(f"[EVAL] Classes: {saved['classes']}\n")
    return saved["model"], saved["label_encoder"]

def _get_test_data(le) -> tuple:
    """
    Recreate the exact test split used during training.
    Identical random_state=42 + stratify=y produces the same split.

    Args:
        le: Fitted LabelEncoder from model.pkl

    Returns:
        (X_test: np.ndarray, y_test: np.ndarray)
    """
    print("[EVAL] Recreating test split from datasets...")
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    csic_path = os.path.join(data_dir, "csic_database.csv")
    payload_train = os.path.join(data_dir, "payload_train.csv")
    payload_test = os.path.join(data_dir, "payload_test.csv")

    df_csic = _load_csic(csic_path)
    df_payload = _load_payloads(payload_train, payload_test)
    df = pd.concat([df_csic, df_payload], ignore_index=True).dropna()
    known_labels = set(le.classes_)
    df = df[df["attack_type"].isin(known_labels)]

    y = le.transform(df["attack_type"])
    X = df[FEATURE_NAMES].values.astype(float)

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[EVAL] Test set: {len(X_test)} rows\n")
    return X_test, y_test


def _print_confusion_matrix(cm: np.ndarray, class_names: list) -> None:
    """
    print confusion matrix as a formatted table.
    Rows = actual class, Columns = predicted class.
    Diagonal = correct predictions.
    """
    col_width = max(len(name) for name in class_names) + 2

    print(" predicted →")
    header_row = f" {'Actual ↓':<{col_width}}"
    for name in class_names:
        header_row += name[:col_width - 1].ljust(col_width)
    print(header_row)
    print(" " + "-" * (col_width * (len(class_names) + 1)))

    for i, row_name in enumerate(class_names):
        row = f" {row_name:<{col_width}}"
        for j, val in enumerate(cm[i]):
            cell = f"[{val}]" if i == j else str(val)
            row += cell.ljust(col_width)
        print(row)
    print()


def _analyze_confidence(model, X_test: np.ndarray,
                        y_test: np.ndarray, class_names: list) -> None:
    """
    Show average, min, max confidence per predicted class.
    Flags classes below ML_CONFIDENCE_THRESHOLD — those will be 
    silently passed to the fallback layer in production.
    """
    probas = model.predict_proba(X_test)
    Y_pred = model.classes_[probas.argmax(axis=1)]
    threshold = config.ML_CONFIDENCE_THRESHOLD

    print("[EVAL] === Confidence Distribution per Class ===")
    print(f"[EVAL] ML_CONFIDENCE_THRESHOLD = {threshold}")
    print(f"[EVAL] Predictions below {threshold:.0%} are passed to fallback layer\n")

    for i, name in enumerate(class_names):
        class_idx = model.classes_[i]
        mask = (Y_pred == class_idx)
        if mask.sum() == 0:
            print(f"  {name:<22} No predictions made")
            continue
        correct_mask = (y_test[mask] == class_idx)
        avg_conf = probas[mask, i].mean()
        min_conf = probas[mask, i].min()
        max_conf = probas[mask, i].max()
        flag = " ⚠ avg below threshold" if avg_conf < threshold else ""
        print(
            f"  {name:<22} "
            f"avg={avg_conf:.3f}  "
            f"min={min_conf:.3f}  "
            f"max={max_conf:.3f}"
            f"{flag}"
        )
    print()


def evaluate() -> None:
    """
    Full evaluation pipeline. Prints complete performance report.
    """
    print("\n" + "=" * 60)
    print("  WRAITH — ML Model Evaluation Report")
    print("=" * 60 + "\n")

    model, le = _load_model()
    class_names = list(le.classes_)

    X_test, y_test = _get_test_data(le)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"[EVAL] Overall Accuracy: {accuracy:.4f} ({accuracy * 100:.2f}%)\n")

    print("[EVAL] === Per-Class Performance ===")
    print(classification_report(
        y_test, y_pred,
        target_names=class_names,
        zero_division=0
    ))

    print("[EVAL] === Confusion Matrix ===")
    cm = confusion_matrix(y_test, y_pred)
    _print_confusion_matrix(cm, class_names)

    print("[EVAL] === Feature Importance (sorted by importance) ===")
    importances = model.feature_importances_
    for name, imp in sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda x: x[1], reverse=True
    ):
        bar = "█" * int(imp *50)
        print(f" {name:<22} {imp:.4f} {bar}")
        print()

    _analyze_confidence(model, X_test, y_test, class_names)

    print("[EVAL] === Summary ===")
    report = classification_report(
        y_test, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )
    macro = report["macro avg"]
    print(f" Accuracy : {accuracy * 100:.2f}%")
    print(f" Macro Precision: {macro['precision'] * 100:.2f}%")
    print(f" Macro Recall: {macro['recall'] * 100:.2f}%")
    print(f" Macro F1-Score: {macro['f1-score'] * 100:.2f}%")
    print(f" Test samples: {len(X_test)}")
    print(f" Classes: {len(class_names)}")
    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    evaluate()