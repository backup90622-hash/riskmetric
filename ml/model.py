#!/usr/bin/env python3
"""
model.py — Breach Intel ML Scoring Engine
RandomForest (200 trees) + IsolationForest + SHAP TreeExplainer
Reads normalised feature vector from stdin (JSON).
Outputs { score, risk_level, factors, shap_factors } to stdout (JSON).
HARD RULE: all-zero feature vector → score 0 / NO EXPOSURE (never use model).
"""

import sys
import json
import os
import math
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

MODEL_DIR  = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "breach_rf_model.joblib")
ISO_PATH   = os.path.join(MODEL_DIR, "isolation_forest.joblib")

FEATURE_NAMES = [
    "breach_norm", "password_norm", "severity_norm", "critical_norm",
    "recent_norm", "login_anomaly_score", "public_exposure",
    "social_risk_score", "has_password_breach",
]

CENTROIDS = {"low": 18, "medium": 52, "high": 86}


def is_zero_vector(feature_vec):
    """Return True if ALL breach-related features are zero — truly unexposed."""
    # Primary breach signals: breach_norm, password_norm, severity_norm, critical_norm
    key_indices = [0, 1, 2, 3, 8]  # breach, password, severity, critical, has_password
    return all(feature_vec[i] == 0.0 for i in key_indices)


def zero_result():
    return {
        "score": 0,
        "risk_level": "NO EXPOSURE",
        "factors": [
            {"icon": "🔑", "name": "PASSWORD LEAKS",  "score": 0, "barColor": "var(--accent-red)"},
            {"icon": "💀", "name": "BREACH SEVERITY", "score": 0, "barColor": "var(--accent-orange)"},
            {"icon": "🔁", "name": "EXPOSURE COUNT",  "score": 0, "barColor": "var(--accent-yellow)"},
            {"icon": "⚡", "name": "RECENT BREACHES", "score": 0, "barColor": "var(--accent-cyan)"},
            {"icon": "🌐", "name": "PUBLIC EXPOSURE", "score": 0, "barColor": "var(--accent-blue)"},
        ],
        "shap_factors": [],
        "proba": {"low": 1.0, "medium": 0.0, "high": 0.0},
    }


def generate_training_data():
    np.random.seed(42)
    X, y = [], []
    # LOW RISK (120) — small but NON-ZERO breach signals
    for _ in range(120):
        row = [
            np.random.uniform(0.01, 0.20),
            np.random.uniform(0.00, 0.15),
            np.random.uniform(0.00, 0.40),
            np.random.uniform(0.00, 0.10),
            np.random.uniform(0.00, 0.15),
            np.random.uniform(0.01, 0.30),
            np.random.uniform(0.01, 0.25),
            np.random.uniform(0.01, 0.35),
            0.0,
        ]
        X.append(row); y.append("low")
    # MEDIUM RISK (100)
    for _ in range(100):
        row = [
            np.random.uniform(0.15, 0.50),
            np.random.uniform(0.10, 0.45),
            np.random.uniform(0.30, 0.70),
            np.random.uniform(0.05, 0.30),
            np.random.uniform(0.10, 0.40),
            np.random.uniform(0.25, 0.60),
            np.random.uniform(0.20, 0.55),
            np.random.uniform(0.30, 0.60),
            float(np.random.choice([0, 1], p=[0.4, 0.6])),
        ]
        X.append(row); y.append("medium")
    # HIGH RISK (80)
    for _ in range(80):
        row = [
            np.random.uniform(0.40, 1.00),
            np.random.uniform(0.35, 1.00),
            np.random.uniform(0.60, 1.00),
            np.random.uniform(0.20, 1.00),
            np.random.uniform(0.25, 1.00),
            np.random.uniform(0.50, 1.00),
            np.random.uniform(0.40, 1.00),
            np.random.uniform(0.50, 1.00),
            1.0,
        ]
        X.append(row); y.append("high")
    return np.array(X, dtype=np.float32), y


def get_or_train_models():
    if os.path.exists(MODEL_PATH) and os.path.exists(ISO_PATH):
        try:
            return joblib.load(MODEL_PATH), joblib.load(ISO_PATH)
        except Exception:
            pass
    X, y = generate_training_data()
    rf = RandomForestClassifier(n_estimators=200, max_depth=6, random_state=42,
                                class_weight="balanced", n_jobs=-1)
    rf.fit(X, y)
    iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    iso.fit(X)
    joblib.dump(rf, MODEL_PATH)
    joblib.dump(iso, ISO_PATH)
    return rf, iso


def compute_score(rf, iso, feature_vec):
    X = np.array([feature_vec], dtype=np.float32)
    proba = rf.predict_proba(X)[0]
    classes = list(rf.classes_)
    p = {c: 0.0 for c in ["low", "medium", "high"]}
    for cls, prob in zip(classes, proba):
        p[cls] = prob
    score = p["low"] * CENTROIDS["low"] + p["medium"] * CENTROIDS["medium"] + p["high"] * CENTROIDS["high"]
    iso_score = iso.score_samples(X)[0]
    if iso_score < -0.2:
        score += abs(iso_score) * 15
    return min(round(float(score)), 100), p


def compute_shap(rf, feature_vec):
    if not SHAP_AVAILABLE:
        return None
    try:
        explainer = shap.TreeExplainer(rf)
        X = np.array([feature_vec], dtype=np.float32)
        sv = explainer.shap_values(X)
        if isinstance(sv, list):
            classes = list(rf.classes_)
            idx = classes.index("high") if "high" in classes else -1
            shap_vals = sv[idx][0]
        else:
            shap_vals = sv[0]
        return dict(zip(FEATURE_NAMES, [float(v) * 100 for v in shap_vals]))
    except Exception as e:
        sys.stderr.write(f"[SHAP] Warning: {e}\n")
        return None


def factor_score(v):
    return min(int(round(float(v) * 10)), 10)


def build_factors(nf):
    return [
        {"icon": "🔑", "name": "PASSWORD LEAKS",  "score": factor_score(nf.get("password_norm", 0)),   "barColor": "var(--accent-red)"},
        {"icon": "💀", "name": "BREACH SEVERITY", "score": factor_score(nf.get("severity_norm", 0)),   "barColor": "var(--accent-orange)"},
        {"icon": "🔁", "name": "EXPOSURE COUNT",  "score": factor_score(nf.get("breach_norm", 0)),     "barColor": "var(--accent-yellow)"},
        {"icon": "⚡", "name": "RECENT BREACHES", "score": factor_score(nf.get("recent_norm", 0)),     "barColor": "var(--accent-cyan)"},
        {"icon": "🌐", "name": "PUBLIC EXPOSURE", "score": factor_score(nf.get("public_exposure", 0)), "barColor": "var(--accent-blue)"},
    ]


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"error": "Empty input"})); sys.exit(1)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"JSON parse error: {e}"})); sys.exit(1)

    nf = payload.get("normalized_features", payload)
    feature_vec = [float(nf.get(name, 0.0)) for name in FEATURE_NAMES]

    # ── HARD ZERO GATE ────────────────────────────────────────────────────────
    if is_zero_vector(feature_vec):
        print(json.dumps(zero_result()))
        sys.exit(0)

    # ── Pure Python fallback (no scikit-learn) ────────────────────────────────
    if not ML_AVAILABLE:
        danger = (feature_vec[0] * 0.30 + feature_vec[1] * 0.25
                + feature_vec[8] * 0.25 + feature_vec[2] * 0.20)
        score = min(max(int(round(danger * 86 + (1 - danger) * 18)), 5), 100)
        risk = "CRITICAL" if score >= 75 else "HIGH RISK" if score >= 50 else "MEDIUM" if score >= 25 else "LOW RISK"
        shap_factors = [{"label": f, "pts": int(abs(v * 20)), "pct": int(abs(v * 100))}
                        for f, v in zip(FEATURE_NAMES, feature_vec)]
        shap_factors.sort(key=lambda x: -x["pts"])
        print(json.dumps({"score": score, "risk_level": risk,
                          "factors": build_factors(nf), "shap_factors": shap_factors}))
        sys.exit(0)

    # ── Full ML path ──────────────────────────────────────────────────────────
    rf, iso = get_or_train_models()
    score, proba = compute_score(rf, iso, feature_vec)

    # Ensure minimum score of 5 for genuinely exposed emails
    if score < 5:
        score = 5

    risk = ("CRITICAL"  if score >= 75 else
            "HIGH RISK" if score >= 50 else
            "MEDIUM"    if score >= 25 else "LOW RISK")

    shap_dict = compute_shap(rf, feature_vec)
    if shap_dict:
        shap_factors = [{"label": k, "pts": max(int(round(v)), 0), "pct": int(min(abs(v), 100))}
                        for k, v in shap_dict.items()]
    else:
        shap_factors = [{"label": f, "pts": int(abs(v * 25)), "pct": int(abs(v * 100))}
                        for f, v in zip(FEATURE_NAMES, feature_vec)]
    shap_factors.sort(key=lambda x: -x["pts"])

    print(json.dumps({"score": score, "risk_level": risk,
                      "factors": build_factors(nf), "shap_factors": shap_factors,
                      "proba": {k: round(v, 4) for k, v in proba.items()}}))
    sys.exit(0)


if __name__ == "__main__":
    main()
