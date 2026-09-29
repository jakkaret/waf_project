"""
Gen 3 serving model: LightGBM on feature set F.

F = the 36 structural features of ml/feature_engineering.py minus five request-
shape features that mostly identify the source dataset, plus the 17 value-level
detector features of ml/value_features.py (48 columns). Chosen on 28/09/2026 by
ml/experiment_value_features.py (configuration "E_plus_query_body_entropy"):
best of all configurations on promotion gate 3.1-G.0 (3 of 5 criteria passed;
see PROGRESS_GEN3_CHECKPOINT.md).

This module is the single definition of F and of how a request is scored, so
training (ml/train_final_gen3.py), the experiments and serving (ml/ml_api.py
/predict-gen3) cannot drift apart. It needs libinjection (requirements-train.txt).
"""

from urllib.parse import urlsplit

import numpy as np

from ml.canonical import canonical_features
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS
from ml.value_features import VALUE_FEATURE_COLUMNS, extract_value_features

# Request-shape features dropped from F (dataset fingerprints; query_body_entropy
# is kept because putting it back improved every robustness metric).
F_DROPPED_CONTEXT_COLUMNS = ["url_path_entropy", "avg_param_length", "max_param_length", "path_depth", "param_count"]
# Column order is part of the model contract: identical to the experiment's
# E_plus_query_body_entropy configuration.
FEATURE_SET_F = ([c for c in EXTENDED_FEATURE_COLUMNS if c not in F_DROPPED_CONTEXT_COLUMNS + ["query_body_entropy"]]
                 + VALUE_FEATURE_COLUMNS + ["query_body_entropy"])
# "-canon": features are computed on the canonical request (ml/canonical.py).
# A model trained on the raw form (gen3-F-2026-09-28) must not be served with
# this code: Gen3FModel / Gen3OnnxModel refuse a different version.
FEATURE_SET_VERSION = "gen3-F-2026-09-29-canon"


def request_features(method="GET", url="/", body=""):
    """All F features of one request, as {name: value}, from its canonical form."""
    parts = urlsplit(url)
    feats, (path, query, body) = canonical_features(method, parts.path or "/", parts.query, body)
    feats.update(extract_value_features(method, path, query, body))
    return feats


class Gen3FModel:
    """A fitted LightGBM on FEATURE_SET_F plus its decision threshold and model card."""

    runtime = "joblib"  # ml/gen3_onnx.Gen3OnnxModel is the onnxruntime counterpart

    def __init__(self, model, threshold, columns=None, card=None):
        self.model = model
        self.threshold = float(threshold)
        self.columns = list(columns or FEATURE_SET_F)
        self.card = dict(card or {})
        if self.columns != FEATURE_SET_F:
            raise ValueError("model columns differ from FEATURE_SET_F; retrain or pin the matching code version")

    def matrix(self, requests):
        """(method, url, body) tuples -> float32 matrix in model column order (features computed once per request)."""
        rows = []
        for m, u, b in requests:
            feats = request_features(m, u, b)
            rows.append([feats[c] for c in self.columns])
        return np.array(rows, dtype=np.float32)

    def score_request(self, method="GET", url="/", body=""):
        """Attack probability of one request.

        Uses the LightGBM booster directly: same probability as predict_proba,
        without sklearn's per-call input validation (~0.6 ms of a ~0.3 ms request).
        """
        return float(self.model.booster_.predict(self.matrix([(method, url, body)]))[0])

    def predict(self, method="GET", url="/", body=""):
        p = self.score_request(method, url, body)
        return {"attack_probability": round(p, 4), "is_attack": p >= self.threshold,
                "threshold": round(self.threshold, 4), "feature_set": FEATURE_SET_VERSION}
