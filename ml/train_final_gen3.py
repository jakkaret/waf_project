#!/usr/bin/env python3
"""
Train the Gen 3 serving model (feature set F, ml/gen3_model.py) on ALL data.

The experiments (ml/experiment_value_features.py) hold data back to measure the
model; this script builds the model to deploy once the feature set is chosen:

1. Same dataset as the experiments (build_full_real_dataset + value features),
   same LightGBM hyperparameters (latest archived candidate).
2. Threshold from 5-fold group-level out-of-fold scores over all data: the
   lowest threshold at which EVERY dataset keeps at least --benign-target of its
   benign traffic (default 99%, a margin over the 98.5% of gate G1 because a
   threshold set exactly at the target lands on either side of it on new data).
3. Out-of-fold benign / attack recall per dataset at that threshold (honest
   estimates of G1 / G2 for this model), the 63 scenarios, single-request latency.
4. Final fit on all rows; saves gen3_f_model.joblib (Gen3FModel) and
   model_card.json (inputs with sha256, code hashes, git commit, metrics) to
   ml/models/archive/gen3-final-f-<timestamp>/.

Unseen-dataset recall (gate G3/G4) and the stress test are properties of the
feature set measured by the experiment; the card cites that report.

Not for production enforcement: gate 3.1-G.0 is not passed (3/5). Use for demos
and shadow scoring (ml_api.py /predict-gen3) only.
"""

import argparse
import glob
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.experiment_value_features import latest_hyperparameters, value_feature_frame  # noqa: E402
from ml.gen3_model import FEATURE_SET_F, FEATURE_SET_VERSION, Gen3FModel  # noqa: E402
from ml.promotion_gate import GATE, dataset_of  # noqa: E402
from ml.test_comprehensive import TESTS  # noqa: E402
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, CSIC_PATH, EXTERNAL_SOURCES, NGINX_BENIGN_PATH, TELEMETRY_DIR, VPS_AUDIT_PATH, _sha256_file,
    build_full_real_dataset, group_folds, weighted_recalls,
)

ML_DIR = os.path.dirname(os.path.abspath(__file__))
REFERENCE_EXPERIMENT = "experiment-value-features-20260928-144424"  # gate v2 run that selected F


def benign_threshold(p_benign, w_benign, target):
    """Lowest t with weighted benign recall (score < t) >= target."""
    order = np.argsort(-p_benign, kind="stable")
    pb, wb = p_benign[order], w_benign[order]
    above = np.cumsum(wb) / wb.sum()
    k = int(np.searchsorted(above, (1.0 - target) + 1e-12, side="right"))
    return 0.0 if k >= len(pb) else float(np.nextafter(pb[k], np.inf))


def per_dataset(y, p, w, datasets, threshold):
    out = {}
    for d in sorted(set(datasets)):
        m = datasets == d
        r = weighted_recalls(y[m], (p[m] >= threshold).astype(int), w[m])
        out[d] = {k: r[k] for k in ("benign_recall", "benign_shapes", "attack_recall", "attack_shapes")}
    return out


def git_commit():
    try:
        return subprocess.check_output(["git", "-C", ML_DIR, "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--benign-target", type=float, default=0.99,
                    help="benign recall every dataset must keep at the threshold (gate G1 is 0.985)")
    args = ap.parse_args()

    X, y, _, integrity, meta = build_full_real_dataset()
    V = value_feature_frame(meta)
    F = pd.concat([X.reset_index(drop=True).astype(np.float32), V], axis=1)[FEATURE_SET_F].to_numpy(dtype=np.float32)
    yv, w = y.to_numpy(), meta["Weight"].to_numpy()
    datasets = meta["Source"].map(dataset_of).to_numpy()
    params, params_from = latest_hyperparameters()
    print(f"[*] {len(yv)} rows, {len(FEATURE_SET_F)} features ({FEATURE_SET_VERSION}); params from {params_from}")

    # 1. out-of-fold scores over all data
    t0 = time.time()
    oof = np.zeros(len(yv))
    for fold, (fit, val) in enumerate(group_folds(meta), 1):
        oof[val] = lgb.LGBMClassifier(**params).fit(F[fit], yv[fit], sample_weight=w[fit]).predict_proba(F[val])[:, 1]
        print(f"  OOF fold {fold}/5 done [{time.time()-t0:.0f}s]", flush=True)

    # 2. threshold: every dataset keeps --benign-target of its benign traffic
    per_ds_thr = {d: benign_threshold(oof[(datasets == d) & (yv == 0)], w[(datasets == d) & (yv == 0)], args.benign_target)
                  for d in sorted(set(datasets)) if ((datasets == d) & (yv == 0)).any()}
    threshold = max(per_ds_thr.values())
    oof_by_ds = per_dataset(yv, oof, w, datasets, threshold)
    known = [r["attack_recall"] for r in oof_by_ds.values() if r["attack_recall"] is not None]
    benign = [r["benign_recall"] for r in oof_by_ds.values() if r["benign_recall"] is not None]
    print(f"[*] Threshold {threshold:.4f} (binding: {max(per_ds_thr, key=per_ds_thr.get)}; per dataset {per_ds_thr})")
    for d, r in oof_by_ds.items():
        print(f"    OOF {d:20s} benign {r['benign_recall']} | attack {r['attack_recall']}")
    print(f"    G1-style min benign {min(benign):.4f} (gate {GATE['benign_min']}) | "
          f"G2-style mean attack {np.mean(known):.4f} (gate {GATE['known_attack_mean']})")

    # 3. final fit on all rows
    model = lgb.LGBMClassifier(**params).fit(F, yv, sample_weight=w)
    wrapper = Gen3FModel(model, threshold)

    blocked = [(exp, desc) for exp, m, u, b, desc in TESTS if wrapper.score_request(m, u, b) >= threshold]
    normal_ok = sum(1 for exp, *_ in TESTS if exp == "ALLOW") - sum(1 for exp, _ in blocked if exp == "ALLOW")
    attack_ok = sum(1 for exp, _ in blocked if exp == "BLOCK")
    n_allow = sum(1 for t in TESTS if t[0] == "ALLOW")
    n_block = len(TESTS) - n_allow
    misses = [f"ALLOW:{d}" for e, d in blocked if e == "ALLOW"] + \
             [f"BLOCK:{t[4]}" for t in TESTS if t[0] == "BLOCK" and (t[0], t[4]) not in blocked]
    print(f"[*] Scenarios: normal {normal_ok}/{n_allow} | attack {attack_ok}/{n_block} | misses {misses}")

    reqs = [(m, u, b) for _, m, u, b, _ in TESTS] * 5
    wrapper.score_request(*reqs[0])  # warm-up
    lat = []
    for r in reqs:
        t = time.perf_counter()
        wrapper.score_request(*r)
        lat.append((time.perf_counter() - t) * 1000)
    latency = {"p50_ms": round(float(np.percentile(lat, 50)), 2), "p95_ms": round(float(np.percentile(lat, 95)), 2),
               "n": len(lat)}
    print(f"[*] Single-request latency p50 {latency['p50_ms']} ms / p95 {latency['p95_ms']} ms")

    # 4. save model + card
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(ARCHIVE_DIR, f"gen3-final-f-{stamp}")
    os.makedirs(out_dir, exist_ok=True)
    inputs = [CSIC_PATH, VPS_AUDIT_PATH, NGINX_BENIGN_PATH, *EXTERNAL_SOURCES.values()] + \
        sorted(glob.glob(os.path.join(TELEMETRY_DIR, "*.jsonl")))
    card = {
        "model": "Gen3FModel: LightGBM on feature set F, trained on all data",
        "status": "NOT PROMOTED - promotion gate 3.1-G.0 passed 3/5 (see reference_experiment); demo / shadow use only",
        "created": stamp, "git_commit": git_commit(),
        "feature_set": FEATURE_SET_VERSION, "feature_columns": FEATURE_SET_F,
        "threshold": round(threshold, 6), "benign_target_per_dataset": args.benign_target,
        "threshold_per_dataset": {d: round(t, 6) for d, t in per_ds_thr.items()},
        "hyperparameters": {k: v for k, v in params.items() if k != "class_weight"}
        | {"class_weight": {str(k): v for k, v in params["class_weight"].items()}, "from": params_from},
        "out_of_fold_at_threshold": oof_by_ds,
        "out_of_fold_gate_estimates": {"G1_min_benign": round(min(benign), 4), "G2_mean_known_attack": round(float(np.mean(known)), 4)},
        "scenarios": {"normal_allowed": f"{normal_ok}/{n_allow}", "attack_blocked": f"{attack_ok}/{n_block}", "misses": misses},
        "latency_single_request": latency,
        "reference_experiment": {"report": REFERENCE_EXPERIMENT, "config": "E_plus_query_body_entropy",
                                 "gate_v2": "G1 98.69 PASS, G2 83.6 FAIL, G3 61.1 FAIL, G4 41.0 PASS, G5 PASS"},
        "data": {"sources": sorted(meta["Source"].unique()), "rows": int(len(yv)),
                 "integrity": {k: integrity[k] for k in ("total_unique_samples", "effective_distinct_shapes", "unique_rows_by_source")},
                 "input_files": {os.path.relpath(p, ML_DIR): {"sha256": _sha256_file(p), "bytes": os.path.getsize(p)}
                                 for p in inputs if os.path.exists(p)}},
        "code_sha256": {f: _sha256_file(os.path.join(ML_DIR, f)) for f in
                        ("gen3_model.py", "value_features.py", "feature_engineering.py", "hybrid_model.py",
                         "train_final_gen3.py", "train_gen3_full_real_benchmark.py")},
        "environment": {"python": platform.python_version(), "lightgbm": lgb.__version__},
    }
    wrapper.card = card
    joblib.dump(wrapper, os.path.join(out_dir, "gen3_f_model.joblib"))
    with open(os.path.join(out_dir, "model_card.json"), "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2, default=float)
    print(f"\n[✔] Saved {out_dir}\n    serve it: copy gen3_f_model.joblib to ml/models/gen3/ (ml_api.py /predict-gen3)")


if __name__ == "__main__":
    main()
