#!/usr/bin/env python3
"""
Experiment: do value-level detector features (ml/value_features.py) raise
attack recall *robustly*, i.e. outside the dataset contexts they were trained on?

Why (27/09/2026 hybrid candidate): in-distribution family recall is already
~99%, yet leave-one-source-out attack recall is 6-13%, the 63 scenarios block
18/26 attacks and `POST /api/run cmd=;cat /etc/shadow` scores 0.002. The
LightGBM's top importances are context features (query_body_entropy,
url_path_entropy, avg/max_param_length, path_depth). So each configuration is
judged on four things, not on the in-distribution gate alone:

  1. CORE holdout gate (same protocol as the trainer: group split, near-duplicate
     weights, threshold from CORE dev out-of-fold only) + per-family recall and
     recall split by "request carries any attack signal" vs "structural only"
  2. context-transfer stress test (real holdout payloads inside real holdout
     benign requests; evaluation only) from ml/experiment_unit_model.py
  3. the 63 scenarios of ml/test_comprehensive.py
  4. leave-one-source-out (skip with --no-loso)

Configurations (LightGBM, hyperparameters of the latest archived candidate):
  A  36 structural features (baseline)
  B  36 + value features
  C  B with +1 monotone constraints on every attack-signal feature, so a
     payload can never be "explained away" by benign-looking context
  D  C without the context-fingerprint features (CONTEXT_COLUMNS)

Nothing here changes the training data: no synthetic rows, the stress set is
never trained on.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlsplit

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.experiment_unit_model import (  # noqa: E402
    build_stress_set, holdout_metrics, scenario_report, stress_report,
)
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request  # noqa: E402
from ml.train_gen3_full_real_benchmark import (  # noqa: E402
    ARCHIVE_DIR, BUILD_CACHE_DIR, CORE_SOURCES, LGBM_PARAMS, _build_cache_key, _sha256_file,
    build_full_real_dataset, choose_threshold_weighted, group_folds, split_dev_holdout, weighted_recalls,
)
from ml.value_features import (  # noqa: E402
    VALUE_FEATURE_COLUMNS, VALUE_MONOTONE_COLUMNS, extract_value_features, extract_value_features_from_units,
)

ML_DIR = os.path.dirname(os.path.abspath(__file__))

# Request-shape features that mostly identify the source dataset (top importances
# of the 20260927-205652 candidate); removed in configuration D.
CONTEXT_COLUMNS = [
    "url_path_entropy", "query_body_entropy", "avg_param_length", "max_param_length", "path_depth", "param_count",
]
# Existing structural features that only ever count attack evidence.
SIGNAL_COLUMNS = [
    "keyword_matches", "html_tag_matches", "path_traversal_depth", "has_sql_operator", "has_ssrf_token",
    "has_ssti_nosql", "inline_function_count", "comment_token_count", "suspicious_path_marker_count",
    "encoded_attack_token_count", "double_encoded_count", "json_operator_count",
]
MONOTONE = set(SIGNAL_COLUMNS) | set(VALUE_MONOTONE_COLUMNS)

CONFIGS = {
    "A_base36": (EXTENDED_FEATURE_COLUMNS, False),
    "B_36_plus_value": (EXTENDED_FEATURE_COLUMNS + VALUE_FEATURE_COLUMNS, False),
    "C_value_monotone": (EXTENDED_FEATURE_COLUMNS + VALUE_FEATURE_COLUMNS, True),
    "D_no_context_monotone": ([c for c in EXTENDED_FEATURE_COLUMNS if c not in CONTEXT_COLUMNS]
                              + VALUE_FEATURE_COLUMNS, True),
}


def value_feature_frame(meta):
    """Value features for every built row, cached next to the trainer's build cache."""
    key = hashlib.sha256((_build_cache_key() + _sha256_file(os.path.join(ML_DIR, "value_features.py"))).encode())
    path = os.path.join(BUILD_CACHE_DIR, f"value_{key.hexdigest()[:24]}.joblib")
    if os.path.exists(path):
        print(f"[+] Loaded value features from cache {os.path.relpath(path, ML_DIR)}")
        return joblib.load(path)
    t0 = time.time()
    rows = [extract_value_features_from_units(units, uri) for units, uri in zip(meta["Units"], meta["URI"])]
    V = pd.DataFrame(rows, columns=VALUE_FEATURE_COLUMNS).astype(np.float32)
    print(f"[+] Value features for {len(V)} rows in {time.time() - t0:.0f}s")
    for old in (p for p in os.listdir(BUILD_CACHE_DIR) if p.startswith("value_")):
        os.remove(os.path.join(BUILD_CACHE_DIR, old))
    joblib.dump(V, path)
    return V


def latest_hyperparameters():
    """LightGBM params of the newest archived candidate (the trainer's dev-OOF choice), else the defaults."""
    cands = sorted(d for d in os.listdir(ARCHIVE_DIR) if d.startswith("task3-1-real-augmented-candidate"))
    for c in reversed(cands):
        path = os.path.join(ARCHIVE_DIR, c, "experiment_report.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                hp = json.load(f).get("hyperparameters")
            if hp:
                hp = dict(hp)
                hp["class_weight"] = {int(k): v for k, v in hp["class_weight"].items()}
                return LGBM_PARAMS | hp, c
    return dict(LGBM_PARAMS), "defaults"


def make_params(base, columns, monotone):
    if not monotone:
        return base
    return base | {"monotone_constraints": [1 if c in MONOTONE else 0 for c in columns],
                   "monotone_constraints_method": "intermediate"}


def per_family(y, pred, w, meta):
    att = y == 1
    out = {}
    for fam, idx in meta[att].groupby("Family").indices.items():
        rows = np.flatnonzero(att)[idx]
        out[fam] = {"rows": len(rows), "attack_recall": round(float(w[rows][pred[rows] == 1].sum() / w[rows].sum()), 4)}
    return out


def signal_split(y, pred, w, has_signal, core):
    """CORE holdout attack recall for requests with / without any attack signal at all."""
    out = {}
    for name, m in (("with_signal", has_signal), ("structural_only", ~has_signal)):
        sel = core & (y == 1) & m
        out[name] = {"attack_shapes": round(float(w[sel].sum()), 1),
                     "attack_recall": round(float(w[sel & (pred == 1)].sum() / w[sel].sum()), 4) if sel.any() else None}
    return out


def request_matrix(method, url, body, columns):
    parts = urlsplit(url)
    feats = extract_features_from_request(url=url, method=method, body=body)
    feats |= extract_value_features(method, parts.path or "/", parts.query, body)
    return np.array([[feats[c] for c in columns]], dtype=np.float32)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-loso", action="store_true", help="skip leave-one-source-out (the slowest part)")
    ap.add_argument("--configs", default=",".join(CONFIGS), help="comma-separated subset of " + ",".join(CONFIGS))
    args = ap.parse_args()
    configs = {k: CONFIGS[k] for k in args.configs.split(",")}

    X, y, _, integrity, meta = build_full_real_dataset()
    V = value_feature_frame(meta)
    F = pd.concat([X.reset_index(drop=True).astype(np.float32), V], axis=1)
    yv, w = y.to_numpy(), meta["Weight"].to_numpy()
    dev, hold = split_dev_holdout(meta)
    meta_dev, meta_hold = meta.iloc[dev].reset_index(drop=True), meta.iloc[hold].reset_index(drop=True)
    core_dev = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()
    core_hold = meta_hold["Source"].isin(CORE_SOURCES).to_numpy()
    has_signal = ((F[SIGNAL_COLUMNS].to_numpy() > 0).any(axis=1) | (V["v_detector_units"].to_numpy() > 0))[hold]
    base_params, params_from = latest_hyperparameters()
    print(f"[*] LightGBM params from {params_from}; sources present: {sorted(meta['Source'].unique())}")
    print(f"[*] Attack rows with any value-detector hit: "
          f"{(V['v_detector_units'].to_numpy()[yv == 1] > 0).mean()*100:.1f}% (benign {(V['v_detector_units'].to_numpy()[yv == 0] > 0).mean()*100:.2f}%)")

    print("\n[*] Building context-transfer stress set (evaluation only)")
    injected, control, families, _ = build_stress_set(set(meta_hold["Group"]))

    report = {"params_from": params_from, "sources": sorted(meta["Source"].unique()),
              "core_sources_present": sorted(set(CORE_SOURCES) & set(meta["Source"])),
              "integrity": {k: integrity[k] for k in ("total_unique_samples", "effective_distinct_shapes",
                                                      "unique_rows_by_source")},
              "configs": {}}
    models = {}
    for name, (columns, monotone) in configs.items():
        print(f"\n{'='*70}\n {name}: {len(columns)} features, monotone={monotone}\n{'='*70}", flush=True)
        t0 = time.time()
        params = make_params(base_params, columns, monotone)
        Xc = F[columns].to_numpy(dtype=np.float32)
        Xd, yd, wd = Xc[dev], yv[dev], w[dev]

        oof = np.zeros(len(dev))
        for fi, vi in group_folds(meta_dev):
            oof[vi] = lgb.LGBMClassifier(**params).fit(Xd[fi], yd[fi], sample_weight=wd[fi]).predict_proba(Xd[vi])[:, 1]
        cal = choose_threshold_weighted(yd[core_dev], oof[core_dev], wd[core_dev])
        thr = cal["threshold"]
        model = lgb.LGBMClassifier(**params).fit(Xd, yd, sample_weight=wd)
        p_hold = model.predict_proba(Xc[hold])[:, 1]
        pred_hold = (p_hold >= thr).astype(int)
        hm = holdout_metrics(yv[hold], p_hold, w[hold], meta_hold, thr)
        c = hm["core"]
        print(f"[{name}] OOF core attack {cal['attack_recall']*100:.2f}% @ benign {cal['benign_recall']*100:.2f}% "
              f"(thr {thr:.4f}) | HOLDOUT core benign {c['benign_recall']*100:.2f}% attack {c['attack_recall']*100:.2f}% "
              f"AUC {c['auc']} [{time.time()-t0:.0f}s]", flush=True)
        entry = {
            "n_features": len(columns), "monotone": monotone, "oof_core": cal, "holdout": hm,
            "holdout_per_family": per_family(yv[hold], pred_hold, w[hold], meta_hold),
            "holdout_core_signal_split": signal_split(yv[hold], pred_hold, w[hold], has_signal, core_hold),
            "feature_gain": {k: round(float(v), 1) for k, v in sorted(
                zip(columns, model.booster_.feature_importance("gain")), key=lambda kv: -kv[1])},
        }
        print(f"  signal split (CORE holdout attacks): {entry['holdout_core_signal_split']}")
        print(f"  top gain: {list(entry['feature_gain'])[:8]}")

        def scorer(m, u, b, _model=model, _cols=columns):
            return float(_model.predict_proba(request_matrix(m, u, b, _cols))[0, 1])

        entry["stress_context_transfer"] = stress_report(name, scorer, thr, injected, control, families)
        entry["scenarios"] = scenario_report(name, scorer, thr)

        if not args.no_loso:
            loso = {}
            for source in sorted(meta["Source"].unique()):
                test = (meta["Source"] == source).to_numpy()
                if len(np.unique(yv[~test])) < 2:  # the other sources alone cannot train a classifier
                    continue
                m = lgb.LGBMClassifier(**params).fit(Xc[~test], yv[~test], sample_weight=w[~test])
                p = m.predict_proba(Xc[test])[:, 1]
                r = weighted_recalls(yv[test], (p >= thr).astype(int), w[test])
                if len(np.unique(yv[test])) == 2:
                    r["auc"] = round(float(roc_auc_score(yv[test], p, sample_weight=w[test])), 4)
                loso[source] = r
                print(f"  [{name} LOSO] {source:36s} benign {r['benign_recall']} | attack {r['attack_recall']}"
                      + (f" | AUC {r['auc']}" if "auc" in r else ""), flush=True)
            entry["loso"] = loso
        report["configs"][name] = entry
        models[name] = {"model": model, "columns": columns, "threshold": thr}

    print(f"\n{'='*70}\n SUMMARY (weighted recall; stress = payload detection / control FP)\n{'='*70}")
    for name, e in report["configs"].items():
        c, s = e["holdout"]["core"], e["stress_context_transfer"]
        stress = f"{s['detection_rate']*100:.1f}% / {s['control_false_positive_rate']*100:.1f}%" if "detection_rate" in s else "n/a"
        loso_att = [v["attack_recall"] for v in e.get("loso", {}).values() if v.get("attack_recall") is not None]
        print(f" {name:24s} CORE benign {c['benign_recall']*100:6.2f}% attack {c['attack_recall']*100:6.2f}% | "
              f"stress {stress} | scenarios {e['scenarios']['normal_allowed']} normal, {e['scenarios']['attack_blocked']} attack"
              + (f" | LOSO attack mean {np.mean(loso_att)*100:.1f}%" if loso_att else ""))

    out_dir = os.path.join(ARCHIVE_DIR, f"experiment-value-features-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "value_feature_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=float)
    joblib.dump(models, os.path.join(out_dir, "value_feature_models.joblib"))
    print(f"\n[✔] Saved {out_dir}")


if __name__ == "__main__":
    main()
