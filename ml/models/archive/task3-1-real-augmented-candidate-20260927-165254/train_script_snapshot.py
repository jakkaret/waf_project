#!/usr/bin/env python3
"""
Full Real-World Training & Benchmark for WAF Gen 3 (Roadmap 3.1-D .. 3.1-G):
1. ZERO Synthetic rows, ZERO Row Multiplication. Hand-written "representative"
   URLs are NOT training data; they live only in ml/test_comprehensive.py.
2. Conservative labels with provenance (3.1-D):
   - CSIC 2010 Cleaned (checked-in benchmark labels)
   - VPS Telemetry: benign rows only. Its attack labels were derived from the
     model's own features (circular) and without the POST body that produced
     them, so they are excluded rather than trusted.
   - VPS ModSecurity: attack only when a payload rule family fired
     (930-944: LFI/RFI/RCE/PHP/XSS/SQLi/...). Protocol/generic-only events
     (920xxx + 949110, e.g. Juice Shop /socket.io/ polling hit by 920420) are
     excluded, never auto-labelled as attack. Non-GET events are excluded
     too: bodies were never captured, so their evidence is not in the row.
   - VPS Nginx 200/304 access rows (signature-filtered benign).
3. Features: EXTENDED_FEATURE_COLUMNS from ml/feature_engineering.py.
4. SHA-256 exact dedup + near-duplicate GROUPS (3.1-E.1/E.3): requests that
   differ only in method, digits or random tokens share a group. Groups never
   straddle train and holdout, and every row is weighted 1/group-size so each
   distinct request shape counts once in training, calibration and metrics.
5. Splits and CV folds are stratified on label x source. Hyperparameters and
   the decision threshold are chosen on dev out-of-fold predictions only;
   the holdout is evaluated exactly once (3.1-F.2/F.4).
6. Report: overall + per-source + per-attack-family metrics, enforcement-band
   recall, confusion matrix, single-request latency, and a dataset manifest
   with input file hashes.
"""

import os
import re
import sys
import json
import shutil
import hashlib
import platform
import time
from collections import Counter
from datetime import datetime
from urllib.parse import parse_qsl
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, confusion_matrix
import lightgbm as lgb
import joblib

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.benchmark_real_holdout import load_real_csic_dataset, MIN_BENIGN_RECALL, MIN_ATTACK_RECALL, N_SPLITS, RANDOM_STATE
from ml.benchmark_gen3_real_augmented import load_real_telemetry
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request

ML_DIR = os.path.dirname(os.path.abspath(__file__))
ARCHIVE_DIR = os.path.join(ML_DIR, "models", "archive")
MODSEC_ATTACKS_PATH = os.path.join(ML_DIR, "dataset", "modsec_real_attacks.jsonl")
NGINX_BENIGN_PATH = os.path.join(ML_DIR, "dataset", "nginx_real_benign.jsonl")
CSIC_PATH = os.path.join(ML_DIR, "dataset", "csic_final.csv")
TELEMETRY_DIR = os.path.join(ML_DIR, "telemetry")

# OWASP CRS rule-file prefixes that indicate an actual payload attack.
# Anything else (920 protocol enforcement, 911/913 method/scanner, 949/980
# anomaly-score summaries) is protocol/generic evidence only.
PAYLOAD_RULE_FAMILIES = {
    "930": "LFI",
    "931": "RFI",
    "932": "RCE",
    "933": "PHP",
    "934": "Generic-Injection",
    "941": "XSS",
    "942": "SQLi",
    "943": "Session-Fixation",
    "944": "Java",
}

LGBM_PARAMS = dict(
    n_estimators=400,
    max_depth=10,
    num_leaves=80,
    min_child_samples=20,
    learning_rate=0.05,
    reg_alpha=0.2,
    reg_lambda=0.3,
    colsample_bytree=0.8,
    subsample=0.85,
    class_weight={0: 1.0, 1: 1.5},
    random_state=42,
    n_jobs=-1,
    verbose=-1,
)

_MIXED_TOKEN = re.compile(r"[a-z0-9_\-\.]{6,}")
_DIGITS = re.compile(r"\d+")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def modsec_attack_families(rule_ids):
    """Return the sorted payload families a ModSecurity event hit, or []."""
    return sorted({PAYLOAD_RULE_FAMILIES[r[:3]] for r in rule_ids if str(r)[:3] in PAYLOAD_RULE_FAMILIES})


def _value_shape(value):
    """Collapse values that differ only in digits or random tokens (session ids, cache busters)."""
    v = str(value).lower()
    v = _MIXED_TOKEN.sub(
        lambda m: "T" if any(c.isdigit() for c in m.group()) and any(c.isalpha() for c in m.group()) else m.group(),
        v,
    )
    return _DIGITS.sub("0", v)


def near_duplicate_group(uri, query, body):
    """Group key for 3.1-E.3: same path + param names + value shapes.

    Method is deliberately not part of the key: CSIC ships every request as
    both a GET and a POST variant, which are the same payload.
    """
    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=10000) + \
        parse_qsl(body, keep_blank_values=True, max_num_fields=10000)
    if pairs:
        payload = "&".join(f"{k}={_value_shape(v)}" for k, v in sorted(pairs))
    else:
        payload = _value_shape(query + body)
    return f"{_value_shape(uri)} {payload}"


def load_real_modsec_attacks():
    """Load ModSecurity events; keep only payload-rule hits as attacks (3.1-D.1/D.2)."""
    if not os.path.exists(MODSEC_ATTACKS_PATH):
        raise FileNotFoundError(f"ModSec attacks file not found: {MODSEC_ATTACKS_PATH}")

    rows = []
    excluded = 0
    excluded_rules = Counter()
    excluded_no_body = 0
    with open(MODSEC_ATTACKS_PATH, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rule_ids = [str(r) for r in d.get("rule_ids", [])]
            families = modsec_attack_families(rule_ids)
            if not families:
                excluded += 1
                excluded_rules.update(rule_ids)
                continue
            # The extractor never captured request bodies: for a non-GET event
            # the matched payload was most likely in the body we do not have,
            # so the training row would carry the label without its evidence.
            if str(d.get("Method", "GET")).upper() != "GET" and not d.get("POST-Data"):
                excluded_no_body += 1
                continue
            rows.append({
                "URI": d.get("URI", "/"),
                "GET-Query": d.get("GET-Query", ""),
                "POST-Data": d.get("POST-Data", ""),
                "Method": d.get("Method", "GET"),
                "Class": "Anomalous",
                "Source": "ModSecurity_VPS_Payload_Rule",
                "Family": "+".join(families),
            })

    df_modsec = pd.DataFrame(rows)
    print(f"[+] ModSecurity payload-rule attacks: {len(df_modsec)} rows kept; "
          f"{excluded} protocol/generic-only events excluded (3.1-D.2); "
          f"{excluded_no_body} non-GET events without captured body excluded")
    return df_modsec, {
        "kept_payload_rule_rows": len(df_modsec),
        "excluded_protocol_only_rows": excluded,
        "excluded_non_get_without_body_rows": excluded_no_body,
        "excluded_top_rule_ids": dict(excluded_rules.most_common(10)),
    }


def load_real_nginx_benign():
    """Load verified clean 200/304 requests extracted from VPS Nginx access.json."""
    if not os.path.exists(NGINX_BENIGN_PATH):
        print(f"[!] Nginx benign file not found at: {NGINX_BENIGN_PATH}")
        return pd.DataFrame()

    rows = []
    with open(NGINX_BENIGN_PATH, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rows.append({
                "URI": d.get("URI", "/"),
                "GET-Query": d.get("GET-Query", ""),
                "POST-Data": d.get("POST-Data", ""),
                "Method": d.get("Method", "GET"),
                "Class": "Valid",
                "Source": "VPS_Nginx_Real_200_Access"
            })

    df_nginx = pd.DataFrame(rows)
    print(f"[+] Loaded Real Nginx Clean Requests: {len(df_nginx)} rows (Provenance: VPS Nginx access.json)")
    return df_nginx


def build_full_real_dataset():
    """Build the deduplicated, conservatively labelled dataset.

    Returns (X, y, hashes, integrity, meta) where meta is a DataFrame aligned
    with X holding Source, Family and the near-duplicate Group of every row.
    """
    print("\n" + "="*60)
    print(" 📦 BUILDING 100% REAL-WORLD GEN 3 DATASET (ZERO SYNTHETIC)")
    print("="*60)

    # 1. CSIC 2010 Cleaned (Real historical benchmark)
    df_csic = load_real_csic_dataset()
    df_csic["Source"] = "CSIC_2010_Cleaned"
    df_csic["Family"] = "CSIC_unlabelled_family"
    print(f"[+] CSIC Cleaned: {len(df_csic)} rows")

    # 2. VPS Live Telemetry: benign only. The loader's attack labels come from
    #    this model's own features on a body we no longer have (circular).
    df_telem_all = load_real_telemetry()
    telem_attack_dropped = int((df_telem_all["Class"] == "Anomalous").sum())
    df_telem = df_telem_all[df_telem_all["Class"] == "Valid"].copy()
    print(f"[+] Telemetry benign kept: {len(df_telem)}; feature-derived attack labels dropped: {telem_attack_dropped}")

    # 3. VPS ModSecurity payload-rule attacks only
    df_modsec, modsec_stats = load_real_modsec_attacks()

    # 4. VPS Live Nginx Real Clean Requests (Real 200/304 verified traffic from VPS)
    df_nginx = load_real_nginx_benign()

    # (The former step 5, 69 hand-written "representative" URLs, was removed:
    #  they are synthetic and overlapped the scenarios in test_comprehensive.py.)

    raw_counts = {
        "CSIC_2010_Cleaned": len(df_csic),
        "VPS_Telemetry_Real_benign": len(df_telem),
        "ModSecurity_VPS_Payload_Rule": len(df_modsec),
        "VPS_Nginx_Real_200_Access": len(df_nginx),
    }

    combined = pd.concat([df_csic, df_telem, df_modsec, df_nginx], ignore_index=True)
    combined["Family"] = combined["Family"].fillna("benign")
    combined.loc[combined["Class"].astype(str).str.strip().str.lower() != "anomalous", "Family"] = "benign"
    rows_before = len(combined)

    # Enforce 100% SHA-256 Deduplication
    request_cols = ["URI", "GET-Query", "POST-Data", "Method"]
    combined[request_cols] = combined[request_cols].fillna("").astype(str)
    canonical = combined[request_cols].agg("\x1f".join, axis=1)
    hashes = canonical.map(lambda v: hashlib.sha256(v.encode("utf-8")).hexdigest())

    labels = combined["Class"].astype(str).str.strip().str.lower().map(lambda v: 1 if v == "anomalous" else 0)

    # Verify no conflicting labels on identical requests
    conflicts = pd.DataFrame({"hash": hashes, "label": labels}).groupby("hash")["label"].nunique()
    conflicting_hashes = int((conflicts > 1).sum())
    if conflicting_hashes:
        print(f"[!] Warning: {conflicting_hashes} conflicting hashes detected; dropping conflicts...")
        valid_hashes = set(conflicts[conflicts == 1].index)
        mask_valid = hashes.isin(valid_hashes)
        combined = combined.loc[mask_valid].reset_index(drop=True)
        hashes = hashes.loc[mask_valid].reset_index(drop=True)
        labels = labels.loc[mask_valid].reset_index(drop=True)

    keep = ~hashes.duplicated(keep="first")
    df_clean = combined.loc[keep].reset_index(drop=True)
    hashes_clean = hashes.loc[keep].reset_index(drop=True)
    labels_clean = labels.loc[keep].reset_index(drop=True)

    groups = df_clean.apply(
        lambda r: near_duplicate_group(r["URI"], r["GET-Query"], r["POST-Data"]), axis=1
    )
    # Near-duplicate weighting (3.1-E.1): every distinct request shape counts
    # once. A shape seen 8,887 times (e.g. GET /?_wd=<token>) gets weight
    # 1/8887 per row instead of dominating training and every metric.
    group_label = groups + "|" + labels_clean.astype(str)
    weights = 1.0 / group_label.map(group_label.value_counts()).astype(float)

    print(f"\n[✔] Data Cleaning & SHA-256 Deduplication Complete:")
    print(f"    - Total Unique Real Rows: {len(df_clean)} (Cleaned from {rows_before})")
    print(f"    - Near-duplicate groups:  {groups.nunique()} (effective distinct shapes: {weights.sum():.0f})")
    print(f"    - Genuine Benign Samples: {sum(labels_clean == 0)} rows / {weights[labels_clean == 0].sum():.0f} shapes")
    print(f"    - Genuine Attack Samples: {sum(labels_clean == 1)} rows / {weights[labels_clean == 1].sum():.0f} shapes")
    print(f"    - Synthetic Payloads:     0 (ZERO Synthetic Data)")

    print(f"\n[*] Extracting {len(EXTENDED_FEATURE_COLUMNS)} features for all {len(df_clean)} real samples...")
    features_list = []
    t0 = time.time()
    for _, row in df_clean.iterrows():
        uri, query, body, method = row["URI"], row["GET-Query"], row["POST-Data"], row["Method"] or "GET"
        full_url = f"{uri}?{query}" if query else uri
        features_list.append(extract_features_from_request(url=full_url, method=method, body=body))

    print(f"[+] Feature Extraction completed in {time.time() - t0:.2f}s")
    X = pd.DataFrame(features_list)[EXTENDED_FEATURE_COLUMNS]
    y = labels_clean
    meta = pd.DataFrame({
        "Source": df_clean["Source"],
        "Family": df_clean["Family"],
        "Group": groups,
        "Weight": weights,
        # Folds are stratified on label x source so every fold (and the
        # holdout) carries the same source mix.
        "Strat": labels_clean.astype(str) + "|" + df_clean["Source"],
    })

    per_source = pd.crosstab(meta["Source"], y).rename(columns={0: "benign", 1: "attack"})
    shapes_by_source = meta.groupby(["Source", y])["Weight"].sum().round(1)
    integrity = {
        "dataset": "CSIC_2010 + VPS_Telemetry_Benign + VPS_ModSecurity_Payload_Rule_Attacks + VPS_Nginx_Benign",
        "synthetic_rows": 0,
        "raw_rows_by_source": raw_counts,
        "exclusions": {
            "telemetry_feature_derived_attack_labels": telem_attack_dropped,
            "modsec_protocol_only_events": modsec_stats["excluded_protocol_only_rows"],
            "modsec_non_get_without_captured_body": modsec_stats["excluded_non_get_without_body_rows"],
            "modsec_excluded_top_rule_ids": modsec_stats["excluded_top_rule_ids"],
            "hand_written_representative_urls": "removed from training (synthetic)",
            "conflicting_label_hashes": conflicting_hashes,
            "exact_duplicates": int(rows_before - len(df_clean)),
        },
        "total_unique_samples": len(X),
        "near_duplicate_groups": int(groups.nunique()),
        "effective_distinct_shapes": round(float(weights.sum()), 1),
        "benign_count": int(sum(y == 0)),
        "attack_count": int(sum(y == 1)),
        "unique_rows_by_source": {s: {k: int(v) for k, v in r.items()} for s, r in per_source.iterrows()},
        "distinct_shapes_by_source_label": {f"{s}|{'attack' if l else 'benign'}": float(v)
                                            for (s, l), v in shapes_by_source.items()},
        "attack_family_counts": {k: int(v) for k, v in meta.loc[y == 1, "Family"].value_counts().items()},
        "feature_count": len(EXTENDED_FEATURE_COLUMNS),
        "feature_columns": EXTENDED_FEATURE_COLUMNS,
    }
    return X, y, hashes_clean.tolist(), integrity, meta


def group_folds(meta, n_splits=N_SPLITS):
    """Group-level stratified folds: yields (train_idx, val_idx) row indices.

    Folds are drawn over near-duplicate groups (one entry per group,
    stratified on label x source), so they balance distinct request shapes
    rather than rows. Row-balanced StratifiedGroupKFold instead parks a whole
    8,887-row group in one fold, leaving that fold with ~2 VPS benign shapes.
    """
    gtab = meta.groupby("Group", sort=True)["Strat"].first()
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    group_arr = meta["Group"].to_numpy()
    for g_fit, g_val in skf.split(np.zeros(len(gtab)), gtab.to_numpy()):
        val_mask = np.isin(group_arr, gtab.index.to_numpy()[g_val])
        yield np.flatnonzero(~val_mask), np.flatnonzero(val_mask)


def split_dev_holdout(meta):
    """Group-aware ~20% holdout: first group-level fold, stratified on label x source."""
    return next(group_folds(meta))


def weighted_recalls(y_true, y_pred, w):
    """Benign/attack recall where each row counts by its near-duplicate weight."""
    y_true, y_pred, w = np.asarray(y_true), np.asarray(y_pred), np.asarray(w, dtype=float)
    out = {}
    for name, cls, hit in (("benign", 0, 0), ("attack", 1, 1)):
        m = y_true == cls
        out[f"{name}_rows"] = int(m.sum())
        out[f"{name}_shapes"] = round(float(w[m].sum()), 1)
        out[f"{name}_recall"] = round(float(w[m & (y_pred == hit)].sum() / w[m].sum()), 4) if m.any() else None
        out[f"{name}_recall_rows"] = round(float((y_pred[m] == hit).mean()), 4) if m.any() else None
    return out


def choose_threshold_weighted(y_true, probs, w):
    """Highest weighted attack recall subject to weighted benign recall >= MIN_BENIGN_RECALL."""
    y_true, probs, w = np.asarray(y_true), np.asarray(probs), np.asarray(w, dtype=float)
    ben, att = y_true == 0, y_true == 1
    wb, wa = w[ben].sum(), w[att].sum()
    best = None
    for t in np.linspace(0.0, 1.0, 2001):
        b_rec = w[ben & (probs < t)].sum() / wb
        if b_rec < MIN_BENIGN_RECALL:
            continue
        a_rec = w[att & (probs >= t)].sum() / wa
        if best is None or (a_rec, b_rec) > (best[1], best[2]):
            best = (float(t), float(a_rec), float(b_rec))
    if best is None:
        return {"threshold": 1.0, "attack_recall": 0.0, "benign_recall": 1.0, "status": "no_threshold_met_benign_gate"}
    status = "passed_both_gates" if best[1] >= MIN_ATTACK_RECALL else "failed_attack_gate"
    return {"threshold": best[0], "attack_recall": best[1], "benign_recall": best[2], "status": status}


def oof_predict(X, y, meta, params, n_splits=N_SPLITS):
    """Out-of-fold probabilities from group-aware, label x source stratified CV."""
    oof = np.zeros(len(X))
    fold_of = np.zeros(len(X), dtype=int)
    for fold, (fit_idx, val_idx) in enumerate(group_folds(meta, n_splits), 1):
        m = lgb.LGBMClassifier(**params)
        m.fit(X.iloc[fit_idx], y.iloc[fit_idx], sample_weight=meta["Weight"].iloc[fit_idx].to_numpy())
        oof[val_idx] = m.predict_proba(X.iloc[val_idx])[:, 1]
        fold_of[val_idx] = fold
    return oof, fold_of


def select_hyperparameters(X_dev, y_dev, meta_dev):
    """Pick regularisation on dev OOF only (the holdout is never consulted).

    The failure mode seen so far is template memorisation, so the grid spans
    tree capacity and leaf size; the objective is the promotion gate itself:
    weighted attack recall at weighted benign recall >= 98.5%.
    """
    grid = []
    for num_leaves in (15, 31, 80):
        for min_child_samples in (20, 100):
            for attack_weight in (1.0, 1.5):
                grid.append(LGBM_PARAMS | {
                    "num_leaves": num_leaves,
                    "min_child_samples": min_child_samples,
                    "class_weight": {0: 1.0, 1: attack_weight},
                })
    results = []
    w = meta_dev["Weight"].to_numpy()
    for i, params in enumerate(grid, 1):
        oof, _ = oof_predict(X_dev, y_dev, meta_dev, params)
        cal = choose_threshold_weighted(y_dev, oof, w)
        auc = float(roc_auc_score(y_dev, oof, sample_weight=w))
        results.append({"params": {k: params[k] for k in ("num_leaves", "min_child_samples")} |
                        {"attack_weight": params["class_weight"][1]},
                        "oof_threshold": round(cal["threshold"], 4),
                        "oof_attack_recall": round(cal["attack_recall"], 4),
                        "oof_benign_recall": round(cal["benign_recall"], 4),
                        "oof_weighted_auc": round(auc, 4)})
        print(f"  [{i:2d}/{len(grid)}] {results[-1]['params']} -> OOF attack {cal['attack_recall']*100:.2f}% "
              f"@ benign {cal['benign_recall']*100:.2f}% (thr {cal['threshold']:.4f}, wAUC {auc:.4f})")
    best_i = max(range(len(grid)), key=lambda i: (results[i]["oof_attack_recall"], results[i]["oof_weighted_auc"]))
    return grid[best_i], results, best_i


def _single_request_latency_us(model, X_sample):
    """Latency of one request through the same DataFrame->predict_proba path ml_api uses."""
    records = X_sample.to_dict("records")
    model.predict_proba(pd.DataFrame([records[0]])[EXTENDED_FEATURE_COLUMNS])  # warm-up
    timings = []
    for rec in records:
        t = time.perf_counter()
        model.predict_proba(pd.DataFrame([rec])[EXTENDED_FEATURE_COLUMNS])
        timings.append((time.perf_counter() - t) * 1e6)
    return {
        "p50_us": round(float(np.percentile(timings, 50)), 1),
        "p95_us": round(float(np.percentile(timings, 95)), 1),
        "n": len(timings),
    }


def main():
    X, y, hashes, integrity, meta = build_full_real_dataset()
    groups = meta["Group"].to_numpy()

    # Group-aware split stratified on label x source: no exact or near-duplicate leakage
    dev_idx, holdout_idx = split_dev_holdout(meta)

    hash_overlap = {hashes[i] for i in dev_idx} & {hashes[i] for i in holdout_idx}
    group_overlap = set(groups[dev_idx]) & set(groups[holdout_idx])
    assert not hash_overlap, f"Critical leakage! {len(hash_overlap)} hashes overlapped."
    assert not group_overlap, f"Near-duplicate leakage! {len(group_overlap)} groups overlapped."

    print(f"\n[+] Verified Zero SHA-256 and Near-Duplicate Group Overlap between "
          f"Development ({len(dev_idx)}) and Holdout ({len(holdout_idx)})")

    X_dev = X.iloc[dev_idx].reset_index(drop=True)
    X_holdout = X.iloc[holdout_idx].reset_index(drop=True)
    y_dev = y.iloc[dev_idx].reset_index(drop=True)
    y_holdout = y.iloc[holdout_idx].reset_index(drop=True)
    meta_dev = meta.iloc[dev_idx].reset_index(drop=True)
    meta_holdout = meta.iloc[holdout_idx].reset_index(drop=True)
    w_dev = meta_dev["Weight"].to_numpy()
    w_holdout = meta_holdout["Weight"].to_numpy()

    print("\n" + "="*60)
    print(" 🔧 HYPERPARAMETER SELECTION ON DEV OUT-OF-FOLD (HOLDOUT UNTOUCHED)")
    print("="*60)
    params, search_results, best_i = select_hyperparameters(X_dev, y_dev, meta_dev)
    print(f"[*] Selected: {search_results[best_i]['params']}")

    # Threshold: calibrated once on the selected config's pooled OOF probabilities
    oof_probs, fold_of = oof_predict(X_dev, y_dev, meta_dev, params)
    calib = choose_threshold_weighted(y_dev, oof_probs, w_dev)
    threshold = calib["threshold"]
    oof_preds = (oof_probs >= threshold).astype(int)
    cv_folds = []
    for fold in range(1, N_SPLITS + 1):
        sel = fold_of == fold
        r = weighted_recalls(y_dev.to_numpy()[sel], oof_preds[sel], w_dev[sel])
        cv_folds.append({"fold": fold, **r})
        print(f"  Fold {fold} @ OOF threshold: Benign {r['benign_recall']*100:.2f}% ({r['benign_shapes']:.0f} shapes) | "
              f"Attack {r['attack_recall']*100:.2f}% ({r['attack_shapes']:.0f} shapes)")
    cv_attack = [f["attack_recall"] for f in cv_folds]
    cv_benign = [f["benign_recall"] for f in cv_folds]
    print(f"\n[*] OOF Calibrated Threshold: {threshold:.4f} ({calib['status']})")
    print(f"    - OOF Benign Recall: {calib['benign_recall']*100:.2f}% (Safety Gate >= 98.5%) ± {np.std(cv_benign)*100:.2f}% across folds")
    print(f"    - OOF Attack Recall: {calib['attack_recall']*100:.2f}% (Target >= 85%) ± {np.std(cv_attack)*100:.2f}% across folds")

    # Fit final model on entire Development set
    print("\n" + "="*60)
    print(" 🎯 FINAL MODEL EVALUATION ON UNSEEN HOLDOUT SET (EVALUATED ONCE)")
    print("="*60)

    final_model = lgb.LGBMClassifier(**params)
    t0 = time.time()
    final_model.fit(X_dev, y_dev, sample_weight=w_dev)
    fit_time = time.time() - t0

    t1 = time.time()
    holdout_probs = final_model.predict_proba(X_holdout)[:, 1]
    batch_us = (time.time() - t1) / len(X_holdout) * 1e6
    single = _single_request_latency_us(final_model, X_holdout.sample(n=min(500, len(X_holdout)), random_state=RANDOM_STATE))

    holdout_preds = (holdout_probs >= threshold).astype(int)
    overall = weighted_recalls(y_holdout, holdout_preds, w_holdout)
    tn, fp, fn, tp = confusion_matrix(y_holdout, holdout_preds).ravel()
    auc = float(roc_auc_score(y_holdout, holdout_probs, sample_weight=w_holdout))
    acc = float(np.sum(w_holdout * (holdout_preds == y_holdout.to_numpy())) / w_holdout.sum())
    b_rec, a_rec = overall["benign_recall"], overall["attack_recall"]

    per_source = {s: weighted_recalls(y_holdout.to_numpy()[idx], holdout_preds[idx], w_holdout[idx])
                  for s, idx in meta_holdout.groupby("Source").indices.items()}
    attack_mask = (y_holdout == 1).to_numpy()
    per_family = {}
    for fam, idx in meta_holdout[attack_mask].groupby("Family").indices.items():
        rows = np.flatnonzero(attack_mask)[idx]
        per_family[fam] = {"rows": len(rows), "attack_recall_rows": round(float(holdout_preds[rows].mean()), 4)}
    # Enforcement bands from ML_ENFORCEMENT_PLAN.md (challenge >= 0.70, block >= 0.95)
    bands = {}
    for name, t in (("challenge_0.70", 0.70), ("block_0.95", 0.95)):
        r = weighted_recalls(y_holdout, (holdout_probs >= t).astype(int), w_holdout)
        bands[name] = {"benign_recall": r["benign_recall"], "attack_recall": r["attack_recall"]}

    passed = bool(b_rec >= MIN_BENIGN_RECALL and a_rec >= MIN_ATTACK_RECALL)
    verdict = "PASSED ALL SAFETY & ACCURACY GATES" if passed else "BELOW GATE (experiment only, do not promote)"

    print(f" Metrics are near-duplicate weighted (each distinct request shape counts once); raw row recall in brackets.")
    print(f" ⭐ ACCURACY SCORE:    {acc*100:.2f}%")
    print(f" ⭐ ROC-AUC SCORE:     {auc:.4f}")
    print(f" ⭐ LATENCY:           single-request p50 {single['p50_us']:.0f} µs / p95 {single['p95_us']:.0f} µs "
          f"(batch-amortised {batch_us:.2f} µs)")
    print(f" Benign Recall:       {b_rec*100:.2f}% [rows {overall['benign_recall_rows']*100:.2f}%] (Requirement >= 98.5% -> {'PASSED' if b_rec>=MIN_BENIGN_RECALL else 'FAILED'})")
    print(f" Attack Recall:       {a_rec*100:.2f}% [rows {overall['attack_recall_rows']*100:.2f}%] (Target >= 85% -> {'PASSED' if a_rec>=MIN_ATTACK_RECALL else 'BELOW TARGET'})")
    print(f" Confusion Matrix:    TN={tn}, FP={fp}, FN={fn}, TP={tp} (rows)")
    print(f" Enforcement bands:   {bands}")
    print(" Per-source:")
    for s, v in per_source.items():
        print(f"   {s:32s} benign {v['benign_recall']} ({v['benign_shapes']} shapes) | attack {v['attack_recall']} ({v['attack_shapes']} shapes)")
    print(" Per-attack-family recall (rows):")
    for f_, v in sorted(per_family.items(), key=lambda kv: -kv[1]["rows"]):
        print(f"   {f_:32s} {v}")
    print(f" Final Status:        {verdict}")
    print("="*60 + "\n")

    # Feature Importance
    importances = final_model.feature_importances_
    feat_imp = {col: int(imp) for col, imp in sorted(zip(EXTENDED_FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)}

    # Save scientific experiment archive
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate_dir = os.path.join(ARCHIVE_DIR, f"task3-1-real-augmented-candidate-{timestamp}")
    os.makedirs(candidate_dir, exist_ok=True)

    model_path = os.path.join(candidate_dir, "lightgbm_waf_model.joblib")
    report_path = os.path.join(candidate_dir, "experiment_report.json")
    manifest_path = os.path.join(candidate_dir, "dataset_manifest.json")

    joblib.dump(final_model, model_path)
    shutil.copy2(os.path.abspath(__file__), os.path.join(candidate_dir, "train_script_snapshot.py"))

    input_files = [CSIC_PATH, MODSEC_ATTACKS_PATH, NGINX_BENIGN_PATH] + sorted(
        os.path.join(TELEMETRY_DIR, f) for f in os.listdir(TELEMETRY_DIR) if f.endswith(".jsonl")
    )
    manifest = {
        "dataset_version": f"gen3-conservative-{timestamp}",
        "input_files": {os.path.relpath(p, ML_DIR): {"sha256": _sha256_file(p), "bytes": os.path.getsize(p)}
                        for p in input_files if os.path.exists(p)},
        "data_integrity": integrity,
        "split_rule": {
            "method": "group-level StratifiedKFold over near-duplicate groups (stratified on label x source), first fold as holdout (~20% of distinct shapes)",
            "group_key": "path + sorted param names + value shape (digits -> 0, mixed alnum tokens >= 6 chars -> T); method excluded",
            "weighting": "1 / size of (group, label): each distinct request shape counts once",
            "random_state": RANDOM_STATE,
            "dev_rows": int(len(dev_idx)),
            "holdout_rows": int(len(holdout_idx)),
            "sha256_overlap": 0,
            "group_overlap": 0,
        },
        "train_script_sha256": _sha256_file(os.path.abspath(__file__)),
        "feature_engineering_sha256": _sha256_file(os.path.join(ML_DIR, "feature_engineering.py")),
        "environment": {"python": platform.python_version(), "lightgbm": lgb.__version__},
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    report_data = {
        "experiment": "Task 3.1 & 2.3 Real-World Training (conservative labels, near-duplicate weighted group split)",
        "timestamp": timestamp,
        "data_integrity": integrity,
        "metric_definition": "near-duplicate weighted recall: each distinct request shape counts once; *_rows fields are raw per-row recall",
        "hyperparameter_search": {
            "method": "grid on dev pooled OOF, objective = weighted attack recall at weighted benign recall >= 98.5%",
            "results": search_results,
            "selected_index": best_i,
        },
        "cv": {
            "method": "5-fold group-level StratifiedKFold (label x source) on dev set; threshold from pooled out-of-fold probabilities",
            "threshold": round(threshold, 4),
            "calibration_status": calib["status"],
            "oof_benign_recall": round(calib["benign_recall"], 4),
            "oof_attack_recall": round(calib["attack_recall"], 4),
            "folds_at_oof_threshold": cv_folds,
            "std_attack_recall_across_folds": round(float(np.std(cv_attack)), 4),
            "std_benign_recall_across_folds": round(float(np.std(cv_benign)), 4),
        },
        "holdout_evaluation": {
            "threshold": round(threshold, 4),
            "threshold_source": "pooled out-of-fold calibration on dev set; holdout never used for tuning",
            "accuracy": round(acc, 4),
            "roc_auc": round(auc, 4),
            "benign_recall": b_rec,
            "attack_recall": a_rec,
            "benign_recall_rows": overall["benign_recall_rows"],
            "attack_recall_rows": overall["attack_recall_rows"],
            "confusion_matrix_rows": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "enforcement_bands": bands,
            "per_source": per_source,
            "per_attack_family": per_family,
            "latency": {"single_request": single, "batch_amortised_us": round(batch_us, 2)},
            "fit_time_s": round(fit_time, 2),
            "passed_safety_gate": passed,
            "verdict": verdict,
        },
        "feature_importances": feat_imp,
        "hyperparameters": {k: v for k, v in params.items() if k != "class_weight"} |
                           {"class_weight": {str(k): v for k, v in params["class_weight"].items()}},
        "candidate_model_path": os.path.relpath(model_path, ML_DIR),
        "dataset_manifest": os.path.relpath(manifest_path, ML_DIR),
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[✔] Candidate Model Saved to: {model_path}")
    print(f"[✔] Full Evaluation Report Saved to: {report_path}")
    print(f"[✔] Dataset Manifest Saved to: {manifest_path}\n")


if __name__ == "__main__":
    main()
