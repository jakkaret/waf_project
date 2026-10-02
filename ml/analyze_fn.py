#!/usr/bin/env python3
"""Analyze False Negatives in the holdout set to understand what attacks the model is missing."""

import sys, os
import pandas as pd, numpy as np, joblib
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.train_gen3_full_real_benchmark import build_full_real_dataset
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS
from sklearn.model_selection import train_test_split

X, y, hashes, _ = build_full_real_dataset()

# Same split as training
row_indices = np.arange(len(X))
dev_idx, holdout_idx = train_test_split(row_indices, test_size=0.20, random_state=20260913, stratify=y)
X_holdout = X.iloc[holdout_idx].reset_index(drop=True)
y_holdout = y.iloc[holdout_idx].reset_index(drop=True)

m = joblib.load(os.path.join(os.path.dirname(__file__), 'models/archive/task3-1-real-augmented-candidate-20260924-164725/lightgbm_waf_model.joblib'))
probs = m.predict_proba(X_holdout)[:, 1]

# Analyze at optimal threshold
threshold = 0.759
preds = (probs >= threshold).astype(int)
fn_mask = (y_holdout == 1) & (preds == 0)
tp_mask = (y_holdout == 1) & (preds == 1)

print(f'Holdout: {len(y_holdout)} samples')
print(f'Attack samples: {(y_holdout==1).sum()}')
print(f'False Negatives: {fn_mask.sum()}')
print(f'True Positives: {tp_mask.sum()}')
print(f'Attack Recall: {tp_mask.sum() / (y_holdout==1).sum() * 100:.2f}%')

# Feature profile of False Negatives vs True Positives
fn_features = X_holdout[fn_mask]
tp_features = X_holdout[tp_mask]
print(f'\n--- False Negative vs True Positive Feature Profile (mean) ---')
for col in EXTENDED_FEATURE_COLUMNS:
    fn_mean = fn_features[col].mean()
    tp_mean = tp_features[col].mean()
    if abs(fn_mean - tp_mean) > 0.01:
        print(f'{col:35s}: FN_mean={fn_mean:8.4f}  TP_mean={tp_mean:8.4f}  delta={fn_mean-tp_mean:+.4f}')

# Check how many FN have is_clean_structure == 1 (look like benign structurally)
fn_clean = fn_features['is_clean_structure'].sum()
fn_static = fn_features['is_static_asset'].sum()
print(f'\n--- FN Structural Profile ---')
print(f'FN with is_clean_structure=1: {int(fn_clean)} / {fn_mask.sum()} ({fn_clean/fn_mask.sum()*100:.1f}%)')
print(f'FN with is_static_asset=1:    {int(fn_static)} / {fn_mask.sum()} ({fn_static/fn_mask.sum()*100:.1f}%)')
print(f'FN with keyword_matches=0:    {int((fn_features["keyword_matches"]==0).sum())} / {fn_mask.sum()}')
print(f'FN with special_char_count=0: {int((fn_features["special_char_count"]==0).sum())} / {fn_mask.sum()}')

# Check probability distribution of FN
print(f'\n--- FN Probability Distribution ---')
fn_probs = probs[fn_mask.values]
for pct in [10, 25, 50, 75, 90]:
    print(f'  P{pct}: {np.percentile(fn_probs, pct)*100:.2f}%')
print(f'  Mean: {fn_probs.mean()*100:.2f}%')

# Count how many FN are just barely below threshold
near_miss = ((fn_probs >= 0.5) & (fn_probs < threshold)).sum()
far_miss = (fn_probs < 0.3).sum()
print(f'\n  Near-miss (0.50 <= p < {threshold}): {near_miss}')
print(f'  Far-miss (p < 0.30):                {far_miss}')

# What if we apply a Clean Guardrail: is_clean_structure=1 AND keyword_matches=0 AND special_char_count=0 -> ALLOW
# Then for everything else, we can lower the threshold
benign_holdout = X_holdout[y_holdout == 0]
attack_holdout = X_holdout[y_holdout == 1]

clean_mask_benign = (benign_holdout['is_clean_structure'] == 1)
clean_mask_attack = (attack_holdout['is_clean_structure'] == 1)

print(f'\n--- Clean Guardrail Analysis ---')
print(f'Benign that pass Clean Guardrail (ALLOW):  {clean_mask_benign.sum()} / {len(benign_holdout)} ({clean_mask_benign.sum()/len(benign_holdout)*100:.2f}%)')
print(f'Attacks that pass Clean Guardrail (LEAK!):  {clean_mask_attack.sum()} / {len(attack_holdout)} ({clean_mask_attack.sum()/len(attack_holdout)*100:.2f}%)')

# Simulate: Clean pass → ALLOW, rest → ML with lower threshold
for test_threshold in [0.40, 0.45, 0.50, 0.55, 0.60]:
    # Clean benign -> always correct (TN)
    tn_clean = clean_mask_benign.sum()
    # Non-clean benign -> ML decides
    non_clean_benign = benign_holdout[~clean_mask_benign]
    non_clean_benign_probs = probs[(y_holdout == 0).values & (~X_holdout['is_clean_structure'].astype(bool)).values]
    tn_ml = (non_clean_benign_probs < test_threshold).sum()
    fp_ml = (non_clean_benign_probs >= test_threshold).sum()
    
    # Clean attack -> leak (FN)
    fn_clean_attack = clean_mask_attack.sum()
    # Non-clean attack -> ML decides
    non_clean_attack_probs = probs[(y_holdout == 1).values & (~X_holdout['is_clean_structure'].astype(bool)).values]
    tp_ml = (non_clean_attack_probs >= test_threshold).sum()
    fn_ml = (non_clean_attack_probs < test_threshold).sum()
    
    total_tn = tn_clean + tn_ml
    total_fp = fp_ml
    total_tp = tp_ml
    total_fn = fn_clean_attack + fn_ml
    
    b_rec = total_tn / (total_tn + total_fp) if (total_tn + total_fp) > 0 else 0
    a_rec = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    
    status = "✅" if b_rec >= 0.985 and a_rec >= 0.85 else "⏳"
    print(f'  Threshold={test_threshold:.2f}: Benign_Recall={b_rec*100:.2f}% Attack_Recall={a_rec*100:.2f}% (TN={total_tn} FP={total_fp} TP={total_tp} FN={total_fn}) {status}')
