import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import StratifiedKFold
from ml.benchmark_gen3_real_augmented import prepare_real_augmented_dataset, load_real_csic_dataset, load_real_telemetry

X, y, hashes, integrity = prepare_real_augmented_dataset()

# Reconstruct deduplicated text dataframe exactly matching X
csic_clean = load_real_csic_dataset()
csic_clean['Source'] = 'CSIC'
telem = load_real_telemetry()
combined = pd.concat([csic_clean, telem], ignore_index=True)
request_cols = ['URI', 'GET-Query', 'POST-Data', 'Method']
import hashlib
canonical = combined[request_cols].fillna('').astype(str).agg('\x1f'.join, axis=1)
h_series = canonical.map(lambda v: hashlib.sha256(v.encode('utf-8')).hexdigest())
keep = ~h_series.duplicated(keep='first')
df_dedup = combined.loc[keep].reset_index(drop=True)

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
for fit_idx, val_idx in skf.split(X, y):
    model = lgb.LGBMClassifier(n_estimators=300, max_depth=12, num_leaves=127, learning_rate=0.06,
                               class_weight={0: 1.0, 1: 1.25}, random_state=42, n_jobs=-1, verbose=-1)
    model.fit(X.iloc[fit_idx], y.iloc[fit_idx])
    val_probs = model.predict_proba(X.iloc[val_idx])[:, 1]
    y_val = y.iloc[val_idx]
    
    thresh = 0.703
    preds = (val_probs >= thresh).astype(int)
    fn_mask = (y_val == 1) & (preds == 0)
    fn_indices = val_idx[fn_mask]
    
    print('Total FN count:', len(fn_indices))
    print('\n--- Raw False Negative Examples (Top 10) ---')
    for idx in fn_indices[:10]:
        row = df_dedup.iloc[idx]
        m = row['Method']
        u = row['URI']
        q = row['GET-Query']
        p = row['POST-Data']
        print(f"[{m}] {u} ? {q} | BODY: {p}")
    break
