#!/usr/bin/env python3
import sys, os, joblib, pandas as pd
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ml.feature_engineering import extract_features_from_request, EXTENDED_FEATURE_COLUMNS

model_dir = "/home/chirachot/seminar/waf_project/ml/models/archive/task3-1-real-augmented-candidate-20260925-120054"
model_path = os.path.join(model_dir, "lightgbm_waf_model.joblib")
m = joblib.load(model_path)

test_cases = [
    ("/index.html", "GET", ""),
    ("/assets/css/style.css", "GET", ""),
    ("/search?q=mechanical+keyboard&sort=price_asc", "GET", ""),
    ("/api/health", "GET", "")
]

for url, method, body in test_cases:
    f = extract_features_from_request(url=url, method=method, body=body)
    df = pd.DataFrame([f])[EXTENDED_FEATURE_COLUMNS]
    prob = m.predict_proba(df)[0, 1]
    contrib = m.booster_.predict(df, pred_contrib=True)[0]
    names = EXTENDED_FEATURE_COLUMNS + ['bias']
    vals = list(df.iloc[0]) + [0]
    print(f"\n=======================================================")
    print(f"URL: {url} | Method: {method} | Prob: {prob*100:.2f}%")
    print(f"=======================================================")
    for name, val, c in sorted(zip(names, vals, contrib), key=lambda x: abs(x[2]), reverse=True)[:8]:
        print(f"  {name:32s} = {val:<8} contrib: {c:+.4f}")
