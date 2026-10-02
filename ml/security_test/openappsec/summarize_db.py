"""Rates per WAF from the open-appsec tool's DuckDB, the way its report computes them.

The tool drops requests with status 0 (timeouts / connection errors) from both
rates (report/data_loader.py: WHERE response_status_code != 0), so this also
prints how many were dropped: a large count means the run is not trustworthy.

    python summarize_db.py <results>/db/waf_comparison.duckdb
"""
import sys

import duckdb

con = duckdb.connect(sys.argv[1], read_only=True)
rows = con.execute('''
    SELECT "WAF_Name", "DataSetType",
           COUNT(*)                                                         AS sent,
           SUM(CASE WHEN response_status_code = 0 THEN 1 ELSE 0 END)        AS dropped_status0,
           SUM(CASE WHEN response_status_code != 0 AND "isBlocked" = 1 THEN 1 ELSE 0 END) AS blocked,
           SUM(CASE WHEN response_status_code != 0 THEN 1 ELSE 0 END)       AS counted
    FROM waf_comparison GROUP BY 1, 2 ORDER BY 1, 2''').fetchall()

per = {}
for waf, kind, sent, dropped, blocked, counted in rows:
    rate = blocked / counted * 100 if counted else float("nan")
    per.setdefault(waf, {})[kind] = rate
    print(f"{waf:28s} {kind:10s} sent {sent:8d}  dropped(status 0) {dropped:6d}  blocked {blocked:8d}/{counted:<8d} {rate:7.3f}%")

print()
print(f"{'WAF':28s} {'TPR':>8s} {'FPR':>8s} {'Balanced':>9s}")
for waf, r in per.items():
    tpr, fpr = r.get("Malicious", float("nan")), r.get("Legitimate", float("nan"))
    print(f"{waf:28s} {tpr:7.3f}% {fpr:7.3f}% {(tpr + 100 - fpr) / 2:8.3f}%")
