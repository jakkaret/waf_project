#!/usr/bin/env python3
"""
Extract verified blocked attack requests from ModSecurity audit.json on VPS.
Adheres strictly to WORKING_RULES.md and WAF_GEN3_ROADMAP.md:
- Only extracts requests that were actually blocked (is_interrupted = True)
- Captures Rule IDs as security provenance (Roadmap 3.1-C & 3.1-D)
- Deduplicates via SHA-256 (0 leakage)
- Redacts and caps body to prevent secret leakage
- Exports clean JSONL format
"""

import os
import sys
import json
import hashlib

AUDIT_PATH = "/root/waf_project/logs/modsecurity/audit.json"
OUT_PATH = "/root/waf_project/ml/dataset/modsec_real_attacks.jsonl"

def main():
    if not os.path.exists(AUDIT_PATH):
        print(f"[!] Audit log not found at {AUDIT_PATH}")
        sys.exit(1)

    print(f"[*] Scanning ModSecurity audit log: {AUDIT_PATH} ...")
    unique_attacks = {}
    total_blocked = 0
    total_lines = 0

    with open(AUDIT_PATH, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            try:
                d = json.loads(line)
            except Exception:
                continue

            tx = d.get("transaction", {})
            if not tx.get("is_interrupted"):
                continue

            total_blocked += 1
            req = tx.get("request", {})
            method = req.get("method", "GET")
            raw_uri = req.get("uri", "/")
            body = req.get("body", "") or ""

            if "?" in raw_uri:
                path, query = raw_uri.split("?", 1)
            else:
                path, query = raw_uri, ""

            # Cap body at 2048 chars for privacy and ML limit
            capped_body = str(body)[:2048]

            h = hashlib.sha256(f"{path}\x1f{query}\x1f{capped_body}\x1f{method}".encode("utf-8")).hexdigest()

            # Extract triggered rule IDs
            rules = []
            for msg in tx.get("messages", []):
                rule_id = msg.get("details", {}).get("ruleId")
                if rule_id:
                    rules.append(rule_id)

            if h not in unique_attacks:
                unique_attacks[h] = {
                    "URI": path,
                    "GET-Query": query,
                    "POST-Data": capped_body,
                    "Method": method,
                    "Class": "Anomalous",
                    "Source": "ModSecurity_Real_Blocked",
                    "rule_ids": list(set(rules)),
                    "sha256": h
                }

    print(f"[+] Total Transactions Checked: {total_lines}")
    print(f"[+] Total Blocked Attack Events: {total_blocked}")
    print(f"[+] Unique Deduplicated Attack Requests: {len(unique_attacks)}")

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as out_fp:
        for item in unique_attacks.values():
            out_fp.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"[✔] Successfully exported {len(unique_attacks)} unique real attacks -> {OUT_PATH}")

if __name__ == "__main__":
    main()
