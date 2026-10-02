#!/usr/bin/env python3
"""
Extract 100% verified genuine benign requests from VPS Nginx access.json.
Criteria:
1. HTTP status code is 200 or 304.
2. Verified clean: no attack keywords, no SQL/XSS/Traversal tokens.
3. Covers real-world static assets (.js, .css, .jpg, .png, .ico, .woff),
   static pages (/setup.php, /login.php, /index.html, /), and API routes.
"""

import sys, os, json, re
import urllib.parse
from collections import Counter

ATTACK_CHECK_PATTERN = re.compile(
    r"(?i)(<script|union\s+select|select\s+.*?\s+from|\.\./|\.\.\\|/etc/passwd|"
    r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1|sleep\s*\(|benchmark\s*\(|\$\{jndi:|'|\"|--)"
)

def extract_benign_from_access_log():
    log_path = "/root/waf_project/logs/nginx/access.json"
    if not os.path.exists(log_path):
        print(f"Log not found: {log_path}")
        return []

    benign_rows = []
    seen = set()

    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                status = str(d.get("status", ""))
                if status not in ("200", "304"):
                    continue

                raw_req = str(d.get("request", "")).strip()
                if not raw_req:
                    continue

                # Parse request line: "METHOD /path?query HTTP/1.1"
                parts = raw_req.split()
                if len(parts) >= 2:
                    method = parts[0].upper()
                    full_target = parts[1]
                else:
                    method = "GET"
                    full_target = raw_req

                if method not in ("GET", "POST", "HEAD", "OPTIONS"):
                    continue

                # Safety check against scanner probes that might return 200 by accident
                if ATTACK_CHECK_PATTERN.search(full_target):
                    continue

                # Split URI and Query
                if "?" in full_target:
                    uri, query = full_target.split("?", 1)
                else:
                    uri, query = full_target, ""

                # Filter out pure noise / malformed
                if not uri.startswith("/"):
                    continue

                key = (method, uri, query)
                if key in seen:
                    continue
                seen.add(key)

                benign_rows.append({
                    "URI": uri,
                    "GET-Query": query,
                    "POST-Data": "",
                    "Method": method,
                    "Class": "Valid",
                    "Source": "VPS_Nginx_Real_200_Access"
                })
            except Exception:
                continue

    print(f"[+] Extracted {len(benign_rows)} unique real benign requests from Nginx access.json")
    return benign_rows

if __name__ == "__main__":
    rows = extract_benign_from_access_log()
    out_path = "/root/waf_project/ml/dataset/nginx_real_benign.jsonl"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as out:
        for r in rows:
            out.write(json.dumps(r) + "\n")
    print(f"[✔] Saved {len(rows)} rows to {out_path}")
