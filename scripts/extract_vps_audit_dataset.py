#!/usr/bin/env python3
"""
Extract a labelled request dataset from ALL ModSecurity audit logs on the VPS
(current + rotated .gz), following WAF_GEN3_ROADMAP.md 3.1-D:

- Attack:  a CRS payload-rule family fired (930-944: LFI/RFI/RCE/PHP/XSS/SQLi/...)
           and the method is GET. Audit logs carry no request body (part C is
           not logged), so for non-GET events the evidence is not in the row.
- Benign:  NO CRS rule of any kind fired, response 2xx/3xx, GET, host in the
           lab allowlist, and the request line passes the same signature
           filter as scripts/extract_nginx_benign.py. Hosts outside the
           allowlist (e.g. look-alike subdomains under the wildcard DNS) are
           never used as benign.
- Everything else is unlabelled and skipped.

Read-only on the VPS: run it over SSH and capture stdout locally, e.g.
    ssh root@VPS python3 - < scripts/extract_vps_audit_dataset.py > ml/dataset/vps_audit_labelled.jsonl
Progress/statistics go to stderr. No request bodies or headers are emitted.
"""

import gzip
import hashlib
import json
import os
import re
import sys
from collections import Counter
from urllib.parse import urlsplit

AUDIT_DIR = "/root/waf_project/logs/modsecurity"
AUDIT_FILES = ["audit.json.2.gz", "audit.json.1.gz", "audit.json"]
LAB_HOSTS = {
    "juice.waf-it-kku.online",
    "dvwa.waf-it-kku.online",
    "bwapp.waf-it-kku.online",
    "vampi.waf-it-kku.online",
    "ryu.waf-it-kku.online",
}
PAYLOAD_RULE_FAMILIES = {
    "930": "LFI", "931": "RFI", "932": "RCE", "933": "PHP", "934": "Generic-Injection",
    "941": "XSS", "942": "SQLi", "943": "Session-Fixation", "944": "Java",
}
# Same filter as scripts/extract_nginx_benign.py
ATTACK_CHECK_PATTERN = re.compile(
    r"(?i)(<script|union\s+select|select\s+.*?\s+from|\.\./|\.\.\\|/etc/passwd|"
    r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1|sleep\s*\(|benchmark\s*\(|\$\{jndi:|'|\"|--)"
)


def records(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def main():
    seen = set()
    stats = Counter()
    for name in AUDIT_FILES:
        path = os.path.join(AUDIT_DIR, name)
        if not os.path.exists(path):
            continue
        for rec in records(path):
            stats["records"] += 1
            t = rec.get("transaction", {}) or {}
            req = t.get("request", {}) or {}
            method = str(req.get("method", "")).upper()
            uri = str(req.get("uri", ""))
            headers = req.get("headers", {}) or {}
            host = str(headers.get("Host") or headers.get("host") or "").split(":")[0].lower()
            status = str((t.get("response") or {}).get("http_code", ""))
            rule_ids = sorted({str((m.get("details") or {}).get("ruleId", "")) for m in (t.get("messages") or [])} - {""})
            families = sorted({PAYLOAD_RULE_FAMILIES[r[:3]] for r in rule_ids if r[:3] in PAYLOAD_RULE_FAMILIES})

            if method != "GET" or not uri.startswith("/"):
                stats["skip_non_get_or_bad_uri"] += 1
                continue
            if families:
                cls, source = "Anomalous", "ModSecurity_VPS_Audit_Payload_Rule"
            elif not rule_ids and status[:1] in ("2", "3") and host in LAB_HOSTS and not ATTACK_CHECK_PATTERN.search(uri):
                cls, source = "Valid", "VPS_Audit_RuleFree_2xx_Lab"
            else:
                stats["skip_unlabelled"] += 1
                continue

            parts = urlsplit(uri)
            key = hashlib.sha256(f"{method}\x1f{parts.path}\x1f{parts.query}\x1f{cls}".encode()).hexdigest()
            if key in seen:
                stats["dup"] += 1
                continue
            seen.add(key)
            stats[cls] += 1
            print(json.dumps({
                "URI": parts.path,
                "GET-Query": parts.query,
                "POST-Data": "",
                "Method": method,
                "Class": cls,
                "Source": source,
                "Family": "+".join(families) if families else "benign",
                "rule_ids": rule_ids,
                "host": host,
                "audit_file": name,
            }, ensure_ascii=False))
    print(json.dumps(dict(stats)), file=sys.stderr)


if __name__ == "__main__":
    main()
