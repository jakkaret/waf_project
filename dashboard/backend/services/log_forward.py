import asyncio
import json
import os
import time
from datetime import datetime
from services.dynamodb_service import DynamoDBService

db = DynamoDBService()

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../")
)

ACCESS_LOG = os.path.join(BASE_DIR, "logs/nginx/access.json")
AUDIT_LOG = os.path.join(BASE_DIR, "logs/modsecurity/audit.json")


# -----------------------------
# ACCESS LOG NORMALIZE
# -----------------------------
def normalize_access(data):
    # 🔥 parse request
    req = data.get("request", "")
    method = None
    url = None

    if req:
        parts = req.split(" ")
        if len(parts) >= 2:
            method = parts[0]
            url = parts[1]

    return {
        # core (แก้ให้ตรง field จริง)
        "ip": data.get("remote_addr"),
        "method": method,
        "url": url,
        "status": int(data.get("status", 0)),
        "user_agent": data.get("http_user_agent"),

        # fields ที่คุณอยากได้
        "body_bytes_sent": int(data.get("body_bytes_sent", 0)),
        "http_referer": data.get("http_referer"),

        # metadata
        "timestamp": int(time.time()),
        "datetime": datetime.utcnow().isoformat() + "Z",
        "source": "nginx",
        "host": None,  # ไม่มีใน log นี้

        # WAF fields
        "attack_type": None,
        "rule_id": None,
        "severity": None,
        "alert": False,

        # ML features
        "request_length": len(url or ""),
        "has_query": "?" in (url or ""),
        "is_suspicious_path": any(x in (url or "").lower() for x in ["admin", "login", "wp", "sql"]),

        # raw
        "raw": data
    }


# -----------------------------
# MODSEC NORMALIZE
# -----------------------------
def normalize_modsec(data):
    tx = data.get("transaction", {})
    req = tx.get("request", {})
    res = tx.get("response", {})
    headers = req.get("headers", {})
    msgs = tx.get("messages", [])

    attack_type = None
    rule_id = None
    severity = None

    if msgs:
        attack_type = msgs[0].get("message")
        rule_id = msgs[0].get("details", {}).get("ruleId")
        severity = msgs[0].get("details", {}).get("severity")

    url = req.get("uri", "")

    return {
        # core
        "ip": tx.get("client_ip"),
        "method": req.get("method"),
        "url": url,
        "status": int(res.get("http_code", 0)),
        "user_agent": headers.get("User-Agent") or headers.get("user-agent"),

        # 🔥 เพิ่มจาก nginx-style
        "body_bytes_sent": len(res.get("body", "")),
        "http_referer": headers.get("Referer") or headers.get("referer"),

        # metadata (A,B,C,D)
        "timestamp": int(time.time()),
        "datetime": datetime.utcnow().isoformat() + "Z",
        "source": "modsec",
        "host": headers.get("Host"),
        "severity": severity,

        # WAF
        "attack_type": attack_type,
        "rule_id": rule_id,
        "alert": False,

        # 🔥 ML feature
        "request_length": len(url),
        "has_query": "?" in url,
        "is_suspicious_path": any(x in url.lower() for x in ["admin", "login", "wp", "sql", "attack"]),

        # network context
        "client_port": tx.get("client_port"),
        "server_ip": tx.get("host_ip"),

        # raw
        "raw": data,
    }


# -----------------------------
# FILE TAIL
# -----------------------------
async def tail_file(path):
    print("Opening log file:", path)

    if not os.path.exists(path):
        print("File not found:", path)

    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            yield line.strip()


# -----------------------------
# PROCESS ACCESS
# -----------------------------
async def process_access_log():
    async for line in tail_file(ACCESS_LOG):
        try:
            raw = json.loads(line)
            data = normalize_access(raw)
            db.save_log(data)
        except Exception as e:
            print("access error:", e)


# -----------------------------
# PROCESS MODSEC
# -----------------------------
async def process_audit_log():
    async for line in tail_file(AUDIT_LOG):
        try:
            raw = json.loads(line)
            data = normalize_modsec(raw)
            db.save_log(data)
        except Exception as e:
            print("audit error:", e)


# -----------------------------
# WORKER
# -----------------------------
async def log_forward_worker():
    print("Starting realtime log forwarder...")
    await asyncio.gather(
        process_access_log(),
        process_audit_log()
    )