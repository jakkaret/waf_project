import asyncio
import json
import os
import time
from services.dynamodb_service import DynamoDBService
from decimal import Decimal

db = DynamoDBService()
BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../")
)
ACCESS_LOG = os.path.join(BASE_DIR, "logs/nginx/access.json")
AUDIT_LOG = os.path.join(BASE_DIR, "logs/modsecurity/audit.json")
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
            print("RAW LINE:", line)
            yield line.strip()
def normalize_log(data: dict, source: str) -> dict:
    if source == "access":
        return {
            "log_id": data.get("request_id"),
            "ip": data.get("remote_addr"),
            "method": data.get("request", "").split(" ")[0],
            "url": data.get("request", "").split(" ")[1],
            "status": int(data.get("status", 0)),
            "user_agent": data.get("http_user_agent"),
            "referer": data.get("http_referer"),
            "request_time": float(data.get("request_time", 0)),
            "timestamp": int(time.time()),
            "source": "nginx",
            "alert": False
        }
    
    elif source == "audit":
        tx = data.get("transaction", {})
        req = tx.get("request", {})
        res = tx.get("response", {})
        return {
            "log_id": tx.get("unique_id"),
            "ip": tx.get("client_ip"),
            "method": req.get("method"),
            "url": req.get("uri"),
            "status": int(res.get("http_code", 0)),
            "user_agent": req.get("headers", {}).get("user-agent"),
            "referer": req.get("headers", {}).get("referer"),
            "timestamp": int(time.time()),
            "source": "modsecurity",
            "alert": True if tx.get("response", {}).get("http_code") == 403 else False
        }
    
    return {}
async def process_access_log():
    async for line in tail_file(ACCESS_LOG):
        try:
            data = json.loads(line)
            normalized = normalize_log(data, "access")
            db.save_log(normalized)
        except Exception as e:
            print("access error:", e)

async def process_audit_log():
    async for line in tail_file(AUDIT_LOG):
        try:
            data = json.loads(line)
            normalized = normalize_log(data, "audit")
            db.save_log(normalized)
        except Exception as e:
            print("audit error:", e)
async def log_forward_worker():
    print(" Starting realtime log forwarder...")
    await asyncio.gather(
        process_access_log(),
        process_audit_log()
    )
