"""Phase 2 item 4 -- the access-log pipeline records each request exactly once,
with the real client IP and the tenant's host, not the edge's identity.

One marked GET to qa1 (client -> edge -> Main waf-nginx -> qa tunnel) must land
as exactly ONE row in ClickHouse access_logs whose:
  * host  == the tenant host (attribution, so tenant isolation can scope on it),
  * client_ip == the real originating client IP -- NOT an edge node's IP and not
    a private/waf-net address (the whole point of the $waf_client_ip real-IP
    chain: geo $from_trusted_proxy -> $http_x_real_ip),
  * edge_node names the edge it entered through (the row came via the edge path).

Rate-limiter enforcement logic (sliding window, over-limit -> 401 that nginx
maps to 429, Retry-After, IP-keyed bucket, static-asset bypass, fail-open) is
covered exhaustively by dashboard/backend/tests/test_dynamic_rate_limiter.py;
its real-client-IP keying is the same $waf_client_ip proven correct here.

Reads ClickHouse directly (authoritative), not the logs API, so it checks the
stored row shape. Skips cleanly if ClickHouse isn't reachable from the runner.
"""
import os
import time
import uuid

import pytest

from conftest import fresh, site

CH_HOST = os.getenv("QA_CH_HOST", "127.0.0.1")
CH_PORT = int(os.getenv("QA_CH_PORT", "8123"))
CH_PASSWORD = os.getenv("QA_CH_PASSWORD", "mysecurepassword")

EDGE_IPS = {"45.154.26.91", "57.158.25.236"}


def _ch_client():
    try:
        import clickhouse_connect
    except ImportError:
        pytest.skip("clickhouse_connect not installed on this runner")
    try:
        c = clickhouse_connect.get_client(
            host=CH_HOST, port=CH_PORT, username="default", password=CH_PASSWORD, connect_timeout=5
        )
        c.ping()
        return c
    except Exception as e:
        pytest.skip(f"ClickHouse not reachable from runner: {e}")


def _rows_for(ch, marker: str):
    for _ in range(20):
        res = ch.query(
            "SELECT host, client_ip, edge_node FROM access_logs WHERE url LIKE {m:String}",
            parameters={"m": f"%{marker}%"},
        )
        if res.result_rows:
            return res.result_rows
        time.sleep(3)
    return []


def test_one_request_is_one_row_with_real_client_ip_and_host(qa1):
    marker = f"pipe{uuid.uuid4().hex[:12]}"
    with site(qa1["host"]) as c:
        r = c.get(fresh(f"/pipeline/{marker}"))
    assert r.status_code in (200, 403, 404), f"unexpected pre-log status {r.status_code}"

    ch = _ch_client()
    rows = _rows_for(ch, marker)
    assert rows, "the request produced no access_logs row (pipeline not delivering)"

    assert len(rows) == 1, f"1 request must produce exactly 1 row, got {len(rows)}: {rows}"
    host, client_ip, edge_node = rows[0]
    assert host == qa1["host"], f"host attribution wrong: {host!r}"
    assert client_ip and client_ip not in EDGE_IPS, f"client_ip is missing or an edge IP: {client_ip!r}"
    assert not client_ip.startswith(("172.18.", "10.", "192.168.", "127.")), (
        f"client_ip is a private/internal address, real IP not preserved: {client_ip!r}"
    )
    assert edge_node, f"edge_node not recorded (row did not come via an edge): {edge_node!r}"
