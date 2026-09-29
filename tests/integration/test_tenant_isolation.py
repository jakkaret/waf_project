"""An origin's data is visible to its Admins and Viewers only.

Every GET route under /api/origins/{origin_id} that the running backend
exposes is called as a stranger (Admin of a different origin): nothing may
come back. The route list comes from the application itself, so a route added
later is covered without editing this file."""
import os
import sys
from pathlib import Path

import httpx
import pytest

from conftest import API

BACKEND = Path(os.getenv("QA_BACKEND_DIR", "/root/waf_project/dashboard/backend"))


def origin_get_routes():
    sys.path.insert(0, str(BACKEND))
    from dotenv import find_dotenv, load_dotenv
    load_dotenv(find_dotenv(str(BACKEND / "main.py")))
    import main  # noqa: E402  (no server start; only the route table is read)
    out = set()
    for r in main.app.routes:
        path, methods = getattr(r, "path", ""), getattr(r, "methods", set()) or set()
        if path.startswith("/api/origins/{origin_id}") and "GET" in methods:
            out.add(path)
    return sorted(out)


ROUTES = origin_get_routes()


def test_route_discovery_found_the_origin_routes():
    assert len(ROUTES) >= 8, ROUTES


@pytest.mark.parametrize("route", ROUTES)
def test_stranger_gets_nothing(route, auth, qa1):
    url = API[: -len("/api")] + route.replace("{origin_id}", qa1["id"])
    if "{" in url:
        pytest.skip(f"route needs another id: {route}")
    r = httpx.get(url, headers=auth["qa-stranger"], timeout=20)
    assert r.status_code in (401, 403, 404), f"{route} -> {r.status_code}: {r.text[:200]}"


@pytest.mark.parametrize("route", ROUTES)
def test_anonymous_gets_nothing(route, qa1):
    url = API[: -len("/api")] + route.replace("{origin_id}", qa1["id"])
    if "{" in url:
        pytest.skip(f"route needs another id: {route}")
    assert httpx.get(url, timeout=20).status_code in (401, 403, 404)


def test_viewer_reads_but_cannot_change_shield(auth, qa1):
    base = f"{API}/origins/{qa1['id']}"
    assert httpx.get(base, headers=auth["qa-viewer"], timeout=20).status_code == 200
    assert httpx.get(f"{base}/shield-events", headers=auth["qa-viewer"], timeout=20).status_code == 200
    body = {"enabled": True, "login_paths": ["/x*"], "clearance_ttl": 3600, "bypass_ips": [], "code_length": 6,
            "code_ttl": 300, "channel": "email", "mode": "log_only", "exclude_paths": [], "access_mode": "open",
            "allowed_emails": []}
    assert httpx.put(f"{base}/otp", json=body, headers=auth["qa-viewer"], timeout=20).status_code == 403


def test_origin_list_shows_only_own_origins(auth, qa1, qa2):
    ids = {o.get("id") or o.get("origin_id") for o in httpx.get(f"{API}/origins", headers=auth["qa-stranger"], timeout=20).json()["origins"]}
    assert qa2["id"] in ids and qa1["id"] not in ids
