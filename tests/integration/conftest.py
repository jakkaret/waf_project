"""Integration tests against the live system through the CDN edge, using only
the QA tenant (scripts/qa/seed.py). Run on Main, where the Mailpit API and the
QA credentials live:

    cd /root/waf_project && /tmp/wt/venv/bin/python -m pytest tests/integration -q

Nothing here touches another tenant's origin or data.
"""
import json
import os
import re
import time
import uuid
from pathlib import Path

import httpx
import pytest

API = os.getenv("QA_API", "https://waf-it-kku.online/api")
MAILPIT = os.getenv("QA_MAILPIT", "http://127.0.0.1:8025")
STATE_PATH = Path(os.getenv("QA_STATE", "/root/qa/qa.json"))
UA = "waf-qa-integration/1.0"
MAIL_DOMAIN = "qa.waf-it-kku.online"


@pytest.fixture(scope="session")
def qa():
    if not STATE_PATH.exists():
        pytest.skip(f"{STATE_PATH} missing -- run scripts/qa/seed.py first")
    return json.loads(STATE_PATH.read_text())


def _login(acct):
    r = httpx.post(f"{API}/auth/login", json={"email": acct["email"], "password": acct["password"]}, timeout=20)
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def auth(qa):
    return {name: _login(acct) for name, acct in qa["accounts"].items()}


@pytest.fixture(scope="session")
def qa1(qa):
    return qa["origins"]["qa1"]


@pytest.fixture(scope="session")
def qa2(qa):
    return qa["origins"]["qa2"]


def site(host: str, **kw) -> httpx.Client:
    """A browser-like client for one QA host: fixed User-Agent (the clearance
    cookie is bound to it), its own cookie jar, no redirects followed."""
    return httpx.Client(base_url=f"https://{host}", headers={"User-Agent": UA}, timeout=25,
                        follow_redirects=False, **kw)


def fresh(path: str) -> str:
    """Unique query string so no cache (edge or browser) can answer for us."""
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}qa_nonce={uuid.uuid4().hex}"


def new_email(tag: str = "t") -> str:
    return f"{tag}-{uuid.uuid4().hex[:10]}@{MAIL_DOMAIN}"


def mail_code(to_addr: str, wait: float = 20.0) -> str | None:
    """The OTP code Mailpit received for to_addr, or None if nothing arrived."""
    deadline = time.time() + wait
    while time.time() < deadline:
        r = httpx.get(f"{MAILPIT}/api/v1/search", params={"query": f'to:"{to_addr}"'}, timeout=10)
        msgs = r.json().get("messages") or []
        if msgs:
            body = httpx.get(f"{MAILPIT}/api/v1/message/{msgs[0]['ID']}", timeout=10).json().get("Text", "")
            m = re.search(r"code is:\s*(\d{4,8})", body)
            if m:
                return m.group(1)
        time.sleep(1)
    return None


def is_origin_response(r: httpx.Response) -> bool:
    """qa-echo answers with JSON describing the request; anything else came
    from the WAF (challenge page, 403, ...)."""
    try:
        return r.status_code == 200 and "headers" in r.json() and "path" in r.json()
    except ValueError:
        return False


@pytest.fixture()
def shield(auth, qa1):
    """Set qa1's CAPTCHA/OTP config for one test and switch both off after."""
    h = auth["qa-admin"]
    base = f"{API}/origins/{qa1['id']}"

    def configure(captcha: dict | None = None, otp: dict | None = None):
        c = {"enabled": False, "engine": "native", "login_paths": ["/login*"], "clearance_ttl": 3600,
             "bypass_ips": [], "pow_difficulty": 1, "mode": "enforce", "exclude_paths": [], **(captcha or {})}
        o = {"enabled": False, "login_paths": ["/login*"], "clearance_ttl": 3600, "bypass_ips": [],
             "code_length": 6, "code_ttl": 300, "channel": "email", "mode": "enforce", "exclude_paths": [],
             "access_mode": "open", "allowed_emails": [], **(otp or {})}
        for kind, body in (("captcha", c), ("otp", o)):
            r = httpx.put(f"{base}/{kind}", json=body, headers=h, timeout=20)
            assert r.status_code == 200, r.text

    yield configure
    configure()
