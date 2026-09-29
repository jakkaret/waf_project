"""CAPTCHA / OTP end to end through the edge on qa1, with real mail (Mailpit).
These are the flows that broke in production on 2026-09-29 without any unit
test noticing: the clearance cookie never validated, POST skipped the gate."""
import hashlib
import re
import time

import httpx
import pytest

from conftest import API, fresh, is_origin_response, mail_code, new_email, site

OTP_PAGE = "ยืนยันตัวตนด้วยอีเมล"


def otp_verify(c: httpx.Client, host: str, email: str) -> httpx.Response:
    r = c.post("/cdn-cgi/otp/request", json={"host": host, "email": email})
    assert r.status_code == 200, r.text
    code = mail_code(email)
    assert code, f"no OTP mail reached Mailpit for {email}"
    return c.post("/cdn-cgi/otp/verify", json={"challenge_id": r.json()["challenge_id"], "code": code, "host": host})


def test_otp_gate_then_clearance_reaches_the_origin(shield, qa1):
    shield(otp={"enabled": True})
    with site(qa1["host"]) as c:
        page = c.get(fresh("/login"))
        assert OTP_PAGE in page.text, "GET /login without clearance must show the OTP page"
        assert c.post(fresh("/login"), data={"u": "x"}).status_code == 403, "POST without clearance must be blocked"
        assert is_origin_response(c.get(fresh("/public"))), "unprotected path must pass"

        assert otp_verify(c, qa1["host"], new_email()).status_code == 200
        assert is_origin_response(c.get(fresh("/login"))), "after OTP the visitor must reach the origin (no loop)"
        assert is_origin_response(c.post(fresh("/login"), data={"u": "x"})), "POST with clearance must pass"


def test_clearance_is_not_shared_through_a_cache(shield, qa1):
    """A page fetched with clearance must not be served to someone without it."""
    shield(otp={"enabled": True})
    path = fresh("/login/profile")
    with site(qa1["host"]) as cleared:
        assert otp_verify(cleared, qa1["host"], new_email()).status_code == 200
        assert is_origin_response(cleared.get(path))
    with site(qa1["host"]) as anon:
        r = anon.get(path)
        assert not is_origin_response(r), "edge served a protected page from cache to a visitor without clearance"


def test_wrong_code_and_other_device_are_refused(shield, qa1):
    shield(otp={"enabled": True})
    email = new_email()
    with site(qa1["host"]) as c:
        r = c.post("/cdn-cgi/otp/request", json={"host": qa1["host"], "email": email})
        cid = r.json()["challenge_id"]
        code = mail_code(email)
        wrong = "000000" if code != "000000" else "111111"
        assert c.post("/cdn-cgi/otp/verify", json={"challenge_id": cid, "code": wrong, "host": qa1["host"]}).status_code == 400
    with httpx.Client(base_url=f"https://{qa1['host']}", headers={"User-Agent": "another-browser/9"}, timeout=25) as other:
        r = other.post("/cdn-cgi/otp/verify", json={"challenge_id": cid, "code": code, "host": qa1["host"]})
        assert r.status_code == 400 and "mismatch" in r.text


def test_allowlist_sends_only_to_listed_and_revokes_immediately(shield, qa1):
    listed, unlisted = new_email("listed"), new_email("unlisted")
    shield(otp={"enabled": True, "access_mode": "allowlist", "allowed_emails": [listed]})
    with site(qa1["host"]) as c:
        r = c.post("/cdn-cgi/otp/request", json={"host": qa1["host"], "email": unlisted})
        assert r.status_code == 200 and r.json()["success"], "unlisted must get the same answer as listed"
        assert mail_code(unlisted, wait=6) is None, "no mail may be sent to an unlisted address"

        assert otp_verify(c, qa1["host"], listed).status_code == 200
        assert is_origin_response(c.get(fresh("/login")))

        shield(otp={"enabled": True, "access_mode": "allowlist", "allowed_emails": [new_email("someone-else")]})
        time.sleep(1)
        assert not is_origin_response(c.get(fresh("/login"))), "removing the email must revoke the existing cookie"


def test_log_only_lets_everyone_through(shield, qa1):
    shield(otp={"enabled": True, "mode": "log_only"})
    with site(qa1["host"]) as c:
        assert is_origin_response(c.get(fresh("/login")))
        assert is_origin_response(c.post(fresh("/login"), data={"u": "x"}))


def test_excluded_path_is_never_gated(shield, qa1):
    shield(otp={"enabled": True, "exclude_paths": ["/login/ajax*"]})
    with site(qa1["host"]) as c:
        assert is_origin_response(c.post(fresh("/login/ajax"), data={"a": "1"}))
        assert c.post(fresh("/login"), data={"a": "1"}).status_code == 403


def test_captcha_pow_then_origin(shield, qa1):
    shield(captcha={"enabled": True, "pow_difficulty": 1})
    with site(qa1["host"]) as c:
        page = c.get(fresh("/login")).text
        cid = re.search(r'"challenge_id":"([^"]+)"', page).group(1)
        prefix = re.search(r'"prefix":"([^"]+)"', page).group(1)
        diff = int(re.search(r'"difficulty":(\d+)', page).group(1))
        nonce = next(n for n in range(2_000_000) if hashlib.sha256(f"{prefix}{n}".encode()).hexdigest().startswith("0" * diff))
        r = c.post("/cdn-cgi/challenge/verify", json={"challenge_id": cid, "nonce": nonce, "host": qa1["host"]})
        assert r.status_code == 200, r.text
        assert is_origin_response(c.get(fresh("/login")))


def test_shield_activity_records_real_client_ip(shield, auth, qa1):
    shield(otp={"enabled": True})
    my_ip = httpx.get("https://api.ipify.org", timeout=10).text.strip()
    with site(qa1["host"]) as c:
        c.get(fresh("/login"))
    for _ in range(15):
        r = httpx.get(f"{API}/origins/{qa1['id']}/shield-events", params={"hours": 1}, headers=auth["qa-admin"], timeout=20)
        recent = r.json().get("recent", [])
        if any(e["event"] == "challenge_shown" and e["client_ip"] == my_ip for e in recent):
            return
        time.sleep(2)
    pytest.fail("challenge_shown with the real client IP never showed up in Shield Activity")
