"""client -> edge -> Main WAF -> origin: what each hop sees and blocks."""
import httpx

from conftest import fresh, is_origin_response, site


def test_origin_receives_the_real_client_ip_and_spoofing_is_ignored(qa1):
    my_ip = httpx.get("https://api.ipify.org", timeout=10).text.strip()
    with site(qa1["host"]) as c:
        r = c.get(fresh("/ip-check"), headers={"X-Real-IP": "6.6.6.6", "X-Forwarded-For": "7.7.7.7"})
    assert is_origin_response(r), r.text[:200]
    seen = r.json()["headers"]
    assert seen.get("x-real-ip") == my_ip
    assert "6.6.6.6" not in str(seen) and "7.7.7.7" not in str(seen)


def test_sqli_is_blocked_and_benign_passes(qa1):
    with site(qa1["host"]) as c:
        assert c.get(fresh("/products?id=1' or 1=1-- -")).status_code == 403
        assert is_origin_response(c.get(fresh("/products?id=42")))


def test_tenants_hosts_are_separate(qa1, qa2):
    with site(qa1["host"]) as a, site(qa2["host"]) as b:
        assert a.get(fresh("/")).json()["headers"]["host"] == qa1["host"]
        assert b.get(fresh("/")).json()["headers"]["host"] == qa2["host"]
