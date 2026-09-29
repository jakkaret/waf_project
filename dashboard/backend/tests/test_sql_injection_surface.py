"""Phase 2 item 2 -- SQL-injection surface regression guard.

bandit flags ~55 B608 (string-built SQL) across the backend. The audit
(docs/KNOWN_ISSUES.md #16) found every one interpolates only server
constants, ints coerced with int(), datetimes parsed to real datetimes,
ClickHouse bound params, or tenant strings routed through
escape_like_value / build_domain_pattern_sql behind an exact-ownership gate.
None takes raw tenant input.

These tests pin that invariant at the two chokepoints every tenant-facing
ClickHouse query funnels through, so a future edit that drops the escaping
fails here rather than shipping an injectable query:

  * tenant_service.build_tenant_origin_filter / build_domain_pattern_sql
    (the origin/analytics/cdn/copilot/logs domain filter), and
  * ClickHouseService.get_logs' own search / method interpolation.

For any value carrying a quote or backslash, the emitted SQL must contain the
*escaped* form and must NOT contain the raw payload verbatim (a raw quote would
close the string literal early -- the definition of a break-out).
"""
import pytest

from services.tenant_service import build_tenant_origin_filter, build_domain_pattern_sql
from services.clickhouse_service import ClickHouseService, escape_like_value

# Payloads deliberately avoid the legacy keyword branches (dvwa/.php/juice/...)
# so the value itself is what gets interpolated and can be checked.
PAYLOADS = [
    "evil.example' OR '1'='1",
    "evil.example'; DROP TABLE access_logs; --",
    "evil.example\\' UNION SELECT secret FROM x --",
    "evil.example' OR 1=1 --",
]


def _assert_escaped(sql: str, payload: str):
    assert escape_like_value(payload) in sql, f"escaped payload missing from SQL: {sql!r}"
    # A raw single quote from the payload must never survive unescaped: every
    # "'" in the emitted SQL that came from the payload is preceded by a
    # backslash. Checking the raw payload is absent is the concrete break-out test.
    assert payload not in sql, f"raw (unescaped) payload leaked into SQL: {sql!r}"


class _FakeResult:
    result_rows = []


class _FakeClient:
    def __init__(self):
        self.queries = []

    def query(self, sql, *a, **k):
        self.queries.append(sql)
        return _FakeResult()


@pytest.mark.parametrize("payload", PAYLOADS)
def test_build_domain_pattern_sql_escapes(payload):
    # build_domain_pattern_sql normalises host to lower-case, so the escaped
    # form that lands in the SQL is of the lower-cased value.
    _assert_escaped(build_domain_pattern_sql(payload), payload.lower())


@pytest.mark.parametrize("payload", PAYLOADS)
def test_admin_origin_filter_escapes(payload):
    # Admin naming a specific origin: value is interpolated (no ownership gate),
    # so the escaping is the only thing standing between it and the query.
    sql = build_tenant_origin_filter(payload, user_domains=[], is_admin=True)
    _assert_escaped(sql, payload.lower())


@pytest.mark.parametrize("payload", PAYLOADS)
def test_non_admin_unowned_origin_is_refused_not_interpolated(payload):
    # A non-admin asking for an origin they don't own must get the fail-closed
    # sentinel, never a query built from their string.
    assert build_tenant_origin_filter(payload, user_domains=["mine.example.com"], is_admin=False) == "1=0"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_get_logs_search_and_method_are_escaped(payload):
    svc = ClickHouseService.__new__(ClickHouseService)  # skip __init__ (no live CH)
    svc.connected = True
    svc.client = _FakeClient()
    svc.get_logs(search=payload, method_filter=payload, limit=20, page=1)
    assert svc.client.queries, "get_logs never issued a query"
    for sql in svc.client.queries:
        _assert_escaped(sql, payload)


def test_get_logs_limit_offset_are_integers_not_injectable():
    # limit/offset go into "LIMIT {limit} OFFSET {offset}" unquoted; get_logs
    # clamps them to ints, so a string can never reach that slot.
    svc = ClickHouseService.__new__(ClickHouseService)
    svc.connected = True
    svc.client = _FakeClient()
    svc.get_logs(search="", limit=10**9, page=10**9)  # absurd values, must be clamped
    main_q = svc.client.queries[0]
    assert "LIMIT 1000 OFFSET" in main_q, main_q  # limit capped at 1000
