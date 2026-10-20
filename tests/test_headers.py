"""Header checks against saved response fixtures. No network."""

from pathlib import Path

import pytest

from albert.checks import headers as h
from albert.core.models import CollectedResponse, Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "headers"


def load(name: str, url: str) -> CollectedResponse:
    """Parse a saved raw response head ('#' lines are comments)."""
    lines = [
        ln
        for ln in (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    version, status = lines[0].split()[:2]
    pairs = tuple((k.strip(), v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:]))
    return CollectedResponse(url, int(status), pairs, version)


def resp(url: str = "https://x.test/", status: int = 200, **headers: str) -> CollectedResponse:
    pairs = [("Content-Type", "text/html")] + [(k.replace("_", "-"), v) for k, v in headers.items()]
    return CollectedResponse(url, status, tuple(pairs))


def ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


def test_bare_apache() -> None:
    found = h.run_header_checks([load("bare_apache.txt", "https://shop.test/account/login")])
    assert ids(found) == {
        "HDR-CSP-MISSING",
        "HDR-CLICKJACKING",
        "HDR-HSTS-MISSING",
        "HDR-NOSNIFF-MISSING",
        "HDR-REFERRER-MISSING",
        "HDR-PERMISSIONS-MISSING",
        "HDR-COOP-MISSING",
        "HDR-COEP-MISSING",
        "HDR-CORP-MISSING",
        "HDR-VERSION-BANNER",
        "HDR-ETAG-INODE",
        "HDR-DEPRECATED-X-XSS-PROTECTION",
        "HDR-CACHE-PUBLIC-SET-COOKIE",
        "HDR-PROTOCOLS",
    }
    banner = next(f for f in found if f.id == "HDR-VERSION-BANNER")
    assert {e.location for e in banner.evidence} == {"server", "x-powered-by"}


def test_weak() -> None:
    found = h.run_header_checks([load("weak.txt", "https://app.test/")])
    assert ids(found) == {
        "HDR-CSP-UNSAFE-INLINE",
        "HDR-CSP-UNSAFE-EVAL",
        "HDR-CSP-WILDCARD",
        "HDR-CSP-NO-BASE-URI",
        "HDR-FRAME-ANCESTORS-WILDCARD",
        "HDR-HSTS-SHORT",
        "HDR-HSTS-NO-SUBDOMAINS",
        "HDR-HSTS-NOT-PRELOAD-READY",
        "HDR-REFERRER-UNSAFE",
        "HDR-PERMISSIONS-WILDCARD",
        "HDR-CORS-WILDCARD-CREDENTIALS",
        "HDR-DEBUG-HEADER",
        "HDR-BACKEND-DISCLOSED",
        "HDR-INTERNAL-IP",
        "HDR-TRACE-ID",
        "HDR-SERVER-TIMING",
        "HDR-CDN-WAF",
        "HDR-PROTOCOLS",
    }
    by_id = {f.id: f for f in found}
    assert by_id["HDR-CDN-WAF"].title == "CDN/WAF detected: Cloudflare"
    assert by_id["HDR-SERVER-TIMING"].severity is Severity.LOW  # names db/desc
    assert len(by_id["HDR-DEBUG-HEADER"].evidence) == 2


def test_hardened_only_info() -> None:
    found = h.run_header_checks([load("hardened.txt", "https://secure.test/")])
    assert ids(found) == {"HDR-PROTOCOLS"}


def test_severity_is_honest() -> None:
    found = h.run_header_checks(
        [load(n, "https://a.test/login") for n in ("bare_apache.txt", "weak.txt", "hardened.txt")]
    )
    assert max(f.severity for f in found) <= Severity.MEDIUM


def test_groups_across_pages() -> None:
    found = h.run_header_checks([resp("https://x.test/a"), resp("https://x.test/b")])
    csp = [f for f in found if f.id == "HDR-CSP-MISSING"]
    assert len(csp) == 1
    assert csp[0].urls == ("https://x.test/a", "https://x.test/b")
    assert len(csp[0].evidence) == 1


def test_csp_report_only_and_non_documents() -> None:
    ro = h.check_csp(resp(Content_Security_Policy_Report_Only="default-src 'self'"))
    assert ids(ro) == {"HDR-CSP-REPORT-ONLY"}
    json_resp = CollectedResponse(
        "https://x.test/api", 200, (("Content-Type", "application/json"),)
    )
    assert h.check_csp(json_resp) == [] and h.check_framing(json_resp) == []


def test_csp_multiple_policies_intersect() -> None:
    r = resp(Content_Security_Policy="script-src 'unsafe-inline', script-src 'self'")
    assert "HDR-CSP-UNSAFE-INLINE" not in ids(h.check_csp(r))
    assert ids(h.check_csp(resp(Content_Security_Policy="upgrade-insecure-requests"))) >= {
        "HDR-CSP-NO-SCRIPT-POLICY",
        "HDR-CSP-NO-OBJECT-SRC",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=0", {"HDR-HSTS-DISABLED"}),
        ("includeSubDomains", {"HDR-HSTS-INVALID"}),
        ('max-age="31536000"; includeSubDomains', {"HDR-HSTS-NOT-PRELOAD-READY"}),
    ],
)
def test_hsts_values(value: str, expected: set[str]) -> None:
    assert ids(h.check_hsts(resp(Strict_Transport_Security=value))) == expected


def test_hsts_ignored_over_http() -> None:
    assert h.check_hsts(resp("http://x.test/")) == []


def test_framing() -> None:
    assert ids(h.check_framing(resp(X_Frame_Options="DENY"))) == {"HDR-FRAME-ANCESTORS-MISSING"}
    fa = resp(Content_Security_Policy="frame-ancestors 'self'", X_Frame_Options="ALLOW-FROM x")
    assert h.check_framing(fa) == []  # frame-ancestors overrides XFO


def test_cors_null_with_credentials_is_medium() -> None:
    r = resp(Access_Control_Allow_Origin="null", Access_Control_Allow_Credentials="true")
    (f,) = h.check_cors(r)
    assert f.id == "HDR-CORS-NULL" and f.severity is Severity.MEDIUM


def test_etag_two_part_not_flagged() -> None:
    assert h.check_etag_inode(resp(ETag='"2aa6-5f3c1b2e4d0c0-gzip"')) == []


def test_sensitive_cache_and_lab_private_ip() -> None:
    assert ids(h.check_cache_control(resp("https://x.test/account/settings"))) == {
        "HDR-CACHE-SENSITIVE"
    }
    assert h.check_cache_control(resp("https://x.test/blog/post")) == []
    lab = resp("http://localhost:3000/", X_Upstream="10.0.0.5:3000")
    assert ids(h.check_leaky_headers(lab)) == {"HDR-BACKEND-DISCLOSED"}


def test_protocols_http11_not_observed() -> None:
    (f,) = h.check_protocols(resp())
    assert [e.value for e in f.evidence] == [
        "HTTP/2: not observed (client is HTTP/1.1-only)",
        "HTTP/3: not advertised (no h3 in Alt-Svc)",
    ]
    (f,) = h.check_protocols(resp(Alt_Svc='h3=":443"; ma=86400, h2=":443"'))
    assert f.evidence[0].value == "HTTP/2: advertised via Alt-Svc"
    assert f.evidence[1].value == "HTTP/3: advertised via Alt-Svc"
