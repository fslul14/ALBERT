"""Cookie checks on saved Set-Cookie fixtures. No network; Albert never sends cookies."""

from pathlib import Path

from albert.checks.cookies import check_cookies, parse_set_cookie, run_cookie_checks
from albert.core.models import CollectedResponse, Finding, Severity
from albert.core.report import build_report_data

FIXTURES = Path(__file__).parent / "fixtures" / "cookies"
LOGIN = "https://www.shop.test/account/login"


def load(name: str, url: str = LOGIN) -> CollectedResponse:
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    headers = [("Set-Cookie", ln) for ln in lines if ln.strip() and not ln.startswith("#")]
    return CollectedResponse(url, 200, (("Content-Type", "text/html"), *headers))


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def test_parse() -> None:
    c = parse_set_cookie("Sid=v=1; Path=/; Secure; HttpOnly; SameSite=Lax; Domain=.x.test")
    assert c is not None
    assert c.name == "Sid" and c.secure and c.httponly and c.samesite == "lax"
    assert c.attrs["domain"] == ".x.test"
    assert parse_set_cookie("novalue") is None


def test_fixture_findings() -> None:
    found = by_id(check_cookies(load("shop_login.txt")))
    expected = {
        "COOKIE-NO-SECURE-PHPSESSID": Severity.MEDIUM,
        "COOKIE-NO-HTTPONLY-PHPSESSID": Severity.MEDIUM,
        "COOKIE-NO-SAMESITE-PHPSESSID": Severity.LOW,
        "COOKIE-BROAD-DOMAIN-remember_me": Severity.LOW,
        "COOKIE-NO-SECURE-tracker": Severity.LOW,
        "COOKIE-NO-HTTPONLY-tracker": Severity.INFO,
        "COOKIE-SAMESITE-NONE-INSECURE-tracker": Severity.LOW,
        "COOKIE-PREFIX-MISUSE-__Host-auth": Severity.LOW,
        "COOKIE-BROAD-DOMAIN-__Host-auth": Severity.LOW,
        "COOKIE-PREFIX-MISUSE-__Secure-pref": Severity.LOW,
        "COOKIE-NO-SECURE-__Secure-pref": Severity.LOW,
    }
    for fid, sev in expected.items():
        assert fid in found, fid
        assert found[fid].severity is sev, fid
    # Well-configured cookies raise nothing above Info; CSRF tokens are exempt from HttpOnly.
    for name in ("cart_id", "good_session", "XSRF-TOKEN"):
        assert all(f.severity is Severity.INFO for f in found.values() if f.id.endswith(f"-{name}"))
    assert "COOKIE-NO-HTTPONLY-XSRF-TOKEN" not in found
    assert "Domain" in found["COOKIE-PREFIX-MISUSE-__Host-auth"].title
    assert max(f.severity for f in found.values()) <= Severity.MEDIUM


def test_per_cookie_ids_stay_distinct_but_group_across_pages() -> None:
    def resp(url: str) -> CollectedResponse:
        return CollectedResponse(
            url, 200, (("Set-Cookie", "a=1; Path=/"), ("Set-Cookie", "b=2; Path=/"))
        )

    grouped = run_cookie_checks([resp("https://x.test/1"), resp("https://x.test/2")])
    httponly = [f for f in grouped if f.id.startswith("COOKIE-NO-HTTPONLY-")]
    assert sorted(f.id for f in httponly) == ["COOKIE-NO-HTTPONLY-a", "COOKIE-NO-HTTPONLY-b"]
    assert all(f.urls == ("https://x.test/1", "https://x.test/2") for f in httponly)


def test_http_site_and_prefix_over_http() -> None:
    r = CollectedResponse(
        "http://x.test/",
        200,
        (("Set-Cookie", "sid=1; HttpOnly; SameSite=Lax"), ("Set-Cookie", "__Secure-x=1; Secure")),
    )
    ids = {f.id for f in check_cookies(r)}
    assert "COOKIE-NO-SECURE-sid" not in ids  # moot without HTTPS (HSTS/TLS checks cover that)
    assert "COOKIE-PREFIX-MISUSE-__Secure-x" in ids


def test_cookie_values_never_reported() -> None:
    cookie_value = "deadbeef0123"
    data = build_report_data_for(check_cookies(load("shop_login.txt")))
    assert cookie_value not in data
    assert "PHPSESSID=[value not recorded]; path=/" in data


def build_report_data_for(findings: list[Finding]) -> str:
    from albert.core.models import ScanResult, Target

    r = ScanResult(Target(LOGIN, "quick"))
    r.findings = findings
    return str(build_report_data(r))
