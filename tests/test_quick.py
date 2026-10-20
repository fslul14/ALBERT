"""`quick` end to end against mocked hosts: same-site redirects, cross-site stops, security.txt.

Also proves scan-mode enforcement is unchanged by the quick-only same-site rule.
"""

import httpx
import pytest
import respx

from albert.core.http_client import HttpClient
from albert.core.models import Target
from albert.core.scope import OutOfScopeError, ScopePolicy, registrable_domain
from albert.quick import run_quick

HTML = {"Content-Type": "text/html"}
SEC_TXT = "Contact: mailto:security@shop.co.uk\nExpires: 2099-01-01T00:00:00Z\n"


def _redirect(src: str, dst: str, status: int = 301) -> respx.Route:
    return respx.get(src).mock(return_value=httpx.Response(status, headers={"Location": dst}))


def _not_found() -> None:
    respx.route().mock(return_value=httpx.Response(404))  # catch-all, register last


# --- the narrow rule itself ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "site"),
    [
        ("www.shop.co.uk", "shop.co.uk"),
        ("shop.co.uk", "shop.co.uk"),
        ("co.uk", None),
        ("alice.github.io", "alice.github.io"),
        ("10.0.0.1", None),
        ("localhost", None),
    ],
)
def test_registrable_domain(host: str, site: str | None) -> None:
    assert registrable_domain(host) == site


QUICK = ScopePolicy.for_target(Target("https://shop.co.uk/", "quick"))


@pytest.mark.parametrize(
    "dst", ["https://www.shop.co.uk/", "http://www.shop.co.uk/x", "https://a.b.shop.co.uk/"]
)
def test_same_site_allowed_in_quick(dst: str) -> None:
    widened = QUICK.with_same_site_redirect("https://shop.co.uk/", dst)
    assert widened.check_request("GET", dst)
    assert QUICK.hosts == frozenset({"shop.co.uk"})  # original policy untouched


@pytest.mark.parametrize(
    ("src", "dst", "reason"),
    [
        ("https://shop.co.uk/", "https://evil.co.uk/", "same registrable domain"),
        ("https://shop.co.uk/", "https://shop.co.uk.evil.test/", "same registrable domain"),
        ("https://shop.co.uk/", "https://www.shop.co.uk:8443/", "non-default port"),
        ("https://shop.co.uk/", "ftp://www.shop.co.uk/", "refused"),
        ("https://shop.co.uk/", "https://u:p@www.shop.co.uk/", "refused"),
        ("https://other.co.uk/", "https://www.other.co.uk/", "out of scope"),  # source not in scope
    ],
)
def test_same_site_refused(src: str, dst: str, reason: str) -> None:
    with pytest.raises(OutOfScopeError, match=reason):
        QUICK.with_same_site_redirect(src, dst)


def test_github_pages_sites_are_separate() -> None:
    p = ScopePolicy.for_target(Target("https://alice.github.io/", "quick"))
    with pytest.raises(OutOfScopeError):
        p.with_same_site_redirect("https://alice.github.io/", "https://bob.github.io/")


# --- scan mode is unchanged ---------------------------------------------------------------


def test_scan_policy_never_widens() -> None:
    scan = ScopePolicy.for_target(Target("https://shop.co.uk/", "scan", authorized_by="self"))
    assert scan.mode == "scan"
    with pytest.raises(OutOfScopeError, match="quick-mode only"):
        scan.with_same_site_redirect("https://shop.co.uk/", "https://www.shop.co.uk/")
    with pytest.raises(OutOfScopeError, match="out of scope"):
        scan.check_request("GET", "https://www.shop.co.uk/")
    assert ScopePolicy(frozenset({"shop.co.uk"})).mode == "scan"  # default is strictest


@respx.mock
async def test_scan_client_does_not_follow_www_redirect() -> None:
    _redirect("https://shop.co.uk/", "https://www.shop.co.uk/")
    www = respx.get("https://www.shop.co.uk/").mock(return_value=httpx.Response(200))
    scan = ScopePolicy.for_target(Target("https://shop.co.uk/", "scan", authorized_by="self"))
    async with HttpClient(scan) as client:
        chain = await client.fetch_chain("https://shop.co.uk/")
    assert chain.not_followed == "https://www.shop.co.uk/"
    assert not www.called


# --- quick end to end ---------------------------------------------------------------------


@respx.mock
async def test_apex_to_www_followed_and_scanned() -> None:
    _redirect("https://shop.co.uk/", "https://www.shop.co.uk/")
    respx.get("https://www.shop.co.uk/").mock(
        return_value=httpx.Response(200, headers={**HTML, "Server": "nginx/1.25.3"})
    )
    respx.get("https://www.shop.co.uk/.well-known/security.txt").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/plain"}, text=SEC_TXT)
    )
    _not_found()
    result = await run_quick(Target("https://shop.co.uk/", "quick"))
    assert result.pages == [
        "https://shop.co.uk/",
        "https://www.shop.co.uk/",
        "https://www.shop.co.uk/.well-known/security.txt",
        "http://www.shop.co.uk/",  # plain-HTTP fetch for the HTTP->HTTPS redirect check
    ]
    assert any("same registrable domain" in n for n in result.notes)
    ids = {f.id for f in result.findings}
    assert "HDR-CSP-MISSING" in ids and "SEC-TXT-PRESENT" in ids
    csp = next(f for f in result.findings if f.id == "HDR-CSP-MISSING")
    assert csp.urls == ("https://www.shop.co.uk/",)  # the final page was scanned
    assert result.skipped == [] and result.errors == []


@respx.mock
async def test_http_to_https_followed() -> None:
    _redirect("http://shop.co.uk/", "https://shop.co.uk/")
    respx.get("https://shop.co.uk/").mock(return_value=httpx.Response(200, headers=HTML))
    _not_found()
    result = await run_quick(Target("http://shop.co.uk/", "quick"))
    assert result.pages[:2] == ["http://shop.co.uk/", "https://shop.co.uk/"]
    assert "redirect 301: http://shop.co.uk/ -> https://shop.co.uk/" in result.notes
    assert "SEC-TXT-MISSING" in {f.id for f in result.findings}


@respx.mock
async def test_http_apex_to_https_www_followed() -> None:
    _redirect("http://shop.co.uk/", "https://www.shop.co.uk/")
    respx.get("https://www.shop.co.uk/").mock(return_value=httpx.Response(200, headers=HTML))
    _not_found()
    result = await run_quick(Target("http://shop.co.uk/", "quick"))
    assert result.pages[1] == "https://www.shop.co.uk/"


@respx.mock
async def test_cross_domain_redirect_stopped_and_reported() -> None:
    _redirect("https://shop.co.uk/", "https://evil.co.uk/")
    evil = respx.route(host="evil.co.uk").mock(return_value=httpx.Response(200))
    _not_found()
    result = await run_quick(Target("https://shop.co.uk/", "quick"))
    assert not evil.called
    assert len(result.skipped) == 1 and "https://evil.co.uk/ not followed" in result.skipped[0]
    assert result.pages[0] == "https://shop.co.uk/"


@respx.mock
async def test_coverage_stubs_noted() -> None:
    respx.get("https://shop.co.uk/").mock(return_value=httpx.Response(200, headers=HTML))
    _not_found()
    result = await run_quick(Target("https://shop.co.uk/", "quick"))
    assert result.checks_run == ["headers", "cookies", "cors", "disclosure", "security_txt", "tls"]
    assert not any("TLS certificate" in n for n in result.notes)  # TLS is covered now
    assert any("DNS/email" in n for n in result.notes)
