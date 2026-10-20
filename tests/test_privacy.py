"""Privacy checks on fixtures of captured request attempts + DOM. No live hosts; the real-render
test proves the step-11 refusal still holds (trackers are reported, never contacted).
"""

import json
import os
import sys
from pathlib import Path

import httpx
import pytest
import respx

from albert.checks.privacy import PrivacyInput, lint_trackers, run_privacy_checks
from albert.core.models import (
    CollectedResponse,
    Confidence,
    Finding,
    RenderedPage,
    Severity,
    SubRequest,
)

FIXTURES = Path(__file__).parent / "fixtures" / "privacy"
BASE = "https://shop.test"
S, C = Severity, Confidence


def html(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def captured(dom_override: dict[str, str] | None = None) -> list[RenderedPage]:
    data = json.loads(html("captured.json"))
    pages = []
    for p in data["pages"]:
        reqs = tuple(
            SubRequest(
                r["url"],
                r["resource_type"],
                r.get("method", "GET"),
                r["outcome"],
                r.get("status"),
                r.get("note", ""),
            )
            for r in p["requests"]
        )
        dom = html((dom_override or {}).get(p["url"], p["dom"]))
        pages.append(RenderedPage(p["url"], p["final_url"], dom, reqs))
    return pages


def page(url: str, text: str, *headers: tuple[str, str]) -> CollectedResponse:
    return CollectedResponse(url, 200, (("Content-Type", "text/html"), *headers), text=text)


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def test_third_party_origins_counted_from_recorded_attempts() -> None:
    found = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", captured())))
    f = found["PRIV-THIRD-PARTY-ORIGINS"]
    assert f.title == "Pages load resources from 7 third-party origin(s)"
    assert (f.severity, f.confidence) == (S.INFO, C.HIGH)
    values = [e.value for e in f.evidence]
    assert (
        values[0] == "https://www.googletagmanager.com: 2 request(s) on 2 page(s) "
        "[Google Tag Manager, tag-manager]"
    )
    assert not any("cdn.shop.test" in v for v in values)  # same registrable domain: first party
    assert all("did not fetch" in e.location for e in f.evidence)


def test_trackers_listed_monitoring_excluded() -> None:
    f = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", captured())))["PRIV-TRACKERS"]
    names = [e.value.split(" (")[0] for e in f.evidence]
    assert names == [
        "FingerprintJS",
        "Google Analytics",
        "Google Tag Manager",
        "Hotjar",
        "Meta Pixel",
    ]
    assert f.severity is S.INFO  # a long tracker list is an observation


def test_tracking_before_consent_and_first_party_cookie() -> None:
    crawled = [
        page(
            f"{BASE}/",
            html("home.html"),
            ("Set-Cookie", "_ga=GA1.1.123; Path=/"),
            ("Set-Cookie", "session=x; HttpOnly"),
        )
    ]
    f = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", captured(), crawled)))[
        "PRIV-TRACKING-BEFORE-CONSENT"
    ]
    assert (f.severity, f.confidence) == (S.LOW, C.MEDIUM)
    values = [e.value for e in f.evidence]
    assert "Meta Pixel load attempted on first visit" in values
    assert "_ga (Google Analytics) set by the server on first visit" in values
    assert not any("session" in v for v in values)
    assert "Third-party cookies themselves can't be observed" in f.impact


def test_consent_manager_detection() -> None:
    # No banner anywhere: trackers + no consent mechanism.
    plain = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", captured())))
    assert plain["PRIV-NO-CONSENT-MECHANISM"].severity is S.LOW
    # OneTrust banner markup in the DOM.
    ot = by_id(
        run_privacy_checks(PrivacyInput(f"{BASE}/", captured({f"{BASE}/": "onetrust.html"})))
    )
    assert [e.value for e in ot["PRIV-CONSENT-MANAGER"].evidence] == ["OneTrust"]
    assert "PRIV-NO-CONSENT-MECHANISM" not in ot
    assert "PRIV-TRACKING-BEFORE-CONSENT" in ot  # a banner doesn't help if tags fire anyway
    # A CMP loader attempt counts too (banner script refused, so the DOM has no banner).
    pages = captured()
    extra = SubRequest(
        "https://cdn.cookielaw.org/scripttemplates/otSDKStub.js", "script", outcome="blocked"
    )
    pages[0] = RenderedPage(
        pages[0].url, pages[0].final_url, pages[0].dom, (*pages[0].requests, extra)
    )
    assert "PRIV-CONSENT-MANAGER" in by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", pages)))
    # Generic banner markup suppresses the "no consent mechanism" observation.
    gen = by_id(
        run_privacy_checks(
            PrivacyInput(f"{BASE}/", captured({f"{BASE}/cart": "generic_banner.html"}))
        )
    )
    assert "PRIV-NO-CONSENT-MECHANISM" not in gen


def test_privacy_policy_link() -> None:
    assert "PRIV-NO-PRIVACY-POLICY" not in by_id(
        run_privacy_checks(PrivacyInput(f"{BASE}/", captured()))
    )
    no_link = captured({f"{BASE}/": "cart.html"})
    assert (
        by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", no_link)))[
            "PRIV-NO-PRIVACY-POLICY"
        ].severity
        is S.INFO
    )


def test_fingerprinting_vendor_and_heuristic() -> None:
    vendor = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", captured())))["PRIV-FINGERPRINTING"]
    assert (vendor.severity, vendor.confidence) == (S.LOW, C.MEDIUM)
    js = CollectedResponse(
        f"{BASE}/static/probe.js",
        200,
        (("Content-Type", "text/javascript"),),
        text=html("fp_heuristic.js"),
    )
    heur = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", scripts=[js])))["PRIV-FINGERPRINTING"]
    assert (heur.severity, heur.confidence) == (S.LOW, C.LOW)


def test_static_html_fallback_is_lower_confidence_and_respects_consent_gating() -> None:
    found = by_id(
        run_privacy_checks(
            PrivacyInput(f"{BASE}/", responses=[page(f"{BASE}/", html("static.html"))])
        )
    )
    origins = [e.value for e in found["PRIV-THIRD-PARTY-ORIGINS"].evidence]
    assert found["PRIV-THIRD-PARTY-ORIGINS"].confidence is C.LOW
    assert not any("hotjar" in v for v in origins)  # type="text/plain": consent-gated, not loaded
    assert not any("preconnect-only" in v for v in origins)
    trackers = [e.value for e in found["PRIV-TRACKERS"].evidence]
    assert any(t.startswith("Google Tag Manager") for t in trackers)
    assert any(t.startswith("Pinterest Tag") for t in trackers)


def test_severity_ceiling_is_low() -> None:
    crawled = [page(f"{BASE}/", html("home.html"), ("Set-Cookie", "_fbp=fb.1.2; Path=/"))]
    findings = run_privacy_checks(PrivacyInput(f"{BASE}/", captured(), crawled))
    assert max(f.severity for f in findings) <= S.LOW


def test_tracker_signatures_lint(tmp_path: Path) -> None:
    services, problems = lint_trackers()
    assert problems == [] and len(services) > 40
    bad = tmp_path / "t.yaml"
    bad.write_text(
        "services:\n"
        "- {name: A, category: spying, domains: [a.example]}\n"
        "- {name: B, category: analytics, domains: ['not a host']}\n"
        "- {name: C, category: analytics, cookies: ['(']}\n"
        "- {name: D, category: consent, dom: ['##bad']}\n"
        "- {name: E, category: analytics}\n",
        encoding="utf-8",
    )
    _, problems = lint_trackers(bad)
    text = "\n".join(problems)
    for expected in (
        "category must be one of",
        "bad domain",
        "bad regex",
        "bad CSS selector",
        "needs at least one signal",
    ):
        assert expected in text, expected


def _chromium_installed() -> bool:
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(
        Path(
            os.environ.get("LOCALAPPDATA", "") if sys.platform == "win32" else "~/.cache"
        ).expanduser()
        / "ms-playwright"
    )
    return any(Path(root).glob("chromium*"))


@pytest.mark.skipif(not _chromium_installed(), reason="Chromium not installed")
@respx.mock
async def test_refusal_holds_trackers_reported_never_contacted() -> None:
    """Step-11 refusal unchanged: the page's trackers are refused, then reported."""
    from albert.core.browser import RenderLimits, render_pages
    from albert.core.http_client import ClientLimits, HttpClient
    from albert.core.scope import ScopePolicy

    page_html = (
        "<html><head><script src='https://www.googletagmanager.com/gtag/js?id=G-1'></script>"
        "<script src='https://static.hotjar.com/c/hotjar-1.js'></script></head>"
        "<body><a href='/privacy'>Privacy</a></body></html>"
    )
    respx.get(f"{BASE}/").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"}, text=page_html)
    )
    gtm = respx.route(host="www.googletagmanager.com").mock(return_value=httpx.Response(200))
    hj = respx.route(host="static.hotjar.com").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))
    policy = ScopePolicy(frozenset({"shop.test"}))
    async with HttpClient(policy, ClientLimits(rate=0)) as client:
        rendered = await render_pages(policy, client, [f"{BASE}/"], RenderLimits(settle_ms=800))
    assert not gtm.called and not hj.called  # never contacted
    assert {r.outcome for r in rendered[0].requests if "shop.test" not in r.url} == {"blocked"}
    trackers = by_id(run_privacy_checks(PrivacyInput(f"{BASE}/", rendered)))["PRIV-TRACKERS"]
    assert {e.value.split(" (")[0] for e in trackers.evidence} == {"Google Tag Manager", "Hotjar"}
