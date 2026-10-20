"""Rendered-content checks on saved rendered-DOM fixtures. No browser, no network."""

from pathlib import Path

from albert.checks import headers
from albert.checks.rendered import (
    check_blank_targets,
    check_dom_secrets,
    check_forms,
    check_mixed_content,
    check_sri,
    reconcile_meta_csp,
    run_rendered_checks,
)
from albert.core.models import CollectedResponse, Finding, RenderedPage, Severity, SubRequest

FIXTURES = Path(__file__).parent / "fixtures" / "rendered"


def page(name: str, url: str = "https://shop.test/", **kw: object) -> RenderedPage:
    dom = (FIXTURES / name).read_text(encoding="utf-8") if name else ""
    return RenderedPage(url, url, dom, **kw)  # type: ignore[arg-type]


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def test_mixed_content_from_dom_and_requests() -> None:
    reqs = (SubRequest("http://api.shop.test/data", "fetch", outcome="blocked"),)
    found = by_id(check_mixed_content(page("mixed.html", requests=reqs)))
    active = {e.value for e in found["RND-MIXED-ACTIVE"].evidence}
    assert active == {
        "http://shop.test/legacy.css",
        "http://cdn.shop.test/old.js",
        "http://widgets.shop.test/frame",
        "http://api.shop.test/data",
    }
    assert [e.value for e in found["RND-MIXED-PASSIVE"].evidence] == ["http://shop.test/banner.png"]
    assert found["RND-MIXED-ACTIVE"].severity is Severity.MEDIUM
    assert check_mixed_content(page("mixed.html", url="http://shop.test/")) == []  # not HTTPS


def test_forms_on_https_page() -> None:
    found = by_id(check_forms(page("forms.html")))
    assert found["RND-FORM-HTTP-ACTION"].severity is Severity.HIGH  # carries a password field
    assert [e.value for e in found["RND-FORM-HTTP-ACTION"].evidence] == ["http://shop.test/login"]
    cross = [e.value for e in found["RND-FORM-CROSS-ORIGIN"].evidence]
    # http://shop.test/login is the same site (only the scheme differs): that's the HTTP-action
    # finding above, not a cross-origin post, so it isn't counted twice.
    assert cross == ["https://newsletter.other.test/subscribe"]
    assert "RND-PASSWORD-ON-HTTP" not in found


def test_password_on_http_page_reported_once() -> None:
    found = by_id(check_forms(page("forms.html", url="http://shop.test/login")))
    assert found["RND-PASSWORD-ON-HTTP"].severity is Severity.HIGH
    assert "RND-FORM-HTTP-ACTION" not in found  # same issue, not double-counted


def test_sri_and_blank_targets() -> None:
    found = by_id(check_sri(page("sri.html")))
    assert [e.value for e in found["RND-SCRIPT-NO-SRI"].evidence] == [
        "https://cdn.other.test/jquery-3.7.1.min.js"
    ]
    assert [e.value for e in found["RND-SRI-NO-CROSSORIGIN"].evidence] == [
        "https://cdn.other.test/lib.js"
    ]
    assert found["RND-STYLE-NO-SRI"].severity is Severity.INFO
    (blank,) = check_blank_targets(page("sri.html"))
    assert [e.value for e in blank.evidence] == ["https://partner.other.test/"]
    assert blank.severity is Severity.INFO


def test_dom_secrets_redacted() -> None:
    stripe = "sk" + "_live_" + "4" * 24
    dom = f'<div data-aws="AKIAIOSFODNN7EXAMPLE"></div><script>var k="{stripe}";</script>'
    found = by_id(check_dom_secrets(RenderedPage("https://shop.test/", "https://shop.test/", dom)))
    assert found["RND-SECRET-AWS_ACCESS_KEY_ID"].severity is Severity.HIGH  # in markup
    assert "RND-SECRET-STRIPE_KEY" not in found  # inside <script>: owned by JS-SECRET-*
    text = str([f.to_dict() for f in found.values()])
    assert "AKIAIOSFODNN7EXAMPLE" not in text and stripe not in text


def test_static_meta_csp_replaces_missing_csp() -> None:
    html = (FIXTURES / "meta_csp.html").read_text(encoding="utf-8")
    resp = CollectedResponse("https://shop.test/", 200, (("Content-Type", "text/html"),), text=html)
    ids = {f.id for f in headers.check_csp(resp)}
    assert "HDR-CSP-MISSING" not in ids
    assert {"HDR-CSP-META-ONLY", "HDR-CSP-UNSAFE-INLINE", "HDR-CSP-NO-BASE-URI"} <= ids


def test_rendered_meta_csp_reconciles_header_finding() -> None:
    # Static HTML had no CSP on either page; after rendering, page A has a JS-inserted meta CSP.
    a, b = "https://shop.test/a", "https://shop.test/b"
    pages = [
        RenderedPage(a, a, (FIXTURES / "meta_csp.html").read_text(encoding="utf-8")),
        RenderedPage(b, b, "<html><body>no csp</body></html>"),
    ]
    static = [
        CollectedResponse(u, 200, (("Content-Type", "text/html"),), text="<p>") for u in (a, b)
    ]
    before = headers.run_header_checks(static)
    after = by_id(reconcile_meta_csp(before, pages))
    assert after["HDR-CSP-MISSING"].urls == (b,)
    assert after["HDR-CSP-META-ONLY"].urls == (a,)
    assert after["HDR-CSP-META-ONLY"].severity is Severity.LOW


def test_run_groups_and_skips_failed_renders() -> None:
    ok = page("sri.html")
    failed = RenderedPage("https://shop.test/x", "https://shop.test/x", "", error="timeout")
    found = run_rendered_checks([ok, page("sri.html", url="https://shop.test/2"), failed])
    no_sri = next(f for f in found if f.id == "RND-SCRIPT-NO-SRI")
    assert no_sri.urls == ("https://shop.test/", "https://shop.test/2")
