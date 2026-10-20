"""Information-disclosure checks on saved fixtures. No network; nothing is ever fetched."""

from pathlib import Path

import pytest

from albert.checks.disclosure import check_disclosure, run_disclosure_checks, visible_text
from albert.core.models import CollectedResponse, Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "disclosure"


def load(
    name: str, path: str = "/page", status: int = 200, ctype: str = "text/html"
) -> CollectedResponse:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return CollectedResponse(
        f"https://shop.test{path}", status, (("Content-Type", ctype),), text=text
    )


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def test_django_debug_page_with_stack_is_medium() -> None:
    found = by_id(check_disclosure(load("django_debug.html", status=500)))
    debug = found["DISC-DEBUG-PAGE"]
    assert debug.title.endswith("Django") and debug.severity is Severity.MEDIUM
    assert any("Python stack trace" in e.location for e in debug.evidence)
    assert "DISC-STACK-TRACE" not in found  # folded into the debug finding


def test_tutorial_quoting_errors_does_not_fire() -> None:
    found = check_disclosure(load("tutorial.html"))
    noisy = {"DISC-DEBUG-PAGE", "DISC-STACK-TRACE", "DISC-DB-ERROR", "DISC-SERVER-PATH"}
    assert noisy.isdisjoint({f.id for f in found})


def test_same_trace_on_error_page_fires() -> None:
    """The tutorial's guard is context, not blindness: on a 500 the quoted trace counts."""
    found = by_id(check_disclosure(load("tutorial.html", status=500)))
    assert "DISC-STACK-TRACE" in found


def test_mysql_error_and_server_path() -> None:
    found = by_id(check_disclosure(load("mysql_error.html")))
    assert found["DISC-DB-ERROR"].severity is Severity.MEDIUM
    assert "MySQL" in found["DISC-DB-ERROR"].title
    assert [e.value for e in found["DISC-SERVER-PATH"].evidence] == ["/var/www/html/products.php"]
    assert found["DISC-SERVER-PATH"].severity is Severity.LOW


def test_java_stack_trace_low() -> None:
    found = by_id(check_disclosure(load("java_500.html", status=500)))
    trace = found["DISC-STACK-TRACE"]
    assert trace.title == "Stack trace exposed (Java)" and trace.severity is Severity.LOW


def test_directory_listing_low() -> None:
    (f,) = [
        f for f in check_disclosure(load("listing.html", "/files/")) if f.id == "DISC-DIR-LISTING"
    ]
    assert f.severity is Severity.LOW


def test_comments_and_source_leaks() -> None:
    found = by_id(check_disclosure(load("comments.html")))
    cred = found["DISC-CREDENTIAL-COMMENT"]
    text = " ".join(e.value for e in cred.evidence)
    assert "Hunter2!x" not in text and "s3cretpw" not in text
    assert "<masked, 9 chars>" in text and "root:<masked, 8 chars>@" in text
    everything = str([f.to_dict() for f in found.values()])
    assert "Hunter2!x" not in everything and "s3cretpw" not in everything
    assert len(cred.evidence) == 2  # the {{ template }} placeholder is ignored
    notes = [e.value for e in found["DISC-DEV-COMMENT"].evidence]
    assert any("TODO" in n for n in notes) and any("FIXME" in n for n in notes)
    assert not any("Footer" in n or "[if" in n for n in notes)
    hosts = {e.value for e in found["DISC-INTERNAL-HOST"].evidence}
    assert {"db01.corp.internal", "jenkins.corp.internal", "http://localhost:3000/debug"} <= hosts
    assert [e.value for e in found["DISC-EMAIL"].evidence] == ["support@shop.test"]
    apis = [e.value for e in found["DISC-API-ENDPOINT"].evidence]
    assert apis == ["/api/v1/orders", "https://api.shop.test/graphql"]
    assert found["DISC-EMAIL"].severity is Severity.INFO
    assert found["DISC-API-ENDPOINT"].severity is Severity.INFO
    assert found["DISC-DEV-COMMENT"].severity is Severity.INFO


def test_robots_and_sitemap_reported_not_fetched() -> None:
    (robots,) = check_disclosure(load("robots.txt", "/robots.txt", ctype="text/plain"))
    assert [e.value for e in robots.evidence] == ["/admin/", "/backup.sql", "/staging/preview"]
    (sitemap,) = check_disclosure(load("sitemap.xml", "/sitemap.xml", ctype="application/xml"))
    assert [e.value for e in sitemap.evidence] == ["https://shop.test/staging/new-home"]


@pytest.mark.parametrize("name", ["tutorial.html", "comments.html", "listing.html"])
def test_lab_host_and_severity_ceiling(name: str) -> None:
    findings = run_disclosure_checks([load(name), load(name, "/other")])
    assert all(f.severity <= Severity.MEDIUM for f in findings)
    assert all(len(f.urls) <= 2 for f in findings)


def test_visible_text_strips_code_only_when_asked() -> None:
    html = "<p>a</p><pre>b</pre><script>c</script>"
    assert "b" not in visible_text(html, strip_code=True)
    assert "b" in visible_text(html, strip_code=False)
    assert "c" not in visible_text(html, strip_code=False)
