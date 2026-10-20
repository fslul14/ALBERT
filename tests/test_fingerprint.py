"""Fingerprinting on saved fixtures with known technology. No live hosts."""

import json
from pathlib import Path

import httpx
import respx

from albert.checks.fingerprint import (
    FingerprintInput,
    detect_technologies,
    favicon_md5,
    lint_signatures,
)
from albert.cli import main
from albert.core.crawler import Crawler, CrawlLimits
from albert.core.http_client import ClientLimits
from albert.core.models import CollectedResponse, Confidence, RenderedPage, Target, TechDetection
from albert.core.scope import ScopePolicy

FIXTURES = Path(__file__).parent / "fixtures" / "fingerprint"
BASE = "https://shop.test"
C = Confidence


def headers_fixture(name: str) -> tuple[tuple[str, str], ...]:
    lines = [
        ln
        for ln in (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    return tuple((k.strip(), v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:]))


def wordpress_input() -> FingerprintInput:
    page = CollectedResponse(
        f"{BASE}/",
        200,
        headers_fixture("wordpress_headers.txt"),
        text=(FIXTURES / "wordpress.html").read_text(encoding="utf-8"),
    )
    script = CollectedResponse(
        f"{BASE}/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
        200,
        (("Content-Type", "application/javascript"),),
        text=(FIXTURES / "jquery_banner.js").read_text(encoding="utf-8"),
    )
    return FingerprintInput(responses=[page, script], scripts=[script])


def find(found: list[TechDetection], name: str, version: str | None = "any") -> TechDetection:
    matches = [d for d in found if d.name == name and (version == "any" or d.version == version)]
    assert len(matches) == 1, (name, version, matches)
    return matches[0]


def test_wordpress_stack() -> None:
    found = detect_technologies(wordpress_input())
    nginx = find(found, "nginx")
    assert (nginx.version, nginx.confidence, nginx.cpe) == ("1.25.3", C.HIGH, "f5:nginx")
    php = find(found, "PHP")
    assert (php.version, php.confidence) == ("8.2.12", C.HIGH)
    assert "cookie PHPSESSID" in php.evidence  # presence signal folded into the versioned one
    wp = find(found, "WordPress")
    assert (wp.version, wp.confidence) == ("6.4.2", C.HIGH)  # exact <meta generator>
    assert any(e.startswith("markup:") for e in wp.evidence)
    mysql = find(found, "MySQL")
    assert (mysql.version, mysql.confidence, mysql.evidence) == (
        None,
        C.LOW,
        ("implied by WordPress",),
    )
    assert find(found, "Google Analytics").confidence is C.MEDIUM


def test_jquery_versions_and_confidence() -> None:
    found = detect_technologies(wordpress_input())
    banner = find(found, "jQuery", "3.7.1")
    assert banner.confidence is C.HIGH  # exact version string in the file's banner
    assert banner.npm == "jquery"
    cdn = find(found, "jQuery", "3.5.1")
    assert cdn.confidence is C.LOW  # inferred from the URL path only
    assert all("3.7.1" != d.version for d in found if d.name == "WordPress")  # bundled lib ver


def test_rendered_angular_and_django_markup() -> None:
    dom = (FIXTURES / "angular_dom.html").read_text(encoding="utf-8")
    django = CollectedResponse(
        f"{BASE}/login",
        200,
        (("Content-Type", "text/html"),),
        text=(FIXTURES / "django.html").read_text(encoding="utf-8"),
    )
    found = detect_technologies(
        FingerprintInput(
            responses=[django], rendered=[RenderedPage(f"{BASE}/app", f"{BASE}/app", dom)]
        )
    )
    angular = find(found, "Angular")
    assert (angular.version, angular.confidence) == ("17.0.8", C.HIGH)
    assert find(found, "Django").confidence is C.MEDIUM
    assert find(found, "Python").confidence is C.LOW  # implied


def test_favicon_hash_match(tmp_path: Path) -> None:
    icon = (FIXTURES / "favicon.ico").read_bytes()
    sig = tmp_path / "sigs.yaml"
    sig.write_text(
        "technologies:\n- name: TestApp\n  category: app\n"
        f"  favicon_md5: ['{favicon_md5(icon)}']\n",
        encoding="utf-8",
    )
    techs, problems = lint_signatures(sig)
    assert problems == []
    found = detect_technologies(FingerprintInput(favicons=[(f"{BASE}/favicon.ico", icon)]), techs)
    assert [(d.name, d.confidence) for d in found] == [("TestApp", C.MEDIUM)]


def test_nothing_detected_on_plain_page() -> None:
    plain = CollectedResponse(f"{BASE}/", 200, (("Content-Type", "text/html"),), text="<p>hi</p>")
    assert detect_technologies(FingerprintInput(responses=[plain])) == []


def test_signature_lint(tmp_path: Path) -> None:
    techs, problems = lint_signatures()
    assert problems == [] and len(techs) > 40
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "technologies:\n"
        "- {name: A, category: x, headers: {Server: '('}}\n"
        "- {name: B, category: x, implies: [Nope]}\n"
        "- {name: C, category: x, favicon_md5: [xyz]}\n"
        "- {name: B, category: x}\n",
        encoding="utf-8",
    )
    _, problems = lint_signatures(bad)
    text = "\n".join(problems)
    assert "bad regex" in text and "implies unknown 'Nope'" in text
    assert "favicon_md5" in text and "duplicate technology 'B'" in text


@respx.mock
async def test_crawler_hashes_only_referenced_same_host_icons() -> None:
    respx.get(f"{BASE}/").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text=(FIXTURES / "wordpress.html").read_text(encoding="utf-8"),
        )
    )
    icon = respx.get(f"{BASE}/wp-content/uploads/favicon.ico").mock(
        return_value=httpx.Response(200, content=(FIXTURES / "favicon.ico").read_bytes())
    )
    guessed = respx.get(f"{BASE}/favicon.ico").mock(return_value=httpx.Response(200))
    other = respx.route(host="cdn.other.test").mock(return_value=httpx.Response(200))
    respx.route(host="shop.test").mock(return_value=httpx.Response(404))
    policy = ScopePolicy.for_target(Target(f"{BASE}/", "scan", authorized_by="self"))
    crawl = await Crawler(policy, f"{BASE}/", ClientLimits(rate=0), CrawlLimits()).run()
    assert [u for u, _ in crawl.favicons] == [f"{BASE}/wp-content/uploads/favicon.ico"]
    assert icon.call_count == 1 and not guessed.called and not other.called


@respx.mock
def test_scan_puts_tech_in_appendix_not_findings(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "shop.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    respx.get(f"{BASE}/").mock(
        return_value=httpx.Response(
            200,
            headers=dict(headers_fixture("wordpress_headers.txt")),
            text=(FIXTURES / "wordpress.html").read_text(encoding="utf-8"),
        )
    )
    respx.route().mock(return_value=httpx.Response(404))
    out = tmp_path / "reports"
    assert main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0"]) == 0
    data = json.loads(next(out.glob("shop.test_*.json")).read_text(encoding="utf-8"))
    md = next(out.glob("shop.test_*.md")).read_text(encoding="utf-8")
    names = {t["name"] for t in data["appendix"]["tech"]}
    assert {"nginx", "PHP", "WordPress", "jQuery"} <= names
    assert not any(
        f["id"].startswith(("FP-", "TECH-")) for f in data["findings"] + data["posture_notes"]
    )
    assert "| nginx | `1.25.3` | web-server | high |" in md
    assert "fingerprint" in data["checks_run"]
