"""Crawler tests against mocked sites. No live hosts."""

import json
from pathlib import Path

import httpx
import pytest
import respx

import albert.quick
from albert.cli import main
from albert.core.crawler import (
    Crawler,
    CrawlLimits,
    dedup_key,
    extract_links,
    normalize_url,
    sitemap_locs,
)
from albert.core.http_client import ClientLimits
from albert.core.models import Target, TLSObservation
from albert.core.scope import ScopePolicy
from albert.core.tls_client import TLSLimits

BASE = "https://site.test"
FAST = ClientLimits(rate=0, concurrency=2)


def page(*links: str, status: int = 200) -> httpx.Response:
    body = "<html><body>" + "".join(f'<a href="{u}">x</a>' for u in links) + "</body></html>"
    return httpx.Response(status, headers={"Content-Type": "text/html"}, text=body)


def site(pages: dict[str, httpx.Response], robots: str = "") -> dict[str, respx.Route]:
    """Mock a site: path -> response; robots.txt optional; everything else 404."""
    if robots:
        respx.get(f"{BASE}/robots.txt").mock(
            return_value=httpx.Response(200, headers={"Content-Type": "text/plain"}, text=robots)
        )
    routes = {path: respx.get(BASE + path).mock(return_value=resp) for path, resp in pages.items()}
    respx.route(host="site.test").mock(return_value=httpx.Response(404))
    return routes


def crawler(limits: CrawlLimits | None = None, **kw: object) -> Crawler:
    policy = ScopePolicy.for_target(Target(f"{BASE}/", "scan", authorized_by="self"))
    return Crawler(policy, f"{BASE}/", FAST, limits or CrawlLimits(), **kw)  # type: ignore[arg-type]


# --- pure helpers -------------------------------------------------------------------------


def test_normalize_and_dedup_key() -> None:
    assert normalize_url("HTTPS://Site.Test:443/a?b=2&a=1#frag") == "https://site.test/a?a=1&b=2"
    assert normalize_url("http://site.test:8080") == "http://site.test:8080/"
    assert normalize_url("mailto:x@y") is None
    variants = ["https://site.test/a", "https://site.test/a/", "https://site.test/a#top"]
    assert len({dedup_key(v) for v in variants}) == 1


def test_extract_links_and_sitemap() -> None:
    html = (
        '<base href="/docs/"><a href="p1">x</a><a href="javascript:void(0)">y</a><iframe src="/f">'
    )
    assert extract_links("https://site.test/", html) == [
        "https://site.test/docs/p1",
        "https://site.test/f",
    ]
    xml = "<urlset><url><loc> https://site.test/a?x=1&amp;y=2 </loc></url></urlset>"
    assert sitemap_locs(xml) == ["https://site.test/a?x=1&y=2"]


# --- crawl behavior -----------------------------------------------------------------------


@respx.mock
async def test_dedup_fetches_each_page_once() -> None:
    routes = site(
        {
            "/": page("/a", "/a/", "/a#x", "/q?b=2&a=1", "/q?a=1&b=2", "/"),
            "/a": page("/"),
            "/q": page(),
        }
    )
    result = await crawler().run()
    assert routes["/a"].call_count == 1 and routes["/q"].call_count == 1
    assert routes["/"].call_count == 1
    assert sorted(result.pages) == sorted([f"{BASE}/", f"{BASE}/a", f"{BASE}/q?a=1&b=2"])


@respx.mock
async def test_robots_disallow_respected() -> None:
    routes = site(
        {"/": page("/public", "/private/x"), "/public": page(), "/private/x": page()},
        robots="User-agent: *\nDisallow: /private\n",
    )
    result = await crawler().run()
    assert routes["/public"].called
    assert not routes["/private/x"].called
    assert any("disallowed by robots.txt" in s for s in result.skipped)


@respx.mock
async def test_robots_5xx_means_disallow_all() -> None:
    respx.get(f"{BASE}/robots.txt").mock(return_value=httpx.Response(503))
    routes = site({"/": page()})
    result = await crawler().run()
    assert not routes["/"].called
    assert any("disallow-all" in n for n in result.notes)


@respx.mock
async def test_depth_cap() -> None:
    routes = site({"/": page("/d1"), "/d1": page("/d2"), "/d2": page("/d3"), "/d3": page()})
    await crawler(CrawlLimits(max_depth=2)).run()
    assert routes["/d2"].called and not routes["/d3"].called


@respx.mock
async def test_page_cap() -> None:
    links = [f"/p{i}" for i in range(10)]
    routes = site({"/": page(*links), **{p: page() for p in links}})
    result = await crawler(CrawlLimits(max_pages=3)).run()
    fetched = sum(r.call_count for r in routes.values())
    assert fetched == 3 and len(result.pages) == 3
    assert any("page cap of 3" in n for n in result.notes)


@respx.mock
async def test_session_id_trap() -> None:
    routes = site({"/": page("/cart?PHPSESSID=abc123", "/ok;jsessionid=XYZ"), "/cart": page()})
    result = await crawler().run()
    assert not routes["/cart"].called
    assert sum("session id" in s for s in result.skipped) == 2


@respx.mock
async def test_calendar_trap_stops_descending() -> None:
    # Each month links to the next: an infinite calendar.
    pages = {f"/events?month={m}": page(f"/events?month={m + 1}") for m in range(1, 40)}
    respx.get(f"{BASE}/").mock(return_value=page("/events?month=1"))
    routes = {
        m: respx.get(f"{BASE}/events", params={"month": str(m)}).mock(
            return_value=pages[f"/events?month={m}"]
        )
        for m in range(1, 40)
    }
    respx.route(host="site.test").mock(return_value=httpx.Response(404))
    result = await crawler(CrawlLimits(max_depth=50, calendar_threshold=5)).run()
    fetched = [m for m, r in routes.items() if r.called]
    assert fetched == [1, 2, 3, 4, 5]
    assert any("calendar-style" in s for s in result.skipped)


@respx.mock
async def test_off_host_links_never_followed() -> None:
    other = respx.route(host="other.test").mock(return_value=page())
    sub = respx.route(host="www.site.test").mock(return_value=page())
    site({"/": page("https://other.test/x", "https://www.site.test/", "//other.test/y")})
    result = await crawler().run()
    assert not other.called and not sub.called
    assert sum("off-host" in s for s in result.skipped) == 3


@respx.mock
async def test_sitemap_seeds() -> None:
    respx.get(f"{BASE}/sitemap.xml").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "application/xml"},
            text=f"<urlset><url><loc>{BASE}/hidden</loc></url>"
            "<url><loc>https://other.test/z</loc></url></urlset>",
        )
    )
    routes = site({"/": page(), "/hidden": page()})
    await crawler().run()
    assert routes["/hidden"].called


@respx.mock
async def test_rate_limit_block_recorded_and_stops() -> None:
    links = [f"/p{i}" for i in range(6)]
    limited = httpx.Response(429, headers={"Retry-After": "0"})
    site({"/": page(*links), **{p: limited for p in links}})
    result = await crawler(CrawlLimits(max_blocks=2, backoff=0)).run()
    assert len(result.blocked) == 2
    assert any("blocking/rate-limiting" in n for n in result.notes)


@respx.mock
async def test_resume_skips_completed_pages(tmp_path: Path) -> None:
    state = tmp_path / "state.jsonl"
    respx.get(f"{BASE}/").mock(return_value=page("/a", "/b"))
    a = respx.get(f"{BASE}/a").mock(return_value=page())
    b = respx.get(f"{BASE}/b").mock(side_effect=RuntimeError("power cut"))
    respx.route(host="site.test").mock(return_value=httpx.Response(404))
    with pytest.raises(RuntimeError):
        await crawler(state_path=state).run()
    assert state.exists()
    b.mock(return_value=page())
    root_calls, a_calls = respx.get(f"{BASE}/").calls.call_count, a.call_count
    result = await crawler(state_path=state, resume=True).run()
    assert respx.get(f"{BASE}/").calls.call_count == root_calls  # not re-fetched
    assert a.call_count == a_calls
    assert b.called
    assert result.resumed == 2
    assert sorted(result.pages) == sorted([f"{BASE}/", f"{BASE}/a", f"{BASE}/b"])
    assert not state.exists()  # clean finish removes state


# --- scan wiring --------------------------------------------------------------------------


@respx.mock
def test_scan_crawls_and_groups_findings(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    site({"/": page("/a", "/b"), "/a": page(), "/b": page()})
    out = tmp_path / "reports"
    assert main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0"]) == 0
    data = json.loads(next(out.glob("site.test_*.json")).read_text(encoding="utf-8"))
    csp = next(f for f in data["findings"] if f["id"] == "HDR-CSP-MISSING")
    assert sorted(csp["urls"]) == [f"{BASE}/", f"{BASE}/a", f"{BASE}/b"]  # one grouped finding
    assert data["target"]["mode"] == "scan" and data["target"]["authorized_by"] == "self"


@respx.mock
@pytest.mark.parametrize("flag, enumerate", [([], True), (["--no-tls-enum"], False)])
def test_scan_no_tls_enum_skips_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: list[str], enumerate: bool
) -> None:
    seen: list[TLSLimits | None] = []
    canned = albert.quick.collect_tls  # type: ignore[attr-defined]  # conftest's fake; record the limits it is given

    async def fake(
        policy: ScopePolicy, host: str, port: int = 443, limits: TLSLimits | None = None
    ) -> TLSObservation:
        seen.append(limits)
        return await canned(policy, host, port, limits)

    monkeypatch.setattr("albert.quick.collect_tls", fake)
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    site({"/": page()})
    out = tmp_path / "reports"
    args = ["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0", *flag]
    assert main(args) == 0
    assert [lim.enumerate for lim in seen if lim is not None] == [enumerate]
    data = json.loads(next(out.glob("site.test_*.json")).read_text(encoding="utf-8"))
    assert any("--no-tls-enum" in n for n in data["notes"]) is not enumerate


def test_scan_without_entry_asks_and_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope = tmp_path / "scope.toml"
    answers = iter([""])  # blank: cancel
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(tmp_path)]) == 2
    assert not scope.exists()

    with respx.mock:
        site({"/": page()})
        answers = iter(["friend, written OK 2026-10-19"])
        assert (
            main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(tmp_path), "--rate", "0"])
            == 0
        )
    text = scope.read_text(encoding="utf-8")
    assert 'host = "site.test"' in text and "allow_active = false" in text


@respx.mock
async def test_state_file_holds_no_cookies_or_tokens(tmp_path: Path) -> None:
    """CWE-312: cookies, tokens and bodies must not reach the resume state file."""
    fake_key = "sk" + "_live_" + "7" * 24
    session = "S3ss10nValue" + "x" * 20
    state = tmp_path / "state.jsonl"
    respx.get(f"{BASE}/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("Content-Type", "text/html"),
                ("Set-Cookie", f"session={session}; Path=/; HttpOnly"),
                ("X-Api-Token", fake_key),
            ],
            text=f'<a href="/a">a</a><a href="/reset?token={fake_key}">r</a><p>{session}</p>',
        )
    )
    respx.get(f"{BASE}/a").mock(side_effect=RuntimeError("interrupted"))
    respx.route(host="site.test").mock(return_value=httpx.Response(404))
    with pytest.raises(RuntimeError):
        await crawler(state_path=state).run()
    text = state.read_text(encoding="utf-8")
    assert session not in text and fake_key not in text
    assert "<p>" not in text  # no bodies
    assert '"session=; Path=/; HttpOnly"' in text  # name + attributes kept for cookie checks
    assert f"{BASE}/a" in text  # the unfetched link is what resume needs


@respx.mock
def test_scan_reports_robots_sensitive_paths_without_fetching(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    admin = respx.get(f"{BASE}/admin/").mock(return_value=page())
    site({"/": page()}, robots="User-agent: *\nDisallow: /admin/\n")
    out = tmp_path / "reports"
    assert main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0"]) == 0
    data = json.loads(next(out.glob("site.test_*.json")).read_text(encoding="utf-8"))
    notes = {f["id"]: f for f in data["posture_notes"]}
    assert [e["value"] for e in notes["DISC-ROBOTS-SENSITIVE"]["evidence"]] == ["/admin/"]
    assert not admin.called
    assert "disclosure" in data["checks_run"]


@respx.mock
def test_scan_checks_security_txt_once_even_if_linked(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    sec = respx.get(f"{BASE}/.well-known/security.txt").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="Contact: mailto:s@site.test\nExpires: 2020-01-01T00:00:00Z\n",
        )
    )
    site({"/": page("/.well-known/security.txt", "/a"), "/a": page("/.well-known/security.txt")})
    out = tmp_path / "reports"
    assert main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0"]) == 0
    data = json.loads(next(out.glob("site.test_*.json")).read_text(encoding="utf-8"))
    assert sec.call_count == 1  # fetched once, not again by the crawl
    every = data["findings"] + data["posture_notes"]
    expired = [f for f in every if f["id"] == "SEC-TXT-EXPIRED"]
    assert len(expired) == 1 and expired[0]["urls"] == [f"{BASE}/.well-known/security.txt"]
    sec_url = f"{BASE}/.well-known/security.txt"
    assert not any(sec_url in f["urls"] for f in every if not f["id"].startswith("SEC-TXT-"))
    assert data["checks_run"].count("security_txt") == 1


@respx.mock
def test_scan_respects_robots_for_security_txt(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    sec = respx.get(f"{BASE}/.well-known/security.txt").mock(return_value=httpx.Response(200))
    site({"/": page()}, robots="User-agent: *\nDisallow: /.well-known/\n")
    out = tmp_path / "reports"
    main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0"])
    data = json.loads(next(out.glob("site.test_*.json")).read_text(encoding="utf-8"))
    assert not sec.called
    assert any("security.txt" in s and "robots" in s for s in data["appendix"]["skipped"])
