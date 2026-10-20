"""Browser layer tests. The interception layer is tested with fakes (no Chromium); static
tests forbid script injection / interaction APIs; a real-Chromium test runs only when the
browser is installed, and even then the browser has no network (HttpClient is respx-mocked).
"""

import ast
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from albert.core import browser
from albert.core.browser import RenderLimits, _PageRecorder, render_pages
from albert.core.http_client import RawResponse
from albert.core.scope import ScopePolicy

POLICY = ScopePolicy(frozenset({"site.test"}))
FORBIDDEN_API = {
    "evaluate",
    "evaluate_handle",
    "add_init_script",
    "add_script_tag",
    "add_style_tag",
    "set_content",
    "fill",
    "click",
    "dblclick",
    "type",
    "press",
    "check",
    "uncheck",
    "tap",
    "select_option",
    "set_input_files",
    "dispatch_event",
    "expose_function",
    "expose_binding",
    "continue_",
    "fallback",
    "submit",
}


@dataclass
class FakeRequest:
    url: str
    method: str = "GET"
    resource_type: str = "script"


@dataclass
class FakeRoute:
    calls: list[tuple[str, Any]] = field(default_factory=list)

    async def abort(self, reason: str = "") -> None:
        self.calls.append(("abort", reason))

    async def fulfill(self, **kw: Any) -> None:
        self.calls.append(("fulfill", kw))


class FakeClient:
    def __init__(self) -> None:
        self.fetched: list[str] = []

    async def fetch_one(self, url: str, method: str = "GET") -> RawResponse:
        self.fetched.append(url)
        headers = (
            ("Content-Type", "text/javascript"),
            ("Set-Cookie", "sid=1"),
            ("Content-Encoding", "gzip"),
            ("Content-Security-Policy", "default-src 'self'"),
        )
        return RawResponse(url, 200, headers, b"console.log(1)")


async def _handle(req: FakeRequest) -> tuple[FakeRoute, FakeClient, _PageRecorder]:
    client, route = FakeClient(), FakeRoute()
    rec = _PageRecorder(POLICY, client, RenderLimits())  # type: ignore[arg-type]
    await rec.handle(route, req)  # type: ignore[arg-type]
    return route, client, rec


async def test_off_scope_subrequest_aborted_never_fetched() -> None:
    route, client, rec = await _handle(FakeRequest("https://cdn.other.test/lib.js"))
    assert route.calls == [("abort", "blockedbyclient")]
    assert client.fetched == []
    assert rec.requests[0].outcome == "blocked" and "out of scope" in rec.requests[0].note


async def test_page_initiated_post_refused() -> None:
    route, client, rec = await _handle(FakeRequest("https://site.test/api", "POST", "fetch"))
    assert route.calls[0][0] == "abort" and client.fetched == []
    assert "GET/HEAD only" in rec.requests[0].note


async def test_in_scope_fetched_via_client_and_cookies_stripped() -> None:
    route, client, rec = await _handle(FakeRequest("https://site.test/app.js"))
    assert client.fetched == ["https://site.test/app.js"]
    ((kind, kw),) = route.calls
    assert kind == "fulfill" and kw["status"] == 200
    names = {k.lower() for k in kw["headers"]}
    assert "set-cookie" not in names and "content-encoding" not in names
    assert "content-security-policy" in names  # the page's own CSP is still enforced
    assert rec.requests[0].outcome == "fetched"


def test_no_script_injection_or_interaction_apis() -> None:
    tree = ast.parse(Path(browser.__file__).read_text(encoding="utf-8"))
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not used & FORBIDDEN_API


def test_scope_checked_first_in_handler_and_navigation() -> None:
    tree = ast.parse(Path(browser.__file__).read_text(encoding="utf-8"))
    for name in ("handle", "_render_one"):
        fn = next(
            n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == name
        )
        first = fn.body[0]
        stmts = first.body if isinstance(first, ast.Try) else [first]
        calls = [c for s in stmts[:1] for c in ast.walk(s) if isinstance(c, ast.Call)]
        assert any(getattr(c.func, "attr", "") == "check_request" for c in calls), name


def test_browser_has_no_network_of_its_own() -> None:
    args = " ".join(browser.CHROMIUM_ARGS)
    assert "--host-resolver-rules=MAP * ~NOTFOUND" in args
    assert "--proxy-server=http://127.0.0.1:9" in args and "<-loopback>" in args


def _chromium_installed() -> bool:
    root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if not root:
        base = {"win32": os.environ.get("LOCALAPPDATA", ""), "darwin": "~/Library/Caches"}.get(
            sys.platform, "~/.cache"
        )
        root = str(Path(base).expanduser() / "ms-playwright")
    return any(Path(root).glob("chromium*"))


@pytest.mark.skipif(
    not _chromium_installed(), reason="Chromium not installed (playwright install chromium)"
)
@respx.mock
async def test_real_render_offline() -> None:
    page_html = (
        "<html><head><script src='/app.js'></script>"
        "<script src='https://cdn.other.test/lib.js'></script></head><body>hi</body></html>"
    )
    app_js = (
        "document.addEventListener('DOMContentLoaded',()=>{document.body.dataset.state='rendered';"
        "fetch('/api/x',{method:'POST',body:'a'}).catch(()=>{});});"
    )
    respx.get("https://site.test/").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"}, text=page_html)
    )
    respx.get("https://site.test/app.js").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/javascript"}, text=app_js)
    )
    respx.route().mock(return_value=httpx.Response(404))
    from albert.core.http_client import ClientLimits, HttpClient

    async with HttpClient(POLICY, ClientLimits(rate=0)) as client:
        (rendered,) = await render_pages(
            POLICY, client, ["https://site.test/"], RenderLimits(settle_ms=1000)
        )
    assert rendered.error is None, rendered.error
    assert 'data-state="rendered"' in rendered.dom  # the site's own JS ran
    outcomes = {(r.url, r.method): r.outcome for r in rendered.requests}
    assert outcomes[("https://site.test/app.js", "GET")] == "fetched"
    assert outcomes[("https://cdn.other.test/lib.js", "GET")] == "blocked"
    assert outcomes[("https://site.test/api/x", "POST")] == "blocked"


@pytest.mark.skipif(
    not _chromium_installed(), reason="Chromium not installed (playwright install chromium)"
)
@respx.mock
def test_scan_with_render_end_to_end(tmp_path: Path) -> None:
    import json

    from albert.cli import main

    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    html = "<html><head><script src='https://cdn.other.test/lib.js'></script></head><body>x</body></html>"
    respx.get("https://site.test/").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"}, text=html)
    )
    respx.route().mock(return_value=httpx.Response(404))
    out = tmp_path / "reports"
    args = [
        "scan",
        "https://site.test/",
        "--scope",
        str(scope),
        "--out",
        str(out),
        "--rate",
        "0",
        "--render",
    ]
    assert main(args) == 0
    data = json.loads(next(out.glob("site.test_*.json")).read_text(encoding="utf-8"))
    assert "rendered" in data["checks_run"]
    assert "RND-SCRIPT-NO-SRI" in {f["id"] for f in data["findings"]}
    assert any(s.startswith("https://cdn.other.test") for s in data["appendix"]["skipped"])
