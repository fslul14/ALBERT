"""Sandboxed headless render (Playwright/Chromium) with NO network of its own.

How passivity is enforced:
- Chromium starts with DNS resolution disabled and a dead proxy, so anything that escaped
  interception (preconnect, WebRTC, background services) cannot reach the network.
- Every request is intercepted. ``policy.check_request`` runs first: off-scope hosts and
  non-GET/HEAD methods are aborted and recorded, never fetched. In-scope requests are
  fetched by HttpClient (scope, per-host rate limit, budget, honest UA) and replayed into
  the page. Set-Cookie is stripped, so the page never holds or sends cookies.
- Service workers are blocked; WebSockets are closed and recorded; popups are closed.
- No script is injected: no evaluate/init scripts/locator actions. The DOM is read through
  the DevTools protocol (DOM.getOuterHTML). No form is filled, submitted or clicked.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from playwright.async_api import (
    BrowserContext,
    Page,
    Request,
    Route,
    WebSocketRoute,
    async_playwright,
)
from playwright.async_api import (
    Error as PlaywrightError,
)

from albert.core.http_client import FetchError, HttpClient
from albert.core.models import RenderedPage, SubRequest
from albert.core.scope import OutOfScopeError, ScopePolicy

CHROMIUM_ARGS = (
    "--host-resolver-rules=MAP * ~NOTFOUND",  # the browser itself resolves nothing
    "--proxy-server=http://127.0.0.1:9",  # anything not intercepted goes to a dead port
    "--proxy-bypass-list=<-loopback>",  # ...including loopback
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--dns-prefetch-disable",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-sync",
    "--no-first-run",
    "--no-pings",
)
_DROP_RESPONSE_HEADERS = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "set-cookie",
    "alt-svc",
}


class RenderError(Exception):
    """The browser could not start (e.g. Chromium not installed). Nothing was rendered."""


@dataclass(frozen=True)
class RenderLimits:
    """Caps for rendering."""

    max_pages: int = 10
    nav_timeout_ms: int = 20_000
    settle_ms: int = 2_000  # extra wait for network idle after load
    max_requests_per_page: int = 80


class _PageRecorder:
    """Intercepts one page's requests: scope first, then HttpClient, then replay."""

    def __init__(self, policy: ScopePolicy, client: HttpClient, limits: RenderLimits) -> None:
        self.policy = policy
        self.client = client
        self.limits = limits
        self.requests: list[SubRequest] = []

    def _add(self, req: Request, outcome: str, status: int | None = None, note: str = "") -> None:
        self.requests.append(
            SubRequest(req.url, req.resource_type, req.method, outcome, status, note)
        )

    async def handle(self, route: Route, req: Request) -> None:
        try:
            self.policy.check_request(req.method, req.url)
        except OutOfScopeError as e:
            self._add(req, "blocked", note=str(e))
            await route.abort("blockedbyclient")
            return
        if len(self.requests) >= self.limits.max_requests_per_page:
            self._add(req, "blocked", note="per-page request cap")
            await route.abort("blockedbyclient")
            return
        try:
            raw = await self.client.fetch_one(req.url, req.method)
        except (FetchError, OutOfScopeError) as e:
            self._add(req, "failed", note=str(e))
            await route.abort("failed")
            return
        except Exception as e:  # e.g. budget spent: stop fetching, keep rendering
            self._add(req, "blocked", note=str(e))
            await route.abort("blockedbyclient")
            return
        self._add(req, "fetched", raw.status)
        headers = {k: v for k, v in raw.headers if k.lower() not in _DROP_RESPONSE_HEADERS}
        await route.fulfill(status=raw.status, headers=headers, body=raw.body)

    async def handle_websocket(self, ws: WebSocketRoute) -> None:
        self.requests.append(SubRequest(ws.url, "websocket", "GET", "blocked", note="websocket"))
        await ws.close()


async def _dom_via_cdp(context: BrowserContext, page: Page) -> str:
    """Serialize the live DOM with DevTools (no JavaScript runs in the page)."""
    cdp = await context.new_cdp_session(page)
    try:
        doc = await cdp.send("DOM.getDocument", {"depth": -1})
        html = await cdp.send("DOM.getOuterHTML", {"nodeId": doc["root"]["nodeId"]})
        return str(html["outerHTML"])
    finally:
        await cdp.detach()


async def _render_one(
    context: BrowserContext, policy: ScopePolicy, client: HttpClient, url: str, limits: RenderLimits
) -> RenderedPage:
    policy.check_request("GET", url)  # navigation target is scope-checked first
    recorder = _PageRecorder(policy, client, limits)
    page = await context.new_page()
    await page.route("**/*", recorder.handle)
    await page.route_web_socket("**/*", recorder.handle_websocket)
    error = None
    try:
        await page.goto(url, wait_until="load", timeout=limits.nav_timeout_ms)
        try:
            await page.wait_for_load_state("networkidle", timeout=limits.settle_ms)
        except PlaywrightError:
            pass  # busy pages never go idle; render what we have
        dom = await _dom_via_cdp(context, page)
    except PlaywrightError as e:
        error, dom = f"render failed: {str(e).splitlines()[0]}", ""
    final_url = page.url
    await page.close()
    return RenderedPage(url, final_url, dom, tuple(recorder.requests), error)


async def render_pages(
    policy: ScopePolicy, client: HttpClient, urls: list[str], limits: RenderLimits | None = None
) -> list[RenderedPage]:
    """Render each URL (in scope) and capture DOM, sub-requests and final URL."""
    limits = limits or RenderLimits()
    urls = [u for u in urls if _in_scope(policy, u)][: limits.max_pages]
    if not urls:
        return []
    out: list[RenderedPage] = []
    async with async_playwright() as pw:
        try:
            browser = await pw.chromium.launch(
                headless=True, chromium_sandbox=True, args=list(CHROMIUM_ARGS)
            )
        except PlaywrightError as e:
            raise RenderError(
                str(e).strip().splitlines()[0] if str(e).strip() else "launch failed"
            ) from None
        try:
            context = await browser.new_context(
                service_workers="block",
                accept_downloads=False,
                java_script_enabled=True,
                ignore_https_errors=False,
            )
            context.on("page", _close_popups)
            for url in urls:
                out.append(await _render_one(context, policy, client, url, limits))
            await context.close()
        finally:
            await browser.close()
    return out


def _in_scope(policy: ScopePolicy, url: str) -> bool:
    try:
        policy.check_request("GET", url)
    except OutOfScopeError:
        return False
    return urlsplit(url).scheme in ("http", "https")


async def _close_popups(page: Page) -> None:
    """Close window.open() popups; pages Albert opens itself have no opener."""
    if await page.opener() is not None:
        await page.close()
