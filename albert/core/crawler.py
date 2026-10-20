"""Async same-host crawler: robots.txt, sitemap seeds, URL dedup, depth/page caps, crawl-trap
detection, block back-off, and resume. Every request goes through HttpClient (scope first).
"""

from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from selectolax.lexbor import LexborHTMLParser

from albert.core.http_client import (
    BudgetExceededError,
    ClientLimits,
    FetchError,
    HttpClient,
)
from albert.core.models import CollectedResponse
from albert.core.scope import OutOfScopeError, ScopePolicy
from albert.core.secrets import redact

ROBOTS_AGENT = "Albert"
STATE_VERSION = 2
MAX_SITEMAPS = 5
MAX_RECORDED_SKIPS = 1000

_DEFAULT_PORTS = {"http": 80, "https": 443}
_LINK_SELECTOR = "a[href], area[href], iframe[src], frame[src]"
_SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "blob:", "about:")
_ASSET_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|webp|svg|ico|bmp|avif|css|js|mjs|map|woff2?|ttf|otf|eot|pdf|zip|gz|"
    r"tgz|rar|7z|tar|mp[34]|webm|ogg|wav|avi|mov|mkv|exe|msi|dmg|iso|apk|docx?|xlsx?|pptx?)$",
    re.I,
)
_SESSION_PARAM = re.compile(
    r"^(?:jsessionid|phpsessid|sid|sessionid|session_id|aspsessionid\w*|cfid|cftoken|zenid|oscsid)$",
    re.I,
)
_CALENDAR_PARAMS = {
    "date",
    "day",
    "month",
    "year",
    "week",
    "cal",
    "calendar",
    "ym",
    "start",
    "end",
    "from",
    "to",
}
_DATE_PATH = re.compile(r"/\d{4}/\d{1,2}(?:/\d{1,2})?(?:/|$)")
_LOC = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)


# --- Pure helpers -------------------------------------------------------------------------


def normalize_url(url: str) -> str | None:
    """Canonical fetch form: lowercase scheme/host, no default port, no fragment or userinfo,
    sorted query params. None for non-http(s) or unparsable URLs."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, parts.path or "/", query, ""))


def dedup_key(url: str) -> str | None:
    """Normalized URL with a trailing slash ignored (``/docs`` == ``/docs/``)."""
    norm = normalize_url(url)
    if norm is None:
        return None
    parts = urlsplit(norm)
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def extract_links(base_url: str, html: str) -> list[str]:
    """Absolute http(s) links from navigational elements, honoring <base href>."""
    tree = LexborHTMLParser(html)
    base_node = tree.css_first("base[href]")
    base = urljoin(base_url, base_node.attributes.get("href") or "") if base_node else base_url
    links = []
    for node in tree.css(_LINK_SELECTOR):
        raw = node.attributes.get("href") or node.attributes.get("src") or ""
        raw = raw.strip()
        if raw and not raw.lower().startswith(_SKIP_SCHEMES):
            links.append(urljoin(base, raw))
    return links


def sitemap_locs(xml: str) -> list[str]:
    """<loc> values from a sitemap or sitemap index (regex, not an XML parser: no entity risk)."""
    return [unescape(m) for m in _LOC.findall(xml)]


def url_shape(url: str) -> str:
    """Path with digit runs collapsed + sorted param names: one 'template' of URLs."""
    parts = urlsplit(url)
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    return re.sub(r"\d+", "N", parts.path) + ("?" + "&".join(names) if names else "")


_STATE_DROP_HEADERS = {"authorization", "proxy-authorization", "cookie"}


def sanitize_headers(headers: Iterable[tuple[str, str]]) -> list[list[str]]:
    """Headers safe to write to the resume state (CWE-312): request-credential headers dropped,
    Set-Cookie values blanked (name + attributes kept for cookie checks), the rest redacted."""
    out = []
    for name, value in headers:
        key = name.lower()
        if key in _STATE_DROP_HEADERS:
            continue
        if key == "set-cookie":
            pair, sep, attrs = value.partition(";")
            value = pair.split("=", 1)[0].strip() + "=" + sep + redact(attrs)
        else:
            value = redact(value)
        out.append([name, value])
    return out


@dataclass
class _ResumeState:
    pages: list[tuple[CollectedResponse, int, bool]] = field(default_factory=list)
    links: list[tuple[str, int]] = field(default_factory=list)


# --- Crawler ------------------------------------------------------------------------------


@dataclass(frozen=True)
class CrawlLimits:
    """Crawl caps and politeness knobs."""

    max_pages: int = 100  # fetches started (each may include redirect hops)
    max_depth: int = 3  # link hops from the start URL
    trap_threshold: int = 20  # URLs per shape before it's treated as a trap/template
    calendar_threshold: int = 5  # same, for date/calendar-looking shapes
    max_blocks: int = 3  # 429/503/WAF responses before the crawl stops
    backoff: float = 5.0  # seconds to pause after a block (Retry-After honored, capped)
    max_backoff: float = 30.0


@dataclass
class CrawlResult:
    """What a crawl produced, in fetch order."""

    responses: list[CollectedResponse] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    resumed: int = 0  # responses loaded from state instead of re-fetched
    aux: list[CollectedResponse] = field(default_factory=list)  # robots.txt, sitemaps


class Crawler:
    """One same-host crawl. Construct, then ``await run()``."""

    def __init__(
        self,
        policy: ScopePolicy,
        start_url: str,
        client_limits: ClientLimits | None = None,
        crawl_limits: CrawlLimits | None = None,
        *,
        state_path: Path | None = None,
        resume: bool = False,
    ) -> None:
        start = normalize_url(start_url)
        if start is None:
            raise ValueError(f"not an http(s) URL: {start_url!r}")
        self.start_url = start
        self.host = urlsplit(start).hostname or ""
        self.policy = policy
        self.client_limits = client_limits or ClientLimits()
        self.limits = crawl_limits or CrawlLimits()
        self.state_path = state_path
        self.resume = resume
        self.result = CrawlResult()
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._seen: set[str] = set()
        self._shapes: Counter[str] = Counter()
        self._trap_shapes: set[str] = set()
        self._skip_seen: set[str] = set()
        self._robots = RobotFileParser()
        self._robots_mode = "allow"  # "allow" (none/4xx), "deny" (unreachable), "rules"
        self._started = 0
        self._blocks = 0
        self._stop_reason: str | None = None  # blocks/budget: state kept for --resume
        self._capped = False
        self._fatal: BaseException | None = None
        self._resume_until = 0.0
        self._client: HttpClient | None = None
        self._loading = False  # replaying resume state: don't re-append it
        self._unsaved_links = 0

    # -- bookkeeping --

    def _skip(self, url: str, reason: str) -> None:
        entry = f"{url} ({reason})"
        if entry in self._skip_seen:
            return
        self._skip_seen.add(entry)
        if len(self.result.skipped) < MAX_RECORDED_SKIPS:
            self.result.skipped.append(entry)

    def _stop(self, reason: str) -> None:
        if self._stop_reason is None:
            self._stop_reason = reason
            self.result.notes.append(f"crawl stopped: {reason}")

    def _trap_reason(self, url: str) -> str | None:
        parts = urlsplit(url)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if any(_SESSION_PARAM.match(k) for k, _ in params) or ";jsessionid=" in parts.path.lower():
            return "crawl trap: session id in URL"
        segments = [s for s in parts.path.split("/") if s]
        if segments and max(Counter(segments).values()) > 3:
            return "crawl trap: repeating path segments"
        if len(url) > 2000:
            return "crawl trap: URL too long"
        shape = url_shape(url)
        self._shapes[shape] += 1
        calendar = bool(_DATE_PATH.search(parts.path)) or any(
            k.lower() in _CALENDAR_PARAMS for k, _ in params
        )
        limit = self.limits.calendar_threshold if calendar else self.limits.trap_threshold
        if self._shapes[shape] > limit:
            kind = "calendar-style" if calendar else "repetitive"
            return f"crawl trap: {kind} URL pattern {shape} (first {limit} kept)"
        return None

    def enqueue(self, url: str, depth: int) -> None:
        """Queue ``url`` if same-host, unseen, within depth, robots-allowed, and not a trap."""
        norm = normalize_url(url)
        key = dedup_key(url)
        if norm is None or key is None or depth > self.limits.max_depth:
            return
        if urlsplit(norm).hostname != self.host:
            self._skip(norm, "off-host")
            return
        if key in self._seen:
            return
        self._seen.add(key)
        if _ASSET_EXT.search(urlsplit(norm).path):
            return  # static asset, not a page
        if reason := self._trap_reason(norm):
            shape = url_shape(norm)
            if shape not in self._trap_shapes:
                self._trap_shapes.add(shape)
                self._skip(norm, reason)
            return
        if not self._robots_allows(norm):
            self._skip(norm, "disallowed by robots.txt")
            return
        self._queue.put_nowait((norm, depth))
        self._record_link(norm, depth)

    def _robots_allows(self, url: str) -> bool:
        if self._robots_mode == "rules":
            return self._robots.can_fetch(ROBOTS_AGENT, url)
        return self._robots_mode == "allow"

    # -- resume state --

    def _write_state(self, record: dict[str, Any]) -> None:
        if self.state_path is None or self._loading:
            return
        with self.state_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(record) + "\n")

    def _load_state(self) -> _ResumeState | None:
        """Completed pages + unfetched links from an interrupted run of the same start URL."""
        if self.state_path is None or not self.resume or not self.state_path.exists():
            return None
        state = _ResumeState()
        with self.state_path.open(encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    break  # torn final line from the interruption
                if i == 0:
                    if rec.get("start_url") != self.start_url or rec.get("v") != STATE_VERSION:
                        self.result.notes.append(
                            "resume state ignored (different start URL/format)"
                        )
                        return None
                elif rec.get("type") == "page":
                    resp = CollectedResponse(
                        rec["url"],
                        int(rec["status"]),
                        tuple((str(k), str(v)) for k, v in rec["headers"]),
                        rec.get("http_version", "HTTP/1.1"),
                    )
                    state.pages.append((resp, int(rec["depth"]), bool(rec["first_hop"])))
                elif rec.get("type") == "link":
                    state.links.append((rec["url"], int(rec["depth"])))
        return state

    def _record(self, resp: CollectedResponse, depth: int, first_hop: bool, *, save: bool) -> None:
        self.result.responses.append(resp)
        self.result.pages.append(resp.url)
        if key := dedup_key(resp.url):
            self._seen.add(key)
        if save:
            self._write_state(
                {
                    "type": "page",
                    "url": redact(resp.url),
                    "status": resp.status,
                    "http_version": resp.http_version,
                    "headers": sanitize_headers(resp.headers),
                    "depth": depth,
                    "first_hop": first_hop,
                }
            )

    def _record_link(self, url: str, depth: int) -> None:
        if redact(url) != url:  # never persist a URL carrying a secret-looking token
            self._unsaved_links += 1
            return
        self._write_state({"type": "link", "url": url, "depth": depth})

    def _follow_links(self, resp: CollectedResponse, depth: int) -> None:
        if resp.status == 200 and resp.content_type in {"text/html", "application/xhtml+xml"}:
            for link in extract_links(resp.url, resp.text):
                self.enqueue(link, depth + 1)

    # -- network --

    async def _fetch(self, url: str) -> list[CollectedResponse]:
        if self._client is None:
            raise RuntimeError("crawler client not open")
        try:
            chain = await self._client.fetch_chain(url)
        except FetchError as e:
            self.result.errors.append(str(e))
            return []
        except OutOfScopeError as e:
            self._skip(url, str(e))
            return []
        if chain.note:
            self._skip(chain.not_followed or url, chain.note)
        return chain.hops

    async def _load_robots(self) -> None:
        robots_url = (
            f"{urlsplit(self.start_url).scheme}://{urlsplit(self.start_url).netloc}/robots.txt"
        )
        hops = await self._fetch(robots_url)
        final = hops[-1] if hops else None
        if final is not None:
            self.result.aux.append(final)
        if final is None or final.status >= 500:
            # RFC 9309: unreachable robots.txt means assume full disallow.
            self._robots_mode = "deny"
            self.result.notes.append("robots.txt unreachable: treated as disallow-all (RFC 9309)")
            return
        if final.status == 200 and final.content_type not in {"text/html", "application/xhtml+xml"}:
            self._robots_mode = "rules"
            self._robots.parse(final.text.splitlines())
            delay = self._robots.crawl_delay(ROBOTS_AGENT)
            if delay and float(delay) > 0 and 1 / float(delay) < self.client_limits.rate:
                self.client_limits = replace(self.client_limits, rate=1 / float(delay))
                self.result.notes.append(f"robots.txt Crawl-delay {delay}s honored")

    async def _load_sitemaps(self) -> None:
        base = f"{urlsplit(self.start_url).scheme}://{urlsplit(self.start_url).netloc}"
        listed = self._robots.site_maps() if self._robots_mode == "rules" else None
        pending = list(listed or []) or [f"{base}/sitemap.xml"]
        fetched = 0
        while pending and fetched < MAX_SITEMAPS:
            url = pending.pop(0)
            if urlsplit(url).hostname != self.host:
                self._skip(url, "off-host sitemap")
                continue
            fetched += 1
            hops = await self._fetch(url)
            if not hops or hops[-1].status != 200:
                continue
            self.result.aux.append(hops[-1])
            for loc in sitemap_locs(hops[-1].text):
                if loc.lower().split("?")[0].endswith((".xml", ".xml.gz")):
                    pending.append(loc)  # nested sitemap index entry
                else:
                    self.enqueue(loc, 1)

    def _block_status(self, resp: CollectedResponse) -> str | None:
        if resp.status in (429, 503):
            return f"HTTP {resp.status}"
        if resp.status == 403 and (
            resp.header("cf-mitigated") or re.search(r"captcha|challenge", resp.text[:5000], re.I)
        ):
            return "WAF/CAPTCHA challenge"
        return None

    async def _crawl_one(self, url: str, depth: int) -> None:
        loop = asyncio.get_running_loop()
        if (wait := self._resume_until - loop.time()) > 0:
            await asyncio.sleep(wait)
        hops = await self._fetch(url)
        for i, hop in enumerate(hops):
            self._record(hop, depth, i == 0, save=True)
        if not hops:
            return
        final = hops[-1]
        if block := self._block_status(final):
            self._blocks += 1
            self.result.blocked.append(f"{final.url} ({block})")
            retry = final.header("retry-after") or ""
            pause = float(retry) if retry.strip().isdigit() else self.limits.backoff
            self._resume_until = loop.time() + min(pause, self.limits.max_backoff)
            if self._blocks >= self.limits.max_blocks:
                self._stop(f"target is blocking/rate-limiting ({self._blocks} block responses)")
            return
        self._follow_links(final, depth)

    async def _worker(self) -> None:
        while True:
            url, depth = await self._queue.get()
            try:
                if self._stop_reason or self._fatal:
                    continue
                if self._started >= self.limits.max_pages:
                    if not self._capped:
                        self._capped = True
                        self.result.notes.append(f"page cap of {self.limits.max_pages} reached")
                    continue
                self._started += 1
                await self._crawl_one(url, depth)
            except BudgetExceededError as e:
                self._stop(str(e))
            except Exception as e:  # surface after the queue drains; never hang join()
                self._fatal = e
            finally:
                self._queue.task_done()

    async def run(self) -> CrawlResult:
        """Crawl until the frontier is empty, a cap is hit, or the target blocks us."""
        loaded = self._load_state()
        if self.state_path is not None:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            if loaded is None:
                self.state_path.write_text("", encoding="utf-8")
                self._write_state({"start_url": self.start_url, "v": STATE_VERSION})

        async with HttpClient(self.policy, self.client_limits) as robots_client:
            self._client = robots_client
            await self._load_robots()
        async with HttpClient(self.policy, self.client_limits) as client:
            self._client = client
            if loaded is not None:
                self._loading = True
                for resp, depth, first_hop in loaded.pages:
                    self._record(resp, depth, first_hop, save=False)
                    self._started += first_hop
                for url, depth in loaded.links:
                    self.enqueue(url, depth)  # completed ones are already in _seen
                self._loading = False
                self.result.resumed = len(loaded.pages)
                self.result.notes.append(
                    f"resumed: {len(loaded.pages)} responses loaded (headers only), not re-fetched"
                )
            self.enqueue(self.start_url, 0)
            await self._load_sitemaps()
            workers = [
                asyncio.create_task(self._worker()) for _ in range(self.client_limits.concurrency)
            ]
            try:
                await self._queue.join()
            finally:
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
        if self._unsaved_links:
            self.result.notes.append(
                f"{self._unsaved_links} link(s) with secret-like tokens not saved for resume"
            )
        if self._fatal is not None:
            raise self._fatal  # state file kept: the run can be resumed
        if self.state_path is not None and self._stop_reason is None:
            self.state_path.unlink(missing_ok=True)  # finished cleanly: nothing to resume
        return self.result


def state_path_for(out_dir: Path, host: str) -> Path:
    """Where a host's resume state lives (inside the gitignored reports dir)."""
    return out_dir / ".state" / f"{re.sub(r'[^a-z0-9.-]', '_', host.lower())}.jsonl"
