"""All HTTP egress. Enforcement lives in the transport, so every hop (redirects included) passes
the scope checkpoint, method gate, request budget, and per-host limits before any socket opens.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from dataclasses import dataclass
from types import TracebackType
from typing import Self

import httpx

from albert import __version__
from albert.core.models import CollectedResponse
from albert.core.scope import OutOfScopeError, ScopePolicy

USER_AGENT = f"Albert/{__version__} (passive security scanner; +https://github.com/fslul14/ALBERT)"


class BudgetExceededError(Exception):
    """The run's total request budget is spent. Nothing was sent."""


class FetchError(Exception):
    """A request failed (network, TLS, timeout, protocol). The message is safe to report."""


MAX_TEXT_CHARS = 2_000_000
_TEXTUAL = re.compile(r"^(?:text/|application/(?:[\w.+-]*\+)?(?:json|xml|javascript)\b)")


@dataclass(frozen=True)
class FetchChain:
    """Every hop of one GET. ``not_followed`` is a redirect target the policy refused."""

    hops: list[CollectedResponse]
    not_followed: str | None = None
    note: str | None = None  # why the chain stopped early, if it did


def _collect(r: httpx.Response) -> CollectedResponse:
    ctype = r.headers.get("content-type", "").lower()
    text = r.text[:MAX_TEXT_CHARS] if _TEXTUAL.match(ctype) else ""
    return CollectedResponse(
        str(r.url), r.status_code, tuple(r.headers.multi_items()), r.http_version, text
    )


@dataclass(frozen=True)
class ClientLimits:
    """Politeness settings. ``rate``/``concurrency`` are per host."""

    rate: float = 2.0  # requests per second per host; 0 = unlimited
    concurrency: int = 2  # in-flight requests per host
    max_requests: int = 500  # total for the run, every redirect hop counts
    timeout: float = 15.0  # seconds, per phase (connect/read/write/pool)
    max_redirects: int = 5


class _HostGate:
    """Concurrency cap + start-spacing for one host."""

    def __init__(self, concurrency: int, rate: float) -> None:
        self._sem = asyncio.Semaphore(concurrency)
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_start = 0.0

    async def __aenter__(self) -> None:
        await self._sem.acquire()
        try:
            async with self._lock:
                now = asyncio.get_running_loop().time()
                if self._next_start > now:
                    await asyncio.sleep(self._next_start - now)
                    now = self._next_start
                self._next_start = now + self._interval
        except BaseException:
            self._sem.release()
            raise

    async def __aexit__(self, *exc: object) -> None:
        self._sem.release()


class _GuardedTransport(httpx.AsyncBaseTransport):
    """Wraps the real transport; nothing reaches it without passing every gate."""

    def __init__(
        self, policy: ScopePolicy, limits: ClientLimits, inner: httpx.AsyncBaseTransport
    ) -> None:
        self._policy = policy
        self._limits = limits
        self._inner = inner
        self._gates: defaultdict[str, _HostGate] = defaultdict(
            lambda: _HostGate(limits.concurrency, limits.rate)
        )
        self.requests_made = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = self._policy.check_request(request.method, str(request.url))
        if self.requests_made >= self._limits.max_requests:
            raise BudgetExceededError(f"request budget of {self._limits.max_requests} spent")
        self.requests_made += 1
        request.headers["User-Agent"] = USER_AGENT
        async with self._gates[host]:
            # Read the body inside the gate so the concurrency cap covers the whole transfer;
            # httpx then reuses the cached content.
            response = await self._inner.handle_async_request(request)
            try:
                await response.aread()
            finally:
                await response.aclose()
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class HttpClient:
    """The only way Albert speaks HTTP. GET/HEAD only; no caller-supplied headers."""

    def __init__(
        self,
        policy: ScopePolicy,
        limits: ClientLimits | None = None,
        *,
        _inner: httpx.AsyncBaseTransport | None = None,  # tests only; still wrapped
    ) -> None:
        self.limits = limits or ClientLimits()
        self._policy = policy
        self._transport = _GuardedTransport(
            policy, self.limits, _inner or httpx.AsyncHTTPTransport(retries=0)
        )
        self._client = httpx.AsyncClient(
            transport=self._transport,
            timeout=self.limits.timeout,
            follow_redirects=True,
            max_redirects=self.limits.max_redirects,
            headers={"User-Agent": USER_AGENT},
            trust_env=False,  # no env proxies or .netrc credentials
        )

    @property
    def requests_made(self) -> int:
        """Requests sent so far (each redirect hop counts)."""
        return self._transport.requests_made

    async def get(self, url: str) -> httpx.Response:
        """GET ``url`` (redirects followed, each hop scope-checked)."""
        return await self._client.get(url)

    async def head(self, url: str) -> httpx.Response:
        """HEAD ``url``."""
        return await self._client.head(url)

    async def fetch_chain(self, url: str) -> FetchChain:
        """GET ``url``, following redirects here so every hop is kept for checks.

        An off-scope redirect is recorded (``not_followed``), never followed. Raises FetchError
        only if the first request fails; later failures end the chain with a ``note``.
        """
        hops: list[CollectedResponse] = []
        current = url
        for _ in range(self.limits.max_redirects + 1):
            try:
                r = await self._client.get(current, follow_redirects=False)
            except httpx.HTTPError as e:
                msg = f"{current}: {type(e).__name__}: {e}"
                if not hops:
                    raise FetchError(msg) from None
                return FetchChain(hops, note=f"error following redirect: {msg}")
            hops.append(_collect(r))
            if not r.is_redirect or r.next_request is None:
                return FetchChain(hops)
            nxt = str(r.next_request.url)
            try:
                self._policy.check_request("GET", nxt)
            except OutOfScopeError as e:
                return FetchChain(hops, nxt, f"redirect to {nxt} not followed ({e})")
            current = nxt
        return FetchChain(hops, note=f"stopped after {self.limits.max_redirects} redirects")

    async def aclose(self) -> None:
        """Close connections."""
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
