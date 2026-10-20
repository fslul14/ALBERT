"""Third-party intelligence egress (vulnerability DBs, CT logs, Wayback, Safe Browsing, DNS
blocklists). Never contacts the target.

``IntelPolicy`` is this path's checkpoint, enforced in the transport before any socket:
only the listed service endpoints, only the listed methods, HTTPS only, and never a scan
target host. Requests carry package/product names and versions only, never target URLs.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlsplit

import httpx

from albert import __version__
from albert.core.models import DnsAnswer
from albert.core.scope import OutOfScopeError, normalize_host

USER_AGENT = f"Albert/{__version__} (vulnerability lookup; +https://github.com/fslul14/ALBERT)"

# service host -> method -> allowed exact paths
INTEL_ENDPOINTS: dict[str, dict[str, tuple[str, ...]]] = {
    "api.osv.dev": {"POST": ("/v1/query",)},
    "services.nvd.nist.gov": {"GET": ("/rest/json/cves/2.0",)},
    "crt.sh": {"GET": ("/",)},  # Certificate Transparency search
    "web.archive.org": {"GET": ("/cdx/search/cdx",)},  # Wayback Machine CDX index
    "safebrowsing.googleapis.com": {"POST": ("/v4/threatMatches:find",)},
}
# Minimum seconds between requests per service (NVD: 5 requests / 30 s without an API key).
SPACING = {
    "api.osv.dev": 0.2,
    "services.nvd.nist.gov": 6.5,
    "crt.sh": 2.0,
    "web.archive.org": 1.0,
    "safebrowsing.googleapis.com": 0.2,
}
# Third-party DNS blocklist zones (DNSBL): name suffix -> what is looked up under it.
INTEL_DNS_ZONES = {
    "dbl.spamhaus.org": "domain",
    "multi.surbl.org": "domain",
    "zen.spamhaus.org": "ip",
}


class IntelError(Exception):
    """A lookup failed (network, HTTP status, bad JSON). Safe to report."""


class IntelPolicy:
    """Which third-party endpoints may be contacted, and never the target."""

    def __init__(self, target_hosts: Iterable[str] = ()) -> None:
        self.target_hosts = frozenset(normalize_host(h) for h in target_hosts)

    def check(self, method: str, url: str) -> str:
        """Return the service host if allowed; raise OutOfScopeError otherwise."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if (
            parts.scheme != "https"
            or parts.username
            or parts.password
            or parts.port not in (None, 443)
        ):
            raise OutOfScopeError(f"intel request refused: {url!r} (https on 443 only)")
        if host in self.target_hosts:
            raise OutOfScopeError(f"intel request refused: {host!r} is a scan target")
        allowed = INTEL_ENDPOINTS.get(host, {}).get(method.upper())
        if not allowed or parts.path not in allowed:
            raise OutOfScopeError(f"intel request refused: {method} {host}{parts.path} not allowed")
        return host


class IntelDnsPolicy:
    """Checkpoint for DNS blocklist lookups: only names under the listed DNSBL zones, type A."""

    def check(self, name: str, rtype: str) -> str:
        n = name.strip().lower().rstrip(".")
        if rtype.upper() != "A":
            raise OutOfScopeError(f"intel DNS type {rtype} refused")
        zone = next((z for z in INTEL_DNS_ZONES if n.endswith("." + z)), None)
        if zone is None or n == zone:
            raise OutOfScopeError(f"intel DNS name {n!r} is not under a blocklist zone")
        return n


class IntelDns:
    """DNS blocklist queries; the policy is checked before any packet."""

    def __init__(self, resolve: Callable[[str, str], Awaitable[DnsAnswer]] | None = None) -> None:
        self.policy = IntelDnsPolicy()
        self._resolve = resolve

    async def query(self, name: str) -> DnsAnswer:
        n = self.policy.check(name, "A")
        if self._resolve is not None:
            return await self._resolve(n, "A")
        from albert.core.dns_client import system_resolve

        return await system_resolve(n, "A")


class _IntelTransport(httpx.AsyncBaseTransport):
    def __init__(
        self, policy: IntelPolicy, inner: httpx.AsyncBaseTransport, max_requests: int
    ) -> None:
        self._policy = policy
        self._inner = inner
        self._max = max_requests
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self.requests_made = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = self._policy.check(request.method, str(request.url))
        if self.requests_made >= self._max:
            raise IntelError(f"intel request budget of {self._max} spent")
        self.requests_made += 1
        request.headers["User-Agent"] = USER_AGENT
        async with self._lock:  # polite spacing per service
            loop = asyncio.get_running_loop()
            if (wait := self._next.get(host, 0.0) - loop.time()) > 0:
                await asyncio.sleep(wait)
            self._next[host] = loop.time() + SPACING.get(host, 1.0)
        response = await self._inner.handle_async_request(request)
        await response.aread()
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class IntelClient:
    """JSON client for the allow-listed vulnerability databases."""

    def __init__(
        self,
        policy: IntelPolicy,
        *,
        timeout: float = 20.0,
        max_requests: int = 200,
        headers: dict[str, str] | None = None,
        _inner: httpx.AsyncBaseTransport | None = None,  # tests only; still guarded
    ) -> None:
        self._transport = _IntelTransport(
            policy, _inner or httpx.AsyncHTTPTransport(retries=0), max_requests
        )
        self._client = httpx.AsyncClient(
            transport=self._transport,
            timeout=timeout,
            follow_redirects=False,
            headers=headers or {},
            trust_env=False,
        )

    @property
    def requests_made(self) -> int:
        return self._transport.requests_made

    async def _json(self, method: str, url: str, **kw: Any) -> Any:
        try:
            r = await self._client.request(method, url, **kw)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise IntelError(f"{urlsplit(url).hostname}: {type(e).__name__}: {e}") from None

    async def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        return await self._json("GET", url, params=params)

    async def post_json(self, url: str, payload: dict[str, Any]) -> Any:
        return await self._json("POST", url, json=payload)

    async def aclose(self) -> None:
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
