"""The single "may I contact this?" checkpoint. Every egress path calls it before any socket."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from functools import lru_cache
from urllib.parse import urlsplit

from publicsuffixlist import PublicSuffixList

from albert.core.models import ScanMode, Target

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = frozenset({80, 443})

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class OutOfScopeError(Exception):
    """A request was refused by the scope checkpoint. Nothing was sent."""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def normalize_host(raw: str) -> str:
    """Lowercase, strip a trailing dot, punycode-encode; raise ValueError if not a bare host."""
    host = raw.strip().lower().rstrip(".")
    if _is_ip(host):
        return host
    if not host or any(c in host for c in "/@:?#*[] \t"):
        raise ValueError("must be a bare hostname or IP (no scheme, port, path, or wildcard)")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"invalid hostname ({e})") from None
    if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
        raise ValueError("invalid hostname")
    return host


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    return PublicSuffixList()  # bundled list; never fetched at runtime


def registrable_domain(host: str) -> str | None:
    """eTLD+1 per the Public Suffix List, private section included (alice.github.io and
    bob.github.io differ). None for IPs, single-label hosts, and bare public suffixes."""
    try:
        h = normalize_host(host)
    except ValueError:
        return None
    if _is_ip(h) or "." not in h:
        return None
    site: str | None = _psl().privatesuffix(h)
    return site


@dataclass(frozen=True)
class ScopePolicy:
    """Hosts (and non-default ports) Albert may contact during one run."""

    hosts: frozenset[str]
    extra_ports: frozenset[tuple[str, int]] = frozenset()
    mode: ScanMode = "scan"  # strictest by default; only "quick" may widen (same-site redirects)
    paths: frozenset[str] = frozenset()  # non-empty: ONLY these exact paths, https only

    @classmethod
    def for_target(cls, target: Target) -> ScopePolicy:
        """Policy covering exactly the target's host (+ its explicit port, if non-default)."""
        if target.mode != "quick" and not target.authorized_by:
            raise OutOfScopeError(f"{target.mode} requires a scope.toml entry for {target.host}")
        if target.mode == "active" and not target.allow_active:
            raise OutOfScopeError(f"active mode not allowed for {target.host} (allow_active=false)")
        host = normalize_host(target.host)
        port = urlsplit(target.url).port
        extra = {(host, port)} if port is not None and port not in DEFAULT_PORTS else set()
        return cls(frozenset({host}), frozenset(extra), target.mode)

    @classmethod
    def for_mta_sts(cls, domain: str) -> ScopePolicy:
        """Exactly one file: https://mta-sts.<domain>/.well-known/mta-sts.txt (RFC 8461), the
        domain's own published policy. Nothing else on that host is reachable."""
        host = normalize_host(f"mta-sts.{domain}")
        return cls(frozenset({host}), paths=frozenset({"/.well-known/mta-sts.txt"}))

    def with_same_site_redirect(self, from_url: str, to_url: str) -> ScopePolicy:
        """Quick mode only: a new policy that also allows ``to_url``'s host.

        Narrow by design. Refused unless: this is a quick-mode policy; ``from_url`` is already
        in scope; ``to_url`` is http(s) on a default port without credentials; and both hosts
        share a registrable domain (apex <-> www, sub.example.co.uk -> example.co.uk). Scan and
        active policies never widen; they need an explicit scope.toml entry per host.
        """
        if self.mode != "quick":
            raise OutOfScopeError(f"same-site redirect allowance is quick-mode only ({self.mode})")
        src = urlsplit(from_url)
        src_host = self.check_host(src.hostname or "", src.port)
        dst = urlsplit(to_url)
        if dst.scheme not in ALLOWED_SCHEMES or dst.username or dst.password:
            raise OutOfScopeError(f"redirect target {to_url!r} refused")
        try:
            port = dst.port
            dst_host = normalize_host(dst.hostname or "")
        except ValueError:
            raise OutOfScopeError(f"invalid redirect target {to_url!r}") from None
        if port is not None and port not in DEFAULT_PORTS:
            raise OutOfScopeError(f"redirect to non-default port {port} refused")
        site = registrable_domain(src_host)
        if site is None or registrable_domain(dst_host) != site:
            raise OutOfScopeError(
                f"{dst_host!r} is not on the same registrable domain as {src_host!r}"
            )
        return replace(self, hosts=self.hosts | {dst_host})

    def check_host(self, host: str, port: int | None = None) -> str:
        """Return the normalized host if allowed; raise OutOfScopeError otherwise."""
        try:
            h = normalize_host(host)
        except ValueError:
            raise OutOfScopeError(f"invalid host {host!r}") from None
        if h not in self.hosts:
            raise OutOfScopeError(f"host {h!r} is out of scope")
        if port is not None and port not in DEFAULT_PORTS and (h, port) not in self.extra_ports:
            raise OutOfScopeError(f"port {port} on {h!r} is out of scope")
        return h

    def check_request(self, method: str, url: str) -> str:
        """Gate one HTTP request: GET/HEAD only, http(s), no URL credentials, in-scope host+port."""
        if method.upper() not in ALLOWED_METHODS:
            raise OutOfScopeError(f"method {method} refused (passive: GET/HEAD only)")
        parts = urlsplit(url)
        if parts.scheme not in ALLOWED_SCHEMES:
            raise OutOfScopeError(f"scheme {parts.scheme!r} refused")
        if parts.username or parts.password:
            raise OutOfScopeError("URLs with embedded credentials are refused")
        if self.paths and (parts.scheme != "https" or parts.path not in self.paths or parts.query):
            raise OutOfScopeError(f"only {', '.join(sorted(self.paths))} over https is allowed")
        try:
            port = parts.port
        except ValueError:
            raise OutOfScopeError(f"invalid port in {url!r}") from None
        return self.check_host(parts.hostname or "", port)
