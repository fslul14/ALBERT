"""The single "may I contact this?" checkpoint. Every egress path calls it before any socket."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from albert.core.models import Target

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


@dataclass(frozen=True)
class ScopePolicy:
    """Hosts (and non-default ports) Albert may contact during one run."""

    hosts: frozenset[str]
    extra_ports: frozenset[tuple[str, int]] = frozenset()

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
        return cls(frozenset({host}), frozenset(extra))

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
        try:
            port = parts.port
        except ValueError:
            raise OutOfScopeError(f"invalid port in {url!r}") from None
        return self.check_host(parts.hostname or "", port)
