"""Test-wide safety nets: no live hosts, ever.

- Any DNS lookup of a non-loopback name fails the test (respx mocks HTTP above DNS, so only
  code that really opens sockets trips this).
- quick/scan get a canned TLS observation unless a test is marked ``real_tls`` (those use a
  local TLS server on 127.0.0.1).
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from albert.core.models import TLSObservation
from albert.core.scope import ScopePolicy
from albert.core.tls_client import TLSLimits

_LOCAL = {None, "localhost", "127.0.0.1", "::1"}


@pytest.fixture(autouse=True)
def _no_live_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    real = socket.getaddrinfo

    def guarded(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host in _LOCAL:
            return real(host, *args, **kwargs)
        raise OSError(f"test tried to resolve {host!r}: tests must not touch live hosts")

    monkeypatch.setattr(socket, "getaddrinfo", guarded)


def good_tls(host: str, port: int = 443) -> TLSObservation:
    """A healthy TLS result: TLS 1.2 + 1.3, verified, no cert issues."""
    return TLSObservation(
        host,
        port,
        protocol="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        enumerated=True,
        protocols=(("TLSv1.2", True), ("TLSv1.3", True)),
        accepted_ciphers=(("TLSv1.3", "TLS_AES_128_GCM_SHA256", True),),
    )


@pytest.fixture(autouse=True)
def _fake_tls(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("real_tls"):
        return

    async def fake(
        policy: ScopePolicy, host: str, port: int = 443, limits: TLSLimits | None = None
    ) -> TLSObservation:
        return good_tls(policy.check_host(host, port), port)

    monkeypatch.setattr("albert.quick.collect_tls", fake)
