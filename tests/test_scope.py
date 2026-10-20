"""Tests for the scope checkpoint, including that off-scope requests never open a socket."""

import asyncio
import socket
from typing import Any

import httpx
import pytest

from albert.core.http_client import HttpClient
from albert.core.models import Target
from albert.core.scope import OutOfScopeError, ScopePolicy

POLICY = ScopePolicy(frozenset({"a.test"}), frozenset({("a.test", 8443)}))


class SocketOpenedError(Exception):
    pass


@pytest.mark.parametrize(
    "url",
    ["https://a.test/", "http://A.test./x?q=1", "https://a.test:443/", "https://a.test:8443/"],
)
def test_in_scope_passes(url: str) -> None:
    assert POLICY.check_request("GET", url) == "a.test"
    assert POLICY.check_request("head", url) == "a.test"


@pytest.mark.parametrize(
    ("method", "url", "reason"),
    [
        ("GET", "https://evil.test/", "out of scope"),
        ("GET", "https://sub.a.test/", "out of scope"),
        ("GET", "https://a.test:22/", "port 22"),
        ("GET", "ftp://a.test/", "scheme"),
        ("GET", "https://u:p@a.test/", "credentials"),
        ("POST", "https://a.test/", "GET/HEAD only"),
        ("OPTIONS", "https://a.test/", "GET/HEAD only"),
        ("GET", "https://a.test:99999/", "invalid port"),
    ],
)
def test_off_scope_refused(method: str, url: str, reason: str) -> None:
    with pytest.raises(OutOfScopeError, match=reason):
        POLICY.check_request(method, url)


def test_policy_for_target() -> None:
    quick = ScopePolicy.for_target(Target("http://localhost:3000/", "quick"))
    assert quick.check_request("GET", "http://localhost:3000/x") == "localhost"
    with pytest.raises(OutOfScopeError, match="requires a scope.toml entry"):
        ScopePolicy.for_target(Target("https://a.test/", "scan"))
    with pytest.raises(OutOfScopeError, match="active mode not allowed"):
        ScopePolicy.for_target(Target("https://a.test/", "active", authorized_by="me"))


@pytest.fixture
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any DNS lookup or outbound connection raise SocketOpenedError.

    socket.socket.connect itself is left alone: the event loop's own self-pipe uses it.
    """

    def boom(*a: Any, **k: Any) -> Any:
        raise SocketOpenedError

    async def aboom(*a: Any, **k: Any) -> Any:
        raise SocketOpenedError

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", aboom)
    monkeypatch.setattr(asyncio.BaseEventLoop, "create_connection", aboom)


@pytest.mark.usefixtures("no_sockets")
async def test_off_scope_raises_before_socket() -> None:
    async with HttpClient(POLICY) as client:  # real transport, no mocks
        for url in ("https://evil.test/", "https://a.test:22/"):
            with pytest.raises(OutOfScopeError):
                await client.get(url)
        assert client.requests_made == 0


@pytest.mark.usefixtures("no_sockets")
async def test_socket_guard_control() -> None:
    """Control: an in-scope request does reach the socket layer, so the guard above is real."""
    async with HttpClient(ScopePolicy(frozenset({"a.test"}))) as client:
        with pytest.raises(SocketOpenedError):
            await client.get("https://a.test/")


async def test_raw_client_cannot_bypass() -> None:
    """Even the private httpx client goes through the guarded transport."""
    calls: list[httpx.Request] = []

    async def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        return httpx.Response(200)

    client = HttpClient(POLICY, _inner=httpx.MockTransport(handler))
    with pytest.raises(OutOfScopeError, match="GET/HEAD only"):
        await client._client.post("https://a.test/", content=b"x")
    with pytest.raises(OutOfScopeError):
        await client._client.get("https://evil.test/")
    assert calls == []
    await client.aclose()
