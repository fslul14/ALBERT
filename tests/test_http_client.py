"""Tests for the HTTP client: UA, redirects, budget, and per-host limits. No live hosts."""

import asyncio
import re

import httpx
import pytest
import respx

from albert.core.http_client import USER_AGENT, BudgetExceededError, ClientLimits, HttpClient
from albert.core.scope import OutOfScopeError, ScopePolicy

TWO_HOSTS = ScopePolicy(frozenset({"a.test", "b.test"}))


@respx.mock
async def test_get_head_with_honest_ua() -> None:
    route = respx.route(host="a.test").mock(return_value=httpx.Response(200, text="hi"))
    async with HttpClient(TWO_HOSTS) as client:
        r = await client.get("https://a.test/")
        assert r.status_code == 200 and r.text == "hi"
        assert (await client.head("https://a.test/")).status_code == 200
    assert route.call_count == 2
    assert route.calls.last.request.headers["User-Agent"] == USER_AGENT
    assert USER_AGENT.startswith("Albert/")


@respx.mock
async def test_gzip_body_decoded() -> None:
    import gzip

    respx.get("https://a.test/").mock(
        return_value=httpx.Response(
            200, content=gzip.compress(b"zipped"), headers={"Content-Encoding": "gzip"}
        )
    )
    async with HttpClient(TWO_HOSTS) as client:
        assert (await client.get("https://a.test/")).text == "zipped"


@respx.mock
async def test_redirect_off_scope_blocked() -> None:
    respx.get("https://a.test/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.test/"})
    )
    evil = respx.route(host="evil.test").mock(return_value=httpx.Response(200))
    async with HttpClient(TWO_HOSTS) as client:
        with pytest.raises(OutOfScopeError, match="evil.test"):
            await client.get("https://a.test/")
    assert not evil.called


@respx.mock
async def test_redirect_in_scope_followed_and_counted() -> None:
    respx.get("https://a.test/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://b.test/x"})
    )
    respx.get("https://b.test/x").mock(return_value=httpx.Response(200))
    async with HttpClient(TWO_HOSTS) as client:
        assert (await client.get("https://a.test/")).url == "https://b.test/x"
        assert client.requests_made == 2


@respx.mock
async def test_budget() -> None:
    respx.route(host="a.test").mock(return_value=httpx.Response(200))
    async with HttpClient(TWO_HOSTS, ClientLimits(rate=0, max_requests=2)) as client:
        await client.get("https://a.test/1")
        await client.get("https://a.test/2")
        with pytest.raises(BudgetExceededError):
            await client.get("https://a.test/3")
        assert client.requests_made == 2


@respx.mock
async def test_timeout_surfaces() -> None:
    respx.get("https://a.test/").mock(side_effect=httpx.ReadTimeout("slow"))
    async with HttpClient(TWO_HOSTS, ClientLimits(timeout=1)) as client:
        assert client._client.timeout.read == 1
        with pytest.raises(httpx.ReadTimeout):
            await client.get("https://a.test/")


async def test_concurrency_cap_is_per_host() -> None:
    inflight: dict[str, int] = {"a.test": 0, "b.test": 0}
    peak = {"a.test": 0, "b.test": 0, "total": 0}

    async def handler(req: httpx.Request) -> httpx.Response:
        h = req.url.host
        inflight[h] += 1
        peak[h] = max(peak[h], inflight[h])
        peak["total"] = max(peak["total"], sum(inflight.values()))
        await asyncio.sleep(0.05)
        inflight[h] -= 1
        return httpx.Response(200)

    limits = ClientLimits(rate=0, concurrency=1)
    async with HttpClient(TWO_HOSTS, limits, _inner=httpx.MockTransport(handler)) as client:
        urls = [f"https://{h}/{i}" for i in range(3) for h in ("a.test", "b.test")]
        await asyncio.gather(*(client.get(u) for u in urls))
    assert peak["a.test"] == 1 and peak["b.test"] == 1  # cap holds per host
    assert peak["total"] == 2  # but b.test never waited on a.test's slot


async def test_rate_limit_is_per_host() -> None:
    loop = asyncio.get_running_loop()
    starts: dict[str, list[float]] = {"a.test": [], "b.test": []}

    async def handler(req: httpx.Request) -> httpx.Response:
        starts[req.url.host].append(loop.time())
        return httpx.Response(200)

    limits = ClientLimits(rate=4, concurrency=10)  # 0.25 s spacing per host
    async with HttpClient(TWO_HOSTS, limits, _inner=httpx.MockTransport(handler)) as client:
        t0 = loop.time()
        await asyncio.gather(
            client.get("https://a.test/1"),
            client.get("https://a.test/2"),
            client.get("https://b.test/1"),
        )
    a1, a2 = sorted(starts["a.test"])
    assert a2 - a1 >= 0.2  # a.test's second request was spaced
    assert starts["b.test"][0] - t0 < 0.1  # b.test didn't inherit a.test's wait


@respx.mock
async def test_exclude_never_requested_and_redirect_not_followed() -> None:
    login = respx.get("https://a.test/login").mock(return_value=httpx.Response(200))
    respx.get("https://a.test/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://a.test/login"})
    )
    limits = ClientLimits(rate=0, exclude=re.compile(r"/login\b"))
    async with HttpClient(TWO_HOSTS, limits) as client:
        with pytest.raises(OutOfScopeError, match="--exclude"):
            await client.get("https://a.test/login")
        chain = await client.fetch_chain("https://a.test/")
        assert client.requests_made == 1  # only "/"; the excluded URL never left
    assert chain.not_followed == "https://a.test/login" and "--exclude" in (chain.note or "")
    assert not login.called
