"""`albert quick`: single-page, public-equivalent check of any URL (no scope entry).

Collects: the page (with its redirect hops), /.well-known/security.txt, and, as their steps
land, the TLS certificate and DNS/email records. Same-site redirects (apex <-> www,
http -> https) are followed via the narrow quick-only rule in ScopePolicy.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from albert.checks.security_txt import WELL_KNOWN_PATH
from albert.core.engine import run_checks
from albert.core.http_client import (
    BudgetExceededError,
    ClientLimits,
    FetchChain,
    FetchError,
    HttpClient,
)
from albert.core.models import CollectedResponse, ScanResult, Target
from albert.core.scope import OutOfScopeError, ScopePolicy

MAX_REQUESTS = 12  # whole quick run: page + redirects + security.txt
MAX_SITE_HOPS = 2  # cross-host same-site redirects followed


async def _get(policy: ScopePolicy, url: str, budget: int) -> tuple[FetchChain, int]:
    async with HttpClient(policy, ClientLimits(max_requests=budget)) as client:
        try:
            return await client.fetch_chain(url), client.requests_made
        except BudgetExceededError as e:
            return FetchChain([], note=str(e)), client.requests_made


def _redirect_notes(hops: list[CollectedResponse]) -> list[str]:
    notes = []
    for a, b in zip(hops, hops[1:], strict=False):
        if 300 <= a.status < 400:
            cross = urlsplit(a.url).hostname != urlsplit(b.url).hostname
            suffix = " (same registrable domain; followed in quick mode)" if cross else ""
            notes.append(f"redirect {a.status}: {a.url} -> {b.url}{suffix}")
    return notes


async def _collect_page(
    result: ScanResult, policy: ScopePolicy, budget: int
) -> tuple[list[CollectedResponse], ScopePolicy, int]:
    """Fetch the start URL, widening only for same-registrable-domain redirects."""
    hops: list[CollectedResponse] = []
    url = result.target.url
    for _ in range(MAX_SITE_HOPS + 1):
        chain, used = await _get(policy, url, budget)
        budget -= used
        hops += chain.hops
        if chain.not_followed is None or not chain.hops:
            if chain.note:
                result.skipped.append(chain.note)
            break
        try:
            policy = policy.with_same_site_redirect(chain.hops[-1].url, chain.not_followed)
        except OutOfScopeError:
            result.skipped.append(chain.note or f"redirect to {chain.not_followed} not followed")
            break
        url = chain.not_followed
    else:
        result.skipped.append(f"stopped after {MAX_SITE_HOPS} cross-host redirects")
    result.notes += _redirect_notes(hops)
    return hops, policy, budget


async def _collect_security_txt(
    final_url: str, policy: ScopePolicy, budget: int
) -> list[CollectedResponse]:
    parts = urlsplit(final_url)
    chain, _ = await _get(policy, f"{parts.scheme}://{parts.netloc}{WELL_KNOWN_PATH}", budget)
    return chain.hops


def _tls_cert(result: ScanResult) -> None:
    """Stub until step 10 (TLS/cert module)."""
    result.notes.append("not covered yet: TLS certificate (arrives with the TLS module)")


def _dns_email(result: ScanResult) -> None:
    """Stub until step 17 (DNS/email module)."""
    result.notes.append("not covered yet: DNS/email records (arrive with the DNS module)")


async def run_quick(target: Target) -> ScanResult:
    """Run every quick collector, then the matching checks."""
    result = ScanResult(target)
    policy = ScopePolicy.for_target(target)
    try:
        hops, policy, budget = await _collect_page(result, policy, MAX_REQUESTS)
    except (FetchError, OutOfScopeError) as e:
        result.errors.append(str(e))
        hops, budget = [], 0
    run_checks(result, hops, ["headers", "cookies"])
    result.pages = [h.url for h in hops]

    if hops and budget > 0:
        try:
            sec = await _collect_security_txt(hops[-1].url, policy, budget)
        except (FetchError, OutOfScopeError) as e:
            result.errors.append(f"security.txt: {e}")
            sec = []
        result.pages += [h.url for h in sec]
        run_checks(result, sec, ["security_txt"])

    _tls_cert(result)
    _dns_email(result)
    result.finish()
    return result
