"""`albert quick`: single-page, public-equivalent check of any URL (no scope entry).

Collects: the page (with its redirect hops), /.well-known/security.txt, the TLS certificate
and protocol/cipher support, and DNS/email records (SPF, DMARC, MTA-STS, ...). Same-site
redirects (apex <-> www, http -> https) are followed via the narrow quick-only rule in
ScopePolicy.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from albert.checks.dns_email import run_dns_email_checks
from albert.checks.security_txt import WELL_KNOWN_PATH
from albert.checks.tls import check_downgrade, check_http_redirect, check_tls
from albert.core.dns_client import collect_dns, fetch_mta_sts_policy
from albert.core.engine import run_checks
from albert.core.http_client import (
    BudgetExceededError,
    ClientLimits,
    FetchChain,
    FetchError,
    HttpClient,
)
from albert.core.models import CollectedResponse, DnsSnapshot, ScanResult, Target
from albert.core.scope import OutOfScopeError, ScopePolicy, registrable_domain
from albert.core.tls_client import TLSLimits, collect_tls

MAX_REQUESTS = 12  # whole quick run: page + redirects + security.txt
MAX_SITE_HOPS = 2  # cross-host same-site redirects followed
TLS_ENUM_SKIPPED = (
    "TLS protocol/cipher enumeration skipped (--no-tls-enum): certificate handshake only"
)


async def _get(
    policy: ScopePolicy, url: str, budget: int, exclude: re.Pattern[str] | None = None
) -> tuple[FetchChain, int]:
    async with HttpClient(policy, ClientLimits(max_requests=budget, exclude=exclude)) as client:
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
) -> tuple[list[CollectedResponse], int]:
    parts = urlsplit(final_url)
    chain, used = await _get(policy, f"{parts.scheme}://{parts.netloc}{WELL_KNOWN_PATH}", budget)
    return chain.hops, used


async def run_tls_step(
    result: ScanResult,
    policy: ScopePolicy,
    url: str,
    page_hops: list[CollectedResponse],
    *,
    http_budget: int,
    limits: TLSLimits | None = None,
    exclude: re.Pattern[str] | None = None,
) -> None:
    """TLS/cert inspection for ``url``'s host, plus the HTTP->HTTPS redirect and downgrade checks.

    The redirect check uses the page's own hops when the start URL was http://; otherwise it
    GETs http://<host>/ once (the start URL over plain HTTP, as a visitor typing the domain).
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port if parts.scheme == "https" and parts.port else 443
    try:
        obs = await collect_tls(policy, host, port, limits)
    except OutOfScopeError as e:
        result.errors.append(f"tls: {e}")
        return
    findings = check_tls(obs) + check_downgrade(page_hops)
    if page_hops and urlsplit(page_hops[0].url).scheme == "http":
        findings += check_http_redirect(page_hops)
    elif http_budget > 0 and parts.port in (None, 443):
        try:
            chain, _ = await _get(policy, f"http://{host}/", http_budget, exclude)
            result.pages += [h.url for h in chain.hops]
            findings += check_http_redirect(chain.hops) + check_downgrade(chain.hops)
        except (FetchError, OutOfScopeError) as e:
            result.notes.append(f"http://{host}/ not reachable for the redirect check ({e})")
    result.findings += findings
    result.checks_run.append("tls")


async def run_dns_step(result: ScanResult, host: str) -> DnsSnapshot | None:
    """DNS/email posture for the target's registrable domain (its own published records)."""
    domain = registrable_domain(host)
    if domain is None:
        result.notes.append(f"DNS/email skipped: {host} has no registrable domain (IP/local)")
        return None
    snap = await collect_dns(domain, host, fetch_policy=fetch_mta_sts_policy)
    result.findings += run_dns_email_checks([snap])
    result.notes += list(snap.notes)
    if snap.mta_sts_policy is not None:
        result.pages.append(snap.mta_sts_policy.url)
    result.checks_run.append("dns_email")
    return snap


async def run_quick(target: Target, tls_limits: TLSLimits | None = None) -> ScanResult:
    """Run every quick collector, then the matching checks."""
    result = ScanResult(target)
    policy = ScopePolicy.for_target(target)
    try:
        hops, policy, budget = await _collect_page(result, policy, MAX_REQUESTS)
    except (FetchError, OutOfScopeError) as e:
        result.errors.append(str(e))
        hops, budget = [], 0
    run_checks(result, hops, ["headers", "cookies", "cors", "disclosure"])
    result.pages = [h.url for h in hops]

    if hops and budget > 0:
        try:
            sec, used = await _collect_security_txt(hops[-1].url, policy, budget)
            budget -= used
        except (FetchError, OutOfScopeError) as e:
            result.errors.append(f"security.txt: {e}")
            sec = []
        result.pages += [h.url for h in sec]
        run_checks(result, sec, ["security_txt"])

    tls_url = hops[-1].url if hops else target.url
    await run_tls_step(result, policy, tls_url, hops, http_budget=budget, limits=tls_limits)
    if tls_limits is not None and not tls_limits.enumerate:
        result.notes.append(TLS_ENUM_SKIPPED)
    await run_dns_step(result, target.host)
    result.finish()
    return result


async def run_tls_only(target: Target, limits: TLSLimits | None = None) -> ScanResult:
    """Handshake + certificate inspection only: no page, security.txt, or HTTP requests."""
    result = ScanResult(target)
    await run_tls_step(
        result, ScopePolicy.for_target(target), target.url, [], http_budget=0, limits=limits
    )
    result.notes.append("TLS-only run: no HTTP requests were made")
    if limits is not None and not limits.enumerate:
        result.notes.append(TLS_ENUM_SKIPPED)
    result.finish()
    return result
