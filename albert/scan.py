"""`albert scan`: authorized full crawl, then checks across every page (findings grouped)."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from albert.checks.cve import match_cves
from albert.checks.fingerprint import FingerprintInput, detect_technologies
from albert.checks.intel_lookups import intel_findings
from albert.checks.js import run_js_checks
from albert.checks.privacy import PrivacyInput, run_privacy_checks
from albert.checks.rendered import reconcile_meta_csp, run_rendered_checks
from albert.core.browser import RenderError, RenderLimits, render_pages
from albert.core.crawler import Crawler, CrawlLimits
from albert.core.engine import run_checks
from albert.core.http_client import ClientLimits, HttpClient
from albert.core.intel_sources import collect_intel
from albert.core.models import CollectedResponse, DnsSnapshot, RenderedPage, ScanResult, Target
from albert.core.scope import ScopePolicy, registrable_domain
from albert.core.tls_client import TLSLimits
from albert.core.vulndb import CveMode, default_cache_dir, lookup_all
from albert.quick import TLS_ENUM_SKIPPED, run_dns_step, run_tls_step

INSTALL_HINT = r".venv\Scripts\playwright install chromium"


async def _intel_step(
    result: ScanResult,
    target: Target,
    snap: DnsSnapshot | None,
    cache_dir: Path | None,
    scope_hosts: frozenset[str],
) -> None:
    """Third-party intel (CT, Wayback, blocklists, Safe Browsing). Never contacts the target;
    surfaced hosts are reported with their scope status, never contacted."""
    domain = registrable_domain(target.host)
    if domain is None:
        result.notes.append("external intel skipped: no registrable domain")
        return
    mx_ips = [
        v
        for a in (snap.answers if snap else ())
        if a.rtype == "A" and a.name != snap.host  # type: ignore[union-attr]
        for v in a.values
    ]
    base = (cache_dir or default_cache_dir(Path("reports"))).parent / "intel"
    report = await collect_intel(domain, (target.host,), base, mx_ips=mx_ips)
    result.findings += intel_findings(report, lambda h: h in scope_hosts)
    result.checks_run.append("intel")
    result.notes.append(
        "external intel: crt.sh, Wayback, DNS blocklists"
        + (
            ", Safe Browsing"
            if any(r.source == "safe_browsing" and r.status != "skipped" for r in report.results)
            else ""
        )
        + " (third-party services only; discovered hosts were not contacted)"
    )


async def run_scan(
    target: Target,
    crawl_limits: CrawlLimits,
    rate: float = 2.0,
    *,
    state_path: Path | None = None,
    resume: bool = False,
    render: RenderLimits | None = None,
    cve_mode: CveMode = "cache",
    cache_dir: Path | None = None,
    full: bool = False,
    scope_hosts: frozenset[str] | None = None,
    tls_enum: bool = True,
    exclude: re.Pattern[str] | None = None,
) -> ScanResult:
    """Crawl the target (scope-checked, same host), run page checks, optionally render
    pages headlessly (opt-in), then inspect TLS. ``tls_enum=False`` keeps TLS to the certificate
    handshake (no sslyze protocol/cipher enumeration), e.g. for vendor-hosted targets.
    URLs matching ``exclude`` are recorded as skipped and never requested."""
    result = ScanResult(target)
    budget = crawl_limits.max_pages * 3 + 20  # redirect hops + robots + sitemaps
    policy = ScopePolicy.for_target(target)
    crawler = Crawler(
        policy,
        target.url,
        ClientLimits(rate=rate, max_requests=budget, exclude=exclude),
        crawl_limits,
        state_path=state_path,
        resume=resume,
    )
    crawl = await crawler.run()
    if exclude is not None:
        crawl.notes.append(f"--exclude {exclude.pattern!r}: matching URLs were never requested")
    result.pages = crawl.pages
    result.skipped = crawl.skipped
    result.blocked = crawl.blocked
    result.errors = crawl.errors
    result.notes = crawl.notes
    run_checks(result, crawl.responses, ["headers", "cookies", "cors"])
    run_checks(result, crawl.responses + crawl.aux, ["disclosure"])  # + robots/sitemaps
    run_checks(result, crawl.security_txt, ["security_txt"])  # once, on its own fetch chain
    result.pages += [h.url for h in crawl.security_txt]
    rendered = (
        await _render_step(result, policy, crawl.responses, rate, render, exclude) if render else []
    )
    rendered_scripts = [js for page in rendered for js in page.scripts]
    result.tech = detect_technologies(
        FingerprintInput(
            responses=[*crawl.responses, *crawl.aux, *crawl.scripts],
            scripts=[*crawl.scripts, *rendered_scripts],
            rendered=rendered,
            favicons=crawl.favicons,
        )
    )
    result.checks_run.append("fingerprint")
    result.findings += run_privacy_checks(
        PrivacyInput(target.url, rendered, crawl.responses, [*crawl.scripts, *rendered_scripts])
    )
    result.checks_run.append("privacy")
    if cve_mode != "off":
        lookups = await lookup_all(
            result.tech,
            cve_mode,
            cache_dir or default_cache_dir(Path("reports")),
            target_hosts=tuple(policy.hosts),
        )
        result.findings += match_cves(lookups.lookups)
        result.notes += lookups.notes
        result.checks_run.append("cve")
    result.findings += run_js_checks(crawl.responses, [*crawl.scripts, *rendered_scripts])
    result.checks_run.append("js")
    if crawl.scripts or rendered_scripts:
        result.notes.append(
            f"analysed {len(crawl.scripts)} crawled + {len(rendered_scripts)} rendered script "
            "response(s) and inline scripts; .map files are never fetched"
        )
    await run_tls_step(
        result,
        policy,
        target.url,
        crawl.responses[:1],
        http_budget=3,
        limits=TLSLimits(enumerate=tls_enum),
        exclude=exclude,
    )
    if not tls_enum:
        result.notes.append(TLS_ENUM_SKIPPED)
    if full:
        snap = await run_dns_step(result, target.host)
        await _intel_step(result, target, snap, cache_dir, scope_hosts or frozenset(policy.hosts))
    result.finish()
    return result


async def _render_step(
    result: ScanResult,
    policy: ScopePolicy,
    responses: list[CollectedResponse],
    rate: float,
    limits: RenderLimits,
    exclude: re.Pattern[str] | None = None,
) -> list[RenderedPage]:
    """Render crawled HTML pages; all browser traffic goes through HttpClient (scope first)."""
    urls = list(dict.fromkeys(r.url for r in responses if r.is_document))
    budget = limits.max_pages * limits.max_requests_per_page
    try:
        async with HttpClient(
            policy, ClientLimits(rate=rate, max_requests=budget, exclude=exclude)
        ) as client:
            pages = await render_pages(policy, client, urls, limits)
    except RenderError as e:
        result.errors.append(f"render skipped: {e} (install Chromium: {INSTALL_HINT})")
        return []
    result.findings += run_rendered_checks(pages)
    result.findings = reconcile_meta_csp(result.findings, pages)
    result.checks_run.append("rendered")
    result.errors += [f"{p.url}: {p.error}" for p in pages if p.error]
    blocked: Counter[str] = Counter()
    for p in pages:
        for r in p.requests:
            if r.outcome == "blocked":
                parts = urlsplit(r.url)
                blocked[f"{parts.scheme}://{parts.netloc}"] += 1
    result.skipped += [
        f"{origin} ({n} sub-request(s) from rendered pages; out of scope, not fetched)"
        for origin, n in blocked.most_common()
    ]
    result.notes.append(f"rendered {len(pages)} page(s) headlessly (no network of its own)")
    return pages
