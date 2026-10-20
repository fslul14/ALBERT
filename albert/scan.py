"""`albert scan`: authorized full crawl, then checks across every page (findings grouped)."""

from __future__ import annotations

from pathlib import Path

from albert.core.crawler import Crawler, CrawlLimits
from albert.core.engine import run_checks
from albert.core.http_client import ClientLimits
from albert.core.models import ScanResult, Target
from albert.core.scope import ScopePolicy
from albert.quick import run_tls_step


async def run_scan(
    target: Target,
    crawl_limits: CrawlLimits,
    rate: float = 2.0,
    *,
    state_path: Path | None = None,
    resume: bool = False,
) -> ScanResult:
    """Crawl the target (scope-checked, same host), run page checks, then inspect TLS."""
    result = ScanResult(target)
    budget = crawl_limits.max_pages * 3 + 20  # redirect hops + robots + sitemaps
    policy = ScopePolicy.for_target(target)
    crawler = Crawler(
        policy,
        target.url,
        ClientLimits(rate=rate, max_requests=budget),
        crawl_limits,
        state_path=state_path,
        resume=resume,
    )
    crawl = await crawler.run()
    result.pages = crawl.pages
    result.skipped = crawl.skipped
    result.blocked = crawl.blocked
    result.errors = crawl.errors
    result.notes = crawl.notes
    run_checks(result, crawl.responses, ["headers", "cookies"])
    run_checks(result, crawl.responses + crawl.aux, ["disclosure"])  # + robots/sitemaps
    await run_tls_step(result, policy, target.url, crawl.responses[:1], http_budget=3)
    result.finish()
    return result
