"""`albert scan`: authorized full crawl, then checks across every page (findings grouped)."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from albert.checks.js import run_js_checks
from albert.checks.rendered import reconcile_meta_csp, run_rendered_checks
from albert.core.browser import RenderError, RenderLimits, render_pages
from albert.core.crawler import Crawler, CrawlLimits
from albert.core.engine import run_checks
from albert.core.http_client import ClientLimits, HttpClient
from albert.core.models import CollectedResponse, RenderedPage, ScanResult, Target
from albert.core.scope import ScopePolicy
from albert.quick import run_tls_step

INSTALL_HINT = r".venv\Scripts\playwright install chromium"


async def run_scan(
    target: Target,
    crawl_limits: CrawlLimits,
    rate: float = 2.0,
    *,
    state_path: Path | None = None,
    resume: bool = False,
    render: RenderLimits | None = None,
) -> ScanResult:
    """Crawl the target (scope-checked, same host), run page checks, optionally render
    pages headlessly (opt-in), then inspect TLS."""
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
    run_checks(result, crawl.responses, ["headers", "cookies", "cors"])
    run_checks(result, crawl.responses + crawl.aux, ["disclosure"])  # + robots/sitemaps
    rendered = await _render_step(result, policy, crawl.responses, rate, render) if render else []
    rendered_scripts = [js for page in rendered for js in page.scripts]
    result.findings += run_js_checks(crawl.responses, [*crawl.scripts, *rendered_scripts])
    result.checks_run.append("js")
    if crawl.scripts or rendered_scripts:
        result.notes.append(
            f"analysed {len(crawl.scripts)} crawled + {len(rendered_scripts)} rendered script "
            "response(s) and inline scripts; .map files are never fetched"
        )
    await run_tls_step(result, policy, target.url, crawl.responses[:1], http_budget=3)
    result.finish()
    return result


async def _render_step(
    result: ScanResult,
    policy: ScopePolicy,
    responses: list[CollectedResponse],
    rate: float,
    limits: RenderLimits,
) -> list[RenderedPage]:
    """Render crawled HTML pages; all browser traffic goes through HttpClient (scope first)."""
    urls = list(dict.fromkeys(r.url for r in responses if r.is_document))
    budget = limits.max_pages * limits.max_requests_per_page
    try:
        async with HttpClient(policy, ClientLimits(rate=rate, max_requests=budget)) as client:
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
