"""Albert command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import date
from pathlib import Path

from albert import __version__
from albert.checks.fingerprint import SIGNATURES_PATH, lint_signatures
from albert.checks.privacy import TRACKERS_PATH, lint_trackers
from albert.config import DEFAULT_SCOPE_PATH, Scope, ScopeError, append_scope_entry, load_scope
from albert.core.browser import RenderLimits
from albert.core.crawler import CrawlLimits, state_path_for
from albert.core.engine import RULES_DIR, lint_rules
from albert.core.models import ScanResult, Target
from albert.core.report import write_report
from albert.core.vulndb import default_cache_dir
from albert.quick import run_quick, run_tls_only
from albert.scan import run_scan


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("url", nargs="?", help="target URL (prompted for if omitted)")
    p.add_argument("--out", type=Path, default=Path("reports"), help="report directory")
    p.add_argument("--format", default="md,json", help="comma list: md,json")


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="albert", description="Passive web vulnerability scanner."
    )
    parser.add_argument("--version", action="version", version=f"albert {__version__}")
    sub = parser.add_subparsers(dest="command")

    quick = sub.add_parser("quick", help="single-page, public-equivalent check of any URL")
    _add_output_args(quick)
    quick.add_argument(
        "--tls-only", action="store_true", help="handshake + certificate inspection only, no HTTP"
    )

    scan = sub.add_parser("scan", help="authorized full crawl (needs a scope.toml entry)")
    _add_output_args(scan)
    scan.add_argument("--scope", type=Path, default=DEFAULT_SCOPE_PATH, help="scope file")
    scan.add_argument("--max-pages", type=int, default=CrawlLimits.max_pages)
    scan.add_argument("--max-depth", type=int, default=CrawlLimits.max_depth)
    scan.add_argument("--rate", type=float, default=2.0, help="requests/second to the host")
    scan.add_argument("--resume", action="store_true", help="continue an interrupted scan")
    scan.add_argument("--render", action="store_true", help="render pages in headless Chromium")
    scan.add_argument("--render-max", type=int, default=RenderLimits.max_pages)
    scan.add_argument(
        "--full", action="store_true", help="also check DNS/email records (SPF, DMARC, ...)"
    )
    scan.add_argument(
        "--cve",
        choices=["off", "cache", "online"],
        default="cache",
        help="CVE matching: cache = local data only (default); online = query OSV.dev/NVD "
        "(third-party, never the target)",
    )
    rules = sub.add_parser("rules", help="validate or list the YAML rules")
    rules.add_argument("action", choices=["lint", "list"])
    rules.add_argument("--dir", type=Path, default=RULES_DIR, help="rules directory")
    return parser


def _cmd_rules(args: argparse.Namespace) -> int:
    rules, problems = lint_rules(args.dir)
    if args.action == "lint":
        techs, sig_problems = lint_signatures()
        services, tracker_problems = lint_trackers()
        sig_problems += tracker_problems
        for problem in problems + sig_problems:
            print(f"  {problem}", file=sys.stderr)
        verdict = f"{len(problems)} problem(s)" if problems else "OK"
        print(f"{len(rules)} valid rule(s) in {args.dir}: {verdict}")
        sig_verdict = f"{len(sig_problems)} problem(s)" if sig_problems else "OK"
        print(
            f"{len(techs)} technology signature(s) in {SIGNATURES_PATH.name}, "
            f"{len(services)} tracker signature(s) in {TRACKERS_PATH.name}: {sig_verdict}"
        )
        return 1 if problems or sig_problems else 0
    for r in sorted(rules, key=lambda r: (r.family, r.id)):
        print(f"{r.family:8} {r.severity.label:8} {r.confidence.label:6} {r.id:42} {r.title}")
    if problems:
        print(f"({len(problems)} invalid rule(s) skipped; run: albert rules lint)", file=sys.stderr)
    return 1 if problems else 0


def _ask_url() -> str:
    return input("Which URL should I scan? ").strip()


def _target_url(args: argparse.Namespace) -> str:
    url: str = args.url or _ask_url()
    return f"https://{url}" if url and "://" not in url else url


def _formats(args: argparse.Namespace) -> list[str]:
    return [f.strip() for f in args.format.split(",") if f.strip()]


def _finish(result: ScanResult, args: argparse.Namespace) -> int:
    paths = write_report(result, args.out, _formats(args))
    counts = ", ".join(f"{n} {sev}" for sev, n in result.severity_counts().items() if n)
    print(f"{result.target.host}: {counts or 'no findings'} ({len(result.pages)} pages)")
    for err in result.errors:
        print(f"  error: {err}", file=sys.stderr)
    for path in paths:
        print(f"  {path}")
    return 1 if result.errors and not result.pages else 0


def _cmd_quick(args: argparse.Namespace) -> int:
    try:
        target = Target(_target_url(args), "quick")
        result = asyncio.run(run_tls_only(target) if args.tls_only else run_quick(target))
        return _finish(result, args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def _scope_for(path: Path, host: str) -> Scope | None:
    """Load scope; if ``host`` has no entry, ask who authorized it and add one."""
    scope = load_scope(path) if path.exists() else Scope([])
    if scope.entry_for(host) is not None:
        return scope
    who = input(f"{host} has no scope entry. Who authorized this scan? (blank cancels) ").strip()
    if not who:
        return None
    entry = append_scope_entry(path, host, who, date.today())
    print(f"  added {entry.host} to {path} (authorized_by: {entry.authorized_by})")
    return load_scope(path)


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        url = _target_url(args)
        host = Target(url, "quick").host  # validates the URL before touching scope.toml
        scope = _scope_for(args.scope, host)
        if scope is None:
            print("cancelled: no authorization recorded", file=sys.stderr)
            return 2
        target = scope.target(url, "scan")
        limits = CrawlLimits(max_pages=args.max_pages, max_depth=args.max_depth)
        result = asyncio.run(
            run_scan(
                target,
                limits,
                args.rate,
                state_path=state_path_for(args.out, target.host),
                resume=args.resume,
                render=RenderLimits(max_pages=args.render_max) if args.render else None,
                cve_mode=args.cve,
                full=args.full,
                cache_dir=default_cache_dir(args.out),
            )
        )
        return _finish(result, args)
    except (ValueError, ScopeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "quick":
        return _cmd_quick(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
