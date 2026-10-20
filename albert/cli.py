"""Albert command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import date
from pathlib import Path

from albert import __version__
from albert.config import DEFAULT_SCOPE_PATH, Scope, ScopeError, append_scope_entry, load_scope
from albert.core.crawler import CrawlLimits, state_path_for
from albert.core.models import ScanResult, Target
from albert.core.report import write_report
from albert.quick import run_quick
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

    scan = sub.add_parser("scan", help="authorized full crawl (needs a scope.toml entry)")
    _add_output_args(scan)
    scan.add_argument("--scope", type=Path, default=DEFAULT_SCOPE_PATH, help="scope file")
    scan.add_argument("--max-pages", type=int, default=CrawlLimits.max_pages)
    scan.add_argument("--max-depth", type=int, default=CrawlLimits.max_depth)
    scan.add_argument("--rate", type=float, default=2.0, help="requests/second to the host")
    scan.add_argument("--resume", action="store_true", help="continue an interrupted scan")
    return parser


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
        result = asyncio.run(run_quick(target))
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
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
