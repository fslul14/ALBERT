"""Albert command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from albert import __version__
from albert.core.models import Target
from albert.core.report import write_report
from albert.quick import run_quick


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="albert", description="Passive web vulnerability scanner."
    )
    parser.add_argument("--version", action="version", version=f"albert {__version__}")
    sub = parser.add_subparsers(dest="command")
    quick = sub.add_parser("quick", help="single-page, public-equivalent check of any URL")
    quick.add_argument("url", nargs="?", help="URL to check (prompted for if omitted)")
    quick.add_argument("--out", type=Path, default=Path("reports"), help="report directory")
    quick.add_argument("--format", default="md,json", help="comma list: md,json")
    return parser


def _ask_url() -> str:
    return input("Which URL should I scan? ").strip()


def _cmd_quick(args: argparse.Namespace) -> int:
    url = args.url or _ask_url()
    if url and "://" not in url:
        url = f"https://{url}"
    try:
        target = Target(url, "quick")
        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        result = asyncio.run(run_quick(target))
        paths = write_report(result, args.out, formats)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    counts = ", ".join(f"{n} {sev}" for sev, n in result.severity_counts().items() if n)
    print(f"{target.host}: {counts or 'no findings'}")
    for err in result.errors:
        print(f"  error: {err}", file=sys.stderr)
    for path in paths:
        print(f"  {path}")
    return 1 if result.errors and not result.pages else 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "quick":
        return _cmd_quick(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
