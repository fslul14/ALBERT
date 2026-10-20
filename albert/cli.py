"""Albert command-line entry point (subcommands are wired in later steps)."""

import argparse

from albert import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="albert", description="Passive web vulnerability scanner."
    )
    parser.add_argument("--version", action="version", version=f"albert {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    build_parser().parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
