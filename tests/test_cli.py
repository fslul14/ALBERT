"""Smoke test for the CLI entry point."""

import pytest

from albert.cli import main


def test_version_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
