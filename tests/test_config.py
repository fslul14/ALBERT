"""Tests for scope.toml loading and validation."""

from datetime import date
from pathlib import Path

import pytest

from albert.config import ScopeError, load_scope, parse_scope

VALID = """
[[target]]
host = "Example.com."
authorized_by = "self (own domain)"
date = "2026-10-20"
allow_active = true

[[target]]
host = "localhost"
authorized_by = "self (lab)"
date = 2026-10-20
"""


def _one(**fields: str) -> str:
    base = {"host": '"example.com"', "authorized_by": '"self"', "date": '"2026-10-20"'}
    base.update(fields)
    body = "\n".join(f"{k} = {v}" for k, v in base.items() if v != "OMIT")
    return f"[[target]]\n{body}\n"


def test_valid_load() -> None:
    scope = parse_scope(VALID)
    ex, lh = scope.entries
    assert ex.host == "example.com"
    assert ex.allow_active is True
    assert ex.date == date(2026, 10, 20)
    assert lh.date == date(2026, 10, 20)  # native TOML date accepted


def test_allow_active_defaults_false() -> None:
    assert parse_scope(_one()).entries[0].allow_active is False


def test_allow_active_must_be_bool() -> None:
    with pytest.raises(ScopeError, match="allow_active must be true or false"):
        parse_scope(_one(allow_active='"yes"'))


@pytest.mark.parametrize("value", ["OMIT", '""', '"   "'])
def test_authorized_by_missing_or_blank(value: str) -> None:
    with pytest.raises(ScopeError, match=r"target #1 \(host 'example.com'\): authorized_by"):
        parse_scope(_one(authorized_by=value))


@pytest.mark.parametrize(
    "host",
    [
        '"https://example.com"',
        '"example.com/path"',
        '"example.com:8443"',
        '"*.example.com"',
        '"-bad.com"',
        '"exa mple.com"',
        '""',
        "42",
    ],
)
def test_malformed_host(host: str) -> None:
    with pytest.raises(ScopeError, match="target #1"):
        parse_scope(_one(host=host))


def test_ip_hosts_ok() -> None:
    text = _one(host='"127.0.0.1"') + _one(host='"::1"')
    assert [e.host for e in parse_scope(text).entries] == ["127.0.0.1", "::1"]


def test_bad_date() -> None:
    with pytest.raises(ScopeError, match="date must be YYYY-MM-DD"):
        parse_scope(_one(date='"20 Oct"'))


def test_error_names_second_entry() -> None:
    text = _one() + _one(host='"other.com"', authorized_by='""')
    with pytest.raises(ScopeError, match=r"target #2 \(host 'other.com'\)"):
        parse_scope(text)


def test_duplicate_and_unknown_keys() -> None:
    with pytest.raises(ScopeError, match="duplicate host"):
        parse_scope(_one() + _one(host='"EXAMPLE.com"'))
    with pytest.raises(ScopeError, match="unknown key"):
        parse_scope(_one(allow_actve="true"))


def test_invalid_toml_and_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ScopeError, match="invalid TOML"):
        parse_scope("[[target]\nhost=")
    with pytest.raises(ScopeError, match="not found"):
        load_scope(tmp_path / "nope.toml")


def test_target_lookup() -> None:
    scope = parse_scope(VALID)
    t = scope.target("https://EXAMPLE.com/login")
    assert t.authorized_by == "self (own domain)" and t.allow_active and t.mode == "scan"
    assert scope.entry_for("sub.example.com") is None  # subdomains not implied
    with pytest.raises(ScopeError, match="no scope.toml entry"):
        scope.target("https://evil.com/")


def test_example_file_is_valid() -> None:
    load_scope(Path(__file__).parent.parent / "scope.example.toml")
