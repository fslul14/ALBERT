"""Load and validate scope.toml: who authorized scanning which host. No network I/O."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from albert.core.models import ScanMode, Target
from albert.core.scope import normalize_host

DEFAULT_SCOPE_PATH = Path("scope.toml")

_KEYS = {"host", "authorized_by", "date", "allow_active"}


class ScopeError(Exception):
    """scope.toml is missing, malformed, or doesn't cover the requested host."""


@dataclass(frozen=True)
class ScopeEntry:
    """One authorized host."""

    host: str
    authorized_by: str
    date: date
    allow_active: bool = False


def _parse_date(value: Any) -> date:
    if isinstance(value, date):  # TOML native date (unquoted)
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise ValueError(f"date must be YYYY-MM-DD, got {value!r}")


def _parse_entry(raw: Any) -> ScopeEntry:
    if not isinstance(raw, dict):
        raise ValueError("must be a table")
    unknown = set(raw) - _KEYS
    if unknown:
        raise ValueError(f"unknown key(s): {', '.join(sorted(unknown))}")
    host = raw.get("host")
    if not isinstance(host, str):
        raise ValueError("host is missing")
    host = normalize_host(host)
    auth = raw.get("authorized_by")
    if not isinstance(auth, str) or not auth.strip():
        raise ValueError("authorized_by is missing or blank")
    if "date" not in raw:
        raise ValueError("date is missing")
    allow_active = raw.get("allow_active", False)
    if not isinstance(allow_active, bool):
        raise ValueError(f"allow_active must be true or false, got {allow_active!r}")
    return ScopeEntry(host, auth.strip(), _parse_date(raw["date"]), allow_active)


class Scope:
    """Validated set of authorized hosts."""

    def __init__(self, entries: list[ScopeEntry]) -> None:
        self._entries = {e.host: e for e in entries}

    @property
    def entries(self) -> list[ScopeEntry]:
        """All entries, in file order."""
        return list(self._entries.values())

    def entry_for(self, host: str) -> ScopeEntry | None:
        """Exact-host lookup (subdomains are not implied)."""
        try:
            return self._entries.get(normalize_host(host))
        except ValueError:
            return None

    def target(self, url: str, mode: ScanMode = "scan") -> Target:
        """Build the Target for ``url``; raise ScopeError if its host has no entry."""
        host = urlsplit(url).hostname or ""
        entry = self.entry_for(host)
        if entry is None:
            raise ScopeError(
                f"{host or url!r} has no scope.toml entry; add one naming who authorized it"
            )
        return Target(
            url,
            mode,
            authorized_by=entry.authorized_by,
            scope_date=entry.date.isoformat(),
            allow_active=entry.allow_active,
        )


def parse_scope(text: str, source: str = "scope.toml") -> Scope:
    """Parse scope TOML text; raise ScopeError naming the bad entry."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ScopeError(f"{source}: invalid TOML: {e}") from None
    raw_entries = data.get("target", [])
    if not isinstance(raw_entries, list):
        raise ScopeError(f"{source}: use [[target]] tables, not [target]")
    entries: list[ScopeEntry] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_entries, start=1):
        label = f"target #{i}"
        if isinstance(raw, dict) and isinstance(raw.get("host"), str):
            label += f" (host {raw['host']!r})"
        try:
            entry = _parse_entry(raw)
        except ValueError as e:
            raise ScopeError(f"{source}: {label}: {e}") from None
        if entry.host in seen:
            raise ScopeError(f"{source}: {label}: duplicate host")
        seen.add(entry.host)
        entries.append(entry)
    return Scope(entries)


def load_scope(path: Path = DEFAULT_SCOPE_PATH) -> Scope:
    """Read and validate a scope file; raise ScopeError on any problem."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ScopeError(f"{path}: not found (copy scope.example.toml to start)") from None
    except OSError as e:
        raise ScopeError(f"{path}: cannot read: {e.strerror}") from None
    return parse_scope(text, str(path))
