"""Shared vocabulary between collectors, checks, and the report writer. No I/O."""

from __future__ import annotations

from collections.abc import Hashable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, Literal, Self, TypeVar
from urllib.parse import urlsplit

from albert import __version__
from albert.core.secrets import redact

_H = TypeVar("_H", bound=Hashable)

ScanMode = Literal["quick", "scan", "active"]


class _Level(IntEnum):
    """Ordered level with a lowercase label for reports."""

    @property
    def label(self) -> str:
        """Lowercase name, as written to reports."""
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> Self:
        """Parse a label written by ``label`` (case-insensitive)."""
        return cls[label.upper()]


class Severity(_Level):
    """How bad a finding is. Most passive findings are LOW–MEDIUM."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Confidence(_Level):
    """How sure the check is that the finding is real."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2


@dataclass(frozen=True)
class Evidence:
    """One observation backing a finding. Redacted at construction: raw secrets are never stored."""

    kind: str  # "header", "cookie", "body", "cert", "dns", "script", ...
    value: str
    location: str = ""  # URL, header name, record name, ...

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", redact(self.value))
        object.__setattr__(self, "location", redact(self.location))

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form."""
        return {"kind": self.kind, "value": self.value, "location": self.location}


@dataclass(frozen=True)
class Finding:
    """A single issue reported by a check."""

    id: str  # stable check id, e.g. "HDR-CSP-MISSING"
    title: str
    severity: Severity
    confidence: Confidence
    urls: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    impact: str = ""
    remediation: str = ""
    refs: tuple[str, ...] = ()  # "CWE-693", "OWASP A05:2021", "CVE-...", URLs

    def __post_init__(self) -> None:
        # Accept lists from callers but store tuples so findings stay hashable.
        for name in ("urls", "evidence", "refs"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    @property
    def sort_key(self) -> tuple[int, int, str]:
        """Severity desc, then confidence desc, then id."""
        return (-self.severity, -self.confidence, self.id)

    @property
    def group_key(self) -> tuple[str, str, Severity, Confidence]:
        """Findings with the same key are the same issue seen on different pages."""
        return (self.id, self.title, self.severity, self.confidence)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "urls": list(self.urls),
            "evidence": [e.to_dict() for e in self.evidence],
            "impact": self.impact,
            "remediation": self.remediation,
            "refs": list(self.refs),
        }


def _merge(*parts: Iterable[_H]) -> tuple[_H, ...]:
    """Concatenate, dropping duplicates, preserving first-seen order."""
    return tuple(dict.fromkeys(x for part in parts for x in part))


def group_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge the same finding across pages into one with combined URLs/evidence, then sort."""
    groups: dict[tuple[str, str, Severity, Confidence], Finding] = {}
    for f in findings:
        prev = groups.get(f.group_key)
        if prev is None:
            groups[f.group_key] = replace(
                f, urls=_merge(f.urls), evidence=_merge(f.evidence), refs=_merge(f.refs)
            )
        else:
            groups[f.group_key] = replace(
                prev,
                urls=_merge(prev.urls, f.urls),
                evidence=_merge(prev.evidence, f.evidence),
                refs=_merge(prev.refs, f.refs),
            )
    return sorted(groups.values(), key=lambda f: f.sort_key)


@dataclass(frozen=True)
class CollectedResponse:
    """One HTTP response as collected; what header checks consume. Never reported directly."""

    url: str
    status: int
    headers: tuple[tuple[str, str], ...] = ()  # received order, duplicates kept
    http_version: str = "HTTP/1.1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", tuple((str(k), str(v)) for k, v in self.headers))

    def header_all(self, name: str) -> list[str]:
        """Every value of header ``name`` (case-insensitive), in order."""
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def header(self, name: str) -> str | None:
        """First value of header ``name``, or None."""
        values = self.header_all(name)
        return values[0] if values else None

    @property
    def content_type(self) -> str:
        """Lowercased MIME type without parameters ("" if absent)."""
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def is_document(self) -> bool:
        """A successful HTML page (where document-level headers like CSP matter)."""
        return 200 <= self.status < 300 and self.content_type in {
            "text/html",
            "application/xhtml+xml",
        }

    @property
    def is_https(self) -> bool:
        """Served over HTTPS."""
        return urlsplit(self.url).scheme == "https"


@dataclass(frozen=True)
class Target:
    """What is being scanned, and under whose authorization."""

    url: str
    mode: ScanMode
    authorized_by: str | None = None  # from scope.toml; None for `quick`
    scope_date: str | None = None
    allow_active: bool = False

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"target must be an http(s) URL with a host: {self.url!r}")

    @property
    def host(self) -> str:
        """Lowercased hostname of the target URL."""
        return urlsplit(self.url).hostname or ""

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form."""
        return {
            "url": self.url,
            "host": self.host,
            "mode": self.mode,
            "authorized_by": self.authorized_by,
            "scope_date": self.scope_date,
            "allow_active": self.allow_active,
        }


@dataclass
class ScanResult:
    """Everything one run produced. Mutable: collectors and the engine fill it in."""

    target: Target
    tool_version: str = __version__
    rules_version: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)  # crawled
    skipped: list[str] = field(default_factory=list)  # out of scope / robots / caps
    blocked: list[str] = field(default_factory=list)  # WAF / CAPTCHA / rate-limited
    tech: dict[str, str] = field(default_factory=dict)  # name -> version ("" if unknown)
    errors: list[str] = field(default_factory=list)

    def finish(self) -> None:
        """Stamp the end time."""
        self.finished_at = datetime.now(UTC)

    def grouped_findings(self) -> list[Finding]:
        """Findings merged across pages and sorted, as reports show them."""
        return group_findings(self.findings)

    def severity_counts(self) -> dict[str, int]:
        """Grouped-finding count per severity, highest first, zeros included."""
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.grouped_findings():
            counts[f.severity.label] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form; findings are grouped to mirror the Markdown report."""
        return {
            "target": self.target.to_dict(),
            "tool_version": self.tool_version,
            "rules_version": self.rules_version,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.grouped_findings()],
            "checks_run": list(self.checks_run),
            "pages": list(self.pages),
            "skipped": list(self.skipped),
            "blocked": list(self.blocked),
            "tech": dict(self.tech),
            "errors": list(self.errors),
        }
