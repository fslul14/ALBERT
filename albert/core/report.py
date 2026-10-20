"""Markdown + JSON report writer.

Both formats come from one sanitized dict: every string is swept with ``secrets.redact``
(the redaction backstop, independent of any check-side redaction), and the Markdown is
swept again after rendering. Untrusted values are rendered inside code spans.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from albert.core.models import Finding, ScanResult, Severity
from albert.core.secrets import redact

SCHEMA_VERSION = 1
MAX_MD_URLS = 10
_WEIGHTS = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 2}
_GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))


def _sweep(obj: Any) -> Any:
    """Redaction backstop: redact every string (keys included) in a JSON-ready structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {_sweep(k): _sweep(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_sweep(v) for v in obj]
    return obj


def posture(findings: Sequence[Finding]) -> dict[str, Any]:
    """Provisional 0-100 score and letter grade from grouped non-info findings (refined later)."""
    score = max(0, 100 - sum(_WEIGHTS.get(f.severity, 0) for f in findings))
    grade = next(g for floor, g in _GRADES if score >= floor)
    return {"score": score, "grade": grade}


def build_report_data(result: ScanResult) -> dict[str, Any]:
    """The single source for both formats; already redacted."""
    grouped = result.grouped_findings()
    full = [f for f in grouped if f.severity > Severity.INFO]
    info = [f for f in grouped if f.severity == Severity.INFO]
    finished = result.finished_at
    duration = (finished - result.started_at).total_seconds() if finished else None
    data = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "tool": {"name": "albert", "version": result.tool_version, "rules": result.rules_version},
        "target": result.target.to_dict(),
        "started_at": result.started_at.isoformat(),
        "finished_at": finished.isoformat() if finished else None,
        "duration_seconds": duration,
        "pages_scanned": len(result.pages),
        "checks_run": list(result.checks_run),
        "summary": {
            "severity_counts": result.severity_counts(),
            "posture": posture(full),
            "top_issues": [
                {"id": f.id, "title": f.title, "severity": f.severity.label} for f in full[:5]
            ],
        },
        "findings": [f.to_dict() for f in full],
        "posture_notes": [f.to_dict() for f in info],
        "appendix": {
            "pages": list(result.pages),
            "skipped": list(result.skipped),
            "blocked": list(result.blocked),
            "tech": [t.to_dict() for t in result.tech],
            "errors": list(result.errors),
        },
        "notes": list(result.notes),
    }
    return _sweep(data)  # type: ignore[no-any-return]


# --- Markdown -----------------------------------------------------------------------------


def _code(value: Any) -> str:
    """Inline code span that survives backticks and newlines in untrusted text."""
    s = re.sub(r"[\r\n\t]+", " ", str(value))
    if not s:
        return "*(empty)*"
    fence = "`" * (max((len(m) for m in re.findall(r"`+", s)), default=0) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _cell(value: Any) -> str:
    """Table cell: code span with pipes escaped (GFM requires this even inside code)."""
    return _code(value).replace("|", "\\|")


def _text(value: Any) -> str:
    """Plain prose from our own catalog; escape the characters that could restructure output."""
    s = re.sub(r"[\r\n]+", " ", str(value)).replace("<", "&lt;")
    return re.sub(r"([\\`*_\[\]|#])", r"\\\1", s)


def _clip(value: str, limit: int = 120) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


def _md_header(d: dict[str, Any]) -> list[str]:
    t = d["target"]
    scope = (
        f"{_text(t['authorized_by'])} ({_text(t['scope_date'])})"
        if t["authorized_by"]
        else "none (quick mode: single page, public-equivalent)"
    )
    duration = f"{d['duration_seconds']:.1f} s" if d["duration_seconds"] is not None else "n/a"
    rows = [
        ("Target", _cell(t["url"])),
        ("Mode", t["mode"]),
        ("Scope entry", scope),
        ("Started", d["started_at"]),
        ("Finished", d["finished_at"] or "n/a"),
        ("Duration", duration),
        ("Tool", f"albert {d['tool']['version']} (rules: {d['tool']['rules'] or 'n/a'})"),
        ("Pages scanned", str(d["pages_scanned"])),
        ("Checks run", ", ".join(d["checks_run"]) or "none"),
    ]
    lines = ["## Header", "", "| | |", "|---|---|", *(f"| {k} | {v} |" for k, v in rows), ""]
    if d["notes"]:
        lines += ["**Notes:**", "", *(f"- {_code(n)}" for n in d["notes"]), ""]
    return lines


def _md_summary(d: dict[str, Any]) -> list[str]:
    s = d["summary"]
    lines = [
        "## Executive summary",
        "",
        f"**Posture grade: {s['posture']['grade']}** "
        f"(score {s['posture']['score']}/100, provisional rubric)",
        "",
        "| Severity | Count |",
        "|---|---|",
        *(f"| {sev.capitalize()} | {n} |" for sev, n in s["severity_counts"].items()),
        "",
    ]
    if s["top_issues"]:
        lines += ["**Top issues:**", ""]
        lines += [
            f"{i}. **{t['severity'].capitalize()}**: {_text(t['title'])} ({_code(t['id'])})"
            for i, t in enumerate(s["top_issues"], 1)
        ]
    else:
        lines.append("No Low-or-higher issues found.")
    return [*lines, ""]


def _md_finding(n: int, f: dict[str, Any]) -> list[str]:
    urls = f["urls"]
    lines = [
        f"### {n}. [{f['severity'].upper()}] {_text(f['title'])}",
        "",
        f"- **ID:** {_code(f['id'])} · **Severity:** {f['severity'].capitalize()} · "
        f"**Confidence:** {f['confidence'].capitalize()}",
        f"- **URLs ({len(urls)}):**",
        *(f"  - {_code(u)}" for u in urls[:MAX_MD_URLS]),
    ]
    if len(urls) > MAX_MD_URLS:
        lines.append(f"  - ...and {len(urls) - MAX_MD_URLS} more (see JSON)")
    if f["evidence"]:
        lines.append("- **Evidence:**")
        lines += [
            f"  - {_code(e['location']) + ': ' if e['location'] else ''}{_code(e['value'])}"
            for e in f["evidence"]
        ]
    lines += [
        f"- **Impact:** {_text(f['impact'])}",
        f"- **Remediation:** {_text(f['remediation'])}",
    ]
    if f["refs"]:
        lines.append(f"- **References:** {', '.join(_text(r) for r in f['refs'])}")
    return [*lines, ""]


def _md_findings(d: dict[str, Any]) -> list[str]:
    lines = ["## Findings", ""]
    if not d["findings"]:
        return [*lines, "No Low-or-higher findings.", ""]
    for i, f in enumerate(d["findings"], 1):
        lines += _md_finding(i, f)
    return lines


def _md_posture_notes(d: dict[str, Any]) -> list[str]:
    notes = d["posture_notes"]
    if not notes:
        return []
    lines = [
        "## Posture notes (Info)",
        "",
        "| ID | Note | Pages | Detail |",
        "|---|---|---|---|",
    ]
    for f in notes:
        detail = "; ".join(
            (f"{e['location']}: " if e["location"] else "") + e["value"] for e in f["evidence"]
        )
        lines.append(
            f"| {_cell(f['id'])} | {_text(f['title'])} | {len(f['urls'])} | "
            f"{_cell(_clip(detail)) if detail else ''} |"
        )
    return [*lines, ""]


def _md_list(title: str, items: Sequence[str]) -> list[str]:
    body = [f"- {_code(i)}" for i in items] or ["- *(none)*"]
    return [f"### {title}", "", *body, ""]


def _md_tech(tech: list[dict[str, Any]]) -> list[str]:
    if not tech:
        return ["### Technology detected", "", "- *(none)*", ""]
    lines = [
        "### Technology detected",
        "",
        "| Technology | Version | Category | Confidence | Evidence |",
        "|---|---|---|---|---|",
    ]
    for t in tech:
        evidence = _clip("; ".join(t["evidence"]))
        lines.append(
            f"| {_text(t['name'])} | {_cell(t['version']) if t['version'] else '-'} | "
            f"{_text(t['category'])} | {t['confidence']} | {_cell(evidence)} |"
        )
    return [*lines, ""]


def _md_appendix(d: dict[str, Any]) -> list[str]:
    a = d["appendix"]
    return [
        "## Appendix",
        "",
        *_md_list("Pages scanned", a["pages"]),
        *_md_list("Skipped / not followed", a["skipped"]),
        *_md_list("Blocked", a["blocked"]),
        *_md_tech(a["tech"]),
        *_md_list("Errors", a["errors"]),
    ]


def render_markdown(data: dict[str, Any]) -> str:
    """Render report data (from ``build_report_data``) as Markdown."""
    lines = [
        f"# Albert report: {_text(data['target']['host'])}",
        "",
        *_md_header(data),
        *_md_summary(data),
        *_md_findings(data),
        *_md_posture_notes(data),
        *_md_appendix(data),
    ]
    return redact("\n".join(lines).rstrip() + "\n")  # second sweep over the rendered text


# --- Files --------------------------------------------------------------------------------


def report_stem(result: ScanResult) -> str:
    """<host>_<YYYY-MM-DD_HHMM> in local time; host made filename-safe (IPv6, Windows)."""
    host = re.sub(r"[^a-z0-9.-]", "_", result.target.host.lower())
    return f"{host}_{result.started_at.astimezone():%Y-%m-%d_%H%M}"


def write_report(
    result: ScanResult, out_dir: Path = Path("reports"), formats: Sequence[str] = ("md", "json")
) -> list[Path]:
    """Write the report files; never overwrites (adds _2, _3... on a same-minute rerun)."""
    unknown = set(formats) - {"md", "json"}
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(sorted(unknown))}")
    data = build_report_data(result)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem, n = report_stem(result), 1
    while any((out_dir / f"{stem}{'' if n == 1 else f'_{n}'}.{fmt}").exists() for fmt in formats):
        n += 1
    stem = stem if n == 1 else f"{stem}_{n}"
    paths = []
    for fmt in formats:
        path = out_dir / f"{stem}.{fmt}"
        text = render_markdown(data) if fmt == "md" else json.dumps(data, indent=2) + "\n"
        path.write_text(text, encoding="utf-8", newline="\n")
        paths.append(path)
    return paths
