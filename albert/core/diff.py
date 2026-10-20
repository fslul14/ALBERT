"""Scan diffing: compare a prior report's JSON with the current report data. Pure.

Findings match by stable id; where one id legitimately covers several findings (e.g.
HDR-CDN-WAF per provider), the title disambiguates. Categories:
new / resolved / changed (severity, confidence, title or affected-URL set differs) / unchanged /
not_rechecked (the finding's check family didn't run this time, so "resolved" would be a lie).
A prior from another host, report schema, or mode is refused, never diffed.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from albert.core.models import REPORT_SCHEMA_VERSION as SCHEMA_VERSION

# Finding-id prefix -> the check family (checks_run name) that produces it.
FAMILY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("SEC-TXT-", "security_txt"),
    ("HDR-", "headers"),
    ("COOKIE-", "cookies"),
    ("CORS-", "cors"),
    ("DISC-", "disclosure"),
    ("TLS-", "tls"),
    ("RND-", "rendered"),
    ("JS-", "js"),
    ("VULN-", "cve"),
    ("CVE-LOOKUP-", "cve"),
    ("PRIV-", "privacy"),
    ("DNS-", "dns_email"),
    ("INTEL-", "intel"),
)


class DiffError(Exception):
    """The prior report can't be meaningfully compared with this scan."""


def family_of(finding_id: str) -> str | None:
    return next((fam for prefix, fam in FAMILY_PREFIXES if finding_id.startswith(prefix)), None)


def load_prior(path: Path, host: str, mode: str) -> dict[str, Any]:
    """Read and validate a prior report JSON for this host and mode; raise DiffError if not."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise DiffError(f"{path}: not a readable Albert JSON report ({e})") from None
    if not isinstance(data, dict) or "target" not in data or "findings" not in data:
        raise DiffError(f"{path}: not an Albert JSON report")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise DiffError(
            f"{path}: report schema {data.get('schema_version')!r} is incompatible with "
            f"this version (schema {SCHEMA_VERSION}); re-run the prior scan to compare"
        )
    prior_host = str(data["target"].get("host", "")).lower()
    if prior_host != host.lower():
        raise DiffError(f"{path}: prior report is for {prior_host!r}, not {host!r}")
    if data["target"].get("mode") != mode:
        raise DiffError(
            f"{path}: prior report is a {data['target'].get('mode')!r} run, not {mode!r}"
        )
    return data


def _all(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [*report.get("findings", []), *report.get("posture_notes", [])]


def _keyed(
    findings: list[dict[str, Any]], ambiguous: set[str]
) -> dict[tuple[str, str], dict[str, Any]]:
    return {(f["id"], f["title"] if f["id"] in ambiguous else ""): f for f in findings}


def _brief(f: dict[str, Any]) -> dict[str, Any]:
    return {"id": f["id"], "title": f["title"], "severity": f["severity"]}


def diff_reports(prior: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Categorise every finding of either report. Both are report-JSON dicts."""
    before, after = _all(prior), _all(current)
    ambiguous = {
        i
        for report in (before, after)
        for i, n in Counter(f["id"] for f in report).items()
        if n > 1
    }
    old, new = _keyed(before, ambiguous), _keyed(after, ambiguous)
    ran = set(current.get("checks_run", []))
    out: dict[str, list[dict[str, Any]]] = {
        "new": [],
        "resolved": [],
        "changed": [],
        "unchanged": [],
        "not_rechecked": [],
    }
    for key, f in new.items():
        if key not in old:
            out["new"].append(_brief(f))
            continue
        p = old[key]
        change: dict[str, Any] = {}
        for field in ("severity", "confidence", "title"):
            if p[field] != f[field]:
                change[field] = [p[field], f[field]]
        added = sorted(set(f["urls"]) - set(p["urls"]))
        removed = sorted(set(p["urls"]) - set(f["urls"]))
        if added:
            change["urls_added"] = added
        if removed:
            change["urls_removed"] = removed
        if change:
            out["changed"].append({**_brief(f), **change})
        else:
            out["unchanged"].append(_brief(f))
    for key, p in old.items():
        if key in new:
            continue
        family = family_of(p["id"])
        bucket = "resolved" if family is None or family in ran else "not_rechecked"
        out[bucket].append(
            {**_brief(p), **({"family": family} if bucket == "not_rechecked" else {})}
        )
    return {
        "prior": {
            "generated_at": prior.get("generated_at"),
            "started_at": prior.get("started_at"),
            "tool_version": (prior.get("tool") or {}).get("version"),
        },
        "counts": {k: len(v) for k, v in out.items()},
        **{k: sorted(v, key=lambda x: (x["id"], x["title"])) for k, v in out.items()},
    }
