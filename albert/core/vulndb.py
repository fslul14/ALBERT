"""Vulnerability data for detected technologies: local cache first, network only if asked.

Modes: ``off`` (no lookup), ``cache`` (default: cached data only, fully local), ``online``
(OSV.dev for npm packages, NVD for CPE products, via IntelClient; results cached).
Lookup never raises: failures become ``status="unavailable"`` with a reason.

OSV is queried per (package, version) and returns only affecting advisories. NVD is queried
per vendor:product and the CVE list (with version ranges) is cached; ranges are evaluated by
the pure matcher in ``checks/cve.py``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from albert.core.intel import IntelClient, IntelError, IntelPolicy
from albert.core.models import TechDetection
from albert.core.scope import OutOfScopeError

CveMode = Literal["off", "cache", "online"]
OSV_QUERY = "https://api.osv.dev/v1/query"
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FRESH_FOR = timedelta(days=7)
SCHEMA = 1
_LABEL = {"osv": "OSV.dev", "nvd": "NVD"}


@dataclass(frozen=True)
class Lookup:
    """Vulnerability data (or why there is none) for one versioned detection."""

    detection: TechDetection
    source: str  # "osv" | "nvd" | ""
    status: str  # "ok" | "unavailable"
    reason: str = ""
    advisories: tuple[dict[str, Any], ...] = ()  # OSV: affecting; NVD: product CVEs + ranges
    fetched_at: str | None = None


@dataclass
class LookupReport:
    """All lookups plus run-level notes for the report."""

    lookups: list[Lookup] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def default_cache_dir(out_dir: Path) -> Path:
    """Inside the (gitignored) reports directory."""
    return out_dir / ".cache" / "vulndb"


# --- cache --------------------------------------------------------------------------------


def _cache_path(cache_dir: Path, source: str, key: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._@-]", "_", key)[:80]
    digest = hashlib.sha256(key.encode()).hexdigest()[:10]
    return cache_dir / source / f"{safe}-{digest}.json"


def _read_cache(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA else None


def _write_cache(path: Path, advisories: list[dict[str, Any]]) -> str:
    stamp = datetime.now(UTC).isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"schema": SCHEMA, "fetched_at": stamp, "advisories": advisories}),
        encoding="utf-8",
    )
    tmp.replace(path)
    return stamp


def _is_fresh(entry: dict[str, Any]) -> bool:
    try:
        return datetime.now(UTC) - datetime.fromisoformat(entry["fetched_at"]) < FRESH_FOR
    except (KeyError, ValueError):
        return False


# --- parsing (network JSON -> compact cached form) ----------------------------------------


def parse_osv(vuln: dict[str, Any]) -> dict[str, Any]:
    """Compact form of one OSV advisory."""
    fixed = [
        e["fixed"]
        for a in vuln.get("affected", [])
        for r in a.get("ranges", [])
        for e in r.get("events", [])
        if "fixed" in e
    ]
    vectors = [s.get("score", "") for s in vuln.get("severity", []) if s.get("type") == "CVSS_V3"]
    db = vuln.get("database_specific", {}) or {}
    return {
        "id": vuln.get("id", ""),
        "aliases": list(vuln.get("aliases", [])),
        "summary": vuln.get("summary") or (vuln.get("details") or "")[:300],
        "cvss_vector": vectors[0] if vectors else None,
        "severity_label": (db.get("severity") or None),
        "cwes": list(db.get("cwe_ids", []) or []),
        "fixed": list(dict.fromkeys(fixed)),
        "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
    }


def parse_nvd(item: dict[str, Any], vendor: str, product: str) -> dict[str, Any] | None:
    """Compact form of one NVD CVE, keeping only this vendor:product's match criteria."""
    cve = item.get("cve", {})
    prefix = f"cpe:2.3:a:{vendor}:{product}:"
    matches = []
    for config in cve.get("configurations", []):
        multi_node = config.get("operator") == "AND" or len(config.get("nodes", [])) > 1
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable") and m.get("criteria", "").startswith(prefix):
                    matches.append(
                        {
                            "criteria": m["criteria"],
                            **{
                                k: m[k]
                                for k in (
                                    "versionStartIncluding",
                                    "versionStartExcluding",
                                    "versionEndIncluding",
                                    "versionEndExcluding",
                                )
                                if k in m
                            },
                            "needs_platform": multi_node,
                        }
                    )
    if not matches:
        return None
    metrics = cve.get("metrics", {})
    score = label = vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score, vector = data.get("baseScore"), data.get("vectorString")
            label = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = [
        d["value"]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    ]
    return {
        "id": cve.get("id", ""),
        "aliases": [],
        "summary": desc[:300],
        "cvss_score": score,
        "cvss_vector": vector,
        "severity_label": label,
        "cwes": list(dict.fromkeys(cwes)),
        "matches": matches,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
    }


# --- fetching -----------------------------------------------------------------------------


async def _fetch_osv(client: IntelClient, name: str, version: str) -> list[dict[str, Any]]:
    payload: dict[str, Any] = {"package": {"ecosystem": "npm", "name": name}, "version": version}
    out: list[dict[str, Any]] = []
    for _ in range(10):  # page cap
        data = await client.post_json(OSV_QUERY, payload)
        out += [parse_osv(v) for v in data.get("vulns", [])]
        if not (token := data.get("next_page_token")):
            break
        payload["page_token"] = token
    return out


async def _fetch_nvd(client: IntelClient, vendor: str, product: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    start, total = 0, 1
    while start < total and start < 10_000:
        data = await client.get_json(
            NVD_CVES,
            {
                "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
                "resultsPerPage": 2000,
                "startIndex": start,
            },
        )
        items = data.get("vulnerabilities", [])
        out += [p for i in items if (p := parse_nvd(i, vendor, product))]
        total = int(data.get("totalResults", 0))
        start += len(items) or total
    return out


def _source_for(d: TechDetection) -> tuple[str, str] | None:
    if d.npm:
        return "osv", f"npm/{d.npm}@{d.version}"
    if d.cpe and ":" in d.cpe:
        return "nvd", d.cpe  # product-level list; version evaluated locally
    return None


async def lookup_all(
    detections: list[TechDetection],
    mode: CveMode,
    cache_dir: Path,
    *,
    target_hosts: tuple[str, ...] = (),
    client: IntelClient | None = None,
) -> LookupReport:
    """Vulnerability data for every versioned detection that has an identifier."""
    report = LookupReport()
    eligible = [d for d in detections if d.version and _source_for(d)]
    skipped = sum(1 for d in detections if d.version and not _source_for(d))
    if skipped:
        report.notes.append(f"{skipped} versioned technolog(ies) have no CVE identifier yet")
    if mode == "off" or not eligible:
        if mode == "off":
            report.notes.append("CVE matching disabled (--cve off)")
        return report
    owned = client is None and mode == "online"
    if owned:
        client = IntelClient(IntelPolicy(target_hosts))
    memo: dict[tuple[str, str], Lookup] = {}
    try:
        for d in eligible:
            source, key = _source_for(d)  # type: ignore[misc]
            if (source, key) not in memo:
                memo[(source, key)] = await _lookup_one(d, source, key, mode, cache_dir, client)
            prior = memo[(source, key)]
            report.lookups.append(
                Lookup(
                    d, prior.source, prior.status, prior.reason, prior.advisories, prior.fetched_at
                )
            )
    finally:
        if owned and client is not None:
            await client.aclose()
    used = sorted({_LABEL[lk.source] for lk in report.lookups if lk.status == "ok"})
    if mode == "cache":
        where = "local cache only (no network)"
    else:
        where = (
            "online: OSV.dev / NVD, sent package/product names + versions only, never the target"
        )
    report.notes.append(f"CVE lookup: {where}; data used from: {', '.join(used) or 'none'}")
    return report


async def _lookup_one(
    d: TechDetection,
    source: str,
    key: str,
    mode: CveMode,
    cache_dir: Path,
    client: IntelClient | None,
) -> Lookup:
    path = _cache_path(cache_dir, source, key)
    cached = _read_cache(path)
    if cached and (mode == "cache" or _is_fresh(cached)):
        return Lookup(d, source, "ok", "", tuple(cached["advisories"]), cached["fetched_at"])
    if mode == "cache" or client is None:
        return Lookup(d, source, "unavailable", "no cached data (run with --cve online to fetch)")
    try:
        if source == "osv":
            advisories = await _fetch_osv(client, d.npm or "", d.version or "")
        else:
            vendor, product = (d.cpe or "").split(":", 1)
            advisories = await _fetch_nvd(client, vendor, product)
    except (IntelError, OutOfScopeError) as e:
        if cached:  # stale beats nothing
            return Lookup(
                d,
                source,
                "ok",
                f"stale cache used ({e})",
                tuple(cached["advisories"]),
                cached["fetched_at"],
            )
        return Lookup(d, source, "unavailable", str(e))
    stamp = _write_cache(path, advisories)
    return Lookup(d, source, "ok", "", tuple(advisories), stamp)
