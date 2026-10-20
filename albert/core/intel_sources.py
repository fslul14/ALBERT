"""External-intelligence collection (scan --full). Third-party services only, never the target.

Sources: crt.sh (Certificate Transparency), Wayback Machine CDX, Google Safe Browsing v4
(only with ALBERT_SAFE_BROWSING_KEY), and DNS blocklists (Spamhaus DBL / SURBL for the
domain, Spamhaus ZEN for in-domain MX IPs). Every HTTP request goes through IntelClient
(IntelPolicy) and every blocklist query through IntelDns (IntelDnsPolicy). The target's
domain is sent only as the query subject (crt.sh ``q``, Wayback ``url``, Safe Browsing
``threatEntries``, DNSBL names). Results are cached; nothing here ever raises: failures become
``unavailable`` entries. Surfaced hosts are reported, never contacted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from albert import __version__
from albert.core.intel import IntelClient, IntelDns, IntelError, IntelPolicy
from albert.core.scope import OutOfScopeError

CRT_SH = "https://crt.sh/"
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
SAFE_BROWSING = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SAFE_BROWSING_KEY_ENV = "ALBERT_SAFE_BROWSING_KEY"
FRESH_FOR = timedelta(days=1)
SCHEMA = 1
MAX_SUBDOMAINS = 500
MAX_WAYBACK = 500


@dataclass(frozen=True)
class SourceResult:
    """One intel source's outcome."""

    source: str  # "crt.sh" | "wayback" | "safe_browsing" | "blocklists"
    status: str  # "ok" | "unavailable" | "skipped"
    data: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass
class IntelReport:
    domain: str
    results: list[SourceResult] = field(default_factory=list)


# --- cache --------------------------------------------------------------------------------


def _cache_path(cache_dir: Path, source: str, key: str) -> Path:
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    return cache_dir / source / f"{re.sub(r'[^a-z0-9.-]', '_', key.lower())[:60]}-{digest}.json"


def _cached(path: Path) -> dict[str, Any] | None:
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        fresh = datetime.now(UTC) - datetime.fromisoformat(entry["fetched_at"]) < FRESH_FOR
    except (OSError, ValueError, KeyError):
        return None
    return entry["data"] if entry.get("schema") == SCHEMA and fresh else None


def _store(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema": SCHEMA, "fetched_at": datetime.now(UTC).isoformat(), "data": data}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    tmp.replace(path)


# --- sources ------------------------------------------------------------------------------


async def _crt_sh(client: IntelClient, domain: str) -> dict[str, Any]:
    rows = await client.get_json(CRT_SH, {"q": f"%.{domain}", "output": "json"})
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            n = name.strip().lower().lstrip("*.").rstrip(".")
            if n.endswith("." + domain) and re.fullmatch(r"[a-z0-9._-]+", n):
                names.add(n)
    return {"subdomains": sorted(names)[:MAX_SUBDOMAINS], "total": len(names)}


async def _wayback(client: IntelClient, domain: str) -> dict[str, Any]:
    rows = await client.get_json(
        WAYBACK_CDX,
        {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode",
            "collapse": "urlkey",
            "limit": str(MAX_WAYBACK),
            # Live check: unfiltered results for busy domains are mostly 404s and revisit
            # records ("-"); only URLs that once served content are worth reporting.
            "filter": "statuscode:200",
        },
    )
    if not isinstance(rows, list) or not rows:
        return {"urls": []}
    header, *body = rows
    idx = {k: i for i, k in enumerate(header)}
    urls = [
        {
            "url": r[idx["original"]],
            "timestamp": r[idx["timestamp"]],
            "status": r[idx["statuscode"]],
        }
        for r in body
        if len(r) == len(header)
    ]
    return {"urls": urls}


async def _safe_browsing(client: IntelClient, key: str, urls: list[str]) -> dict[str, Any]:
    body = {
        "client": {"clientId": "albert", "clientVersion": __version__},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        data = await client.post_json(f"{SAFE_BROWSING}?key={key}", body)
    except IntelError as e:  # never let the API key reach a message or report
        raise IntelError(str(e).replace(key, "<key>")) from None
    return {
        "matches": [
            {
                "url": m.get("threat", {}).get("url", ""),
                "threat": m.get("threatType", ""),
                "platform": m.get("platformType", ""),
            }
            for m in data.get("matches", [])
        ]
    }


# Return codes that mean "listed"; 127.255.255.x means the query itself was refused.
_DBL = {
    "127.0.1.2": "spam",
    "127.0.1.4": "phishing",
    "127.0.1.5": "malware",
    "127.0.1.6": "botnet C&C",
    "127.0.1.102": "abused legit (spam)",
    "127.0.1.103": "abused legit (redirector)",
    "127.0.1.104": "abused legit (phishing)",
    "127.0.1.105": "abused legit (malware)",
    "127.0.1.106": "abused legit (botnet C&C)",
}
_ZEN = {
    "127.0.0.2": "SBL (spam source)",
    "127.0.0.3": "SBL CSS",
    "127.0.0.4": "XBL (exploited)",
    "127.0.0.9": "DROP",
    "127.0.0.10": "PBL (ISP policy)",
    "127.0.0.11": "PBL (policy)",
}
_SURBL_BITS = {8: "phishing", 16: "malware", 64: "abuse", 128: "cracked"}


def _surbl(code: str) -> str | None:
    try:
        last = int(code.rsplit(".", 1)[1])
    except (IndexError, ValueError):
        return None
    tags = [name for bit, name in _SURBL_BITS.items() if last & bit]
    return ", ".join(tags) or None


async def _blocklists(dns: IntelDns, domain: str, mx_ips: list[str]) -> dict[str, Any]:
    listings: list[dict[str, str]] = []
    refused: list[str] = []
    lookups = [("dbl.spamhaus.org", domain, domain), ("multi.surbl.org", domain, domain)]
    for ip in mx_ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4 and addr.is_global:
            lookups.append(("zen.spamhaus.org", ".".join(reversed(ip.split("."))), ip))
    for zone, label, subject in lookups:
        answer = await dns.query(f"{label}.{zone}")
        if answer.status == "error":
            refused.append(f"{zone}: {answer.error or 'lookup failed'}")
            continue
        for code in answer.values:
            if code.startswith("127.255.255."):
                refused.append(
                    f"{zone}: query refused ({code}; blocklists often refuse public resolvers)"
                )
                continue
            reason = (
                _DBL.get(code)
                if zone == "dbl.spamhaus.org"
                else (_ZEN.get(code) if zone == "zen.spamhaus.org" else _surbl(code))
            )
            if reason:
                listings.append({"zone": zone, "subject": subject, "code": code, "reason": reason})
    return {
        "listings": listings,
        "refused": refused,
        "checked": [f"{s} @ {z}" for z, _, s in lookups],
    }


async def collect_intel(
    domain: str,
    target_hosts: tuple[str, ...],
    cache_dir: Path,
    *,
    mx_ips: list[str] | None = None,
    client: IntelClient | None = None,
    dns: IntelDns | None = None,
    safe_browsing_key: str | None = None,
) -> IntelReport:
    """Query every source for ``domain`` (cache first). Never raises."""
    report = IntelReport(domain)
    key = (
        safe_browsing_key
        if safe_browsing_key is not None
        else os.environ.get(SAFE_BROWSING_KEY_ENV, "")
    )
    owned = client is None
    client = client or IntelClient(IntelPolicy(target_hosts))
    dns = dns or IntelDns()
    jobs: list[tuple[str, str, Any]] = [
        ("crt.sh", domain, lambda: _crt_sh(client, domain)),
        ("wayback", domain, lambda: _wayback(client, domain)),
        (
            "blocklists",
            f"{domain}|{','.join(sorted(mx_ips or []))}",
            lambda: _blocklists(dns, domain, mx_ips or []),
        ),
    ]
    if key:
        urls = [f"https://{h}/" for h in target_hosts] + [f"http://{h}/" for h in target_hosts]
        jobs.append(("safe_browsing", ",".join(urls), lambda: _safe_browsing(client, key, urls)))
    else:
        report.results.append(
            SourceResult(
                "safe_browsing", "skipped", reason=f"no API key (set {SAFE_BROWSING_KEY_ENV})"
            )
        )
    try:
        for source, cache_key, fetch in jobs:
            path = _cache_path(cache_dir, source, cache_key)
            if (data := _cached(path)) is not None:
                report.results.append(SourceResult(source, "ok", data, "cached"))
                continue
            try:
                data = await fetch()
            except (IntelError, OutOfScopeError) as e:
                report.results.append(SourceResult(source, "unavailable", reason=str(e)))
                continue
            if not data.get("refused"):  # retry refused blocklist answers next time
                _store(path, data)
            report.results.append(SourceResult(source, "ok", data))
    finally:
        if owned:
            await client.aclose()
    return report
