"""Findings from external intelligence (scan --full). Pure over an IntelReport.

Severity: CT subdomains and Wayback URLs are Info (inventory); a blocklisted domain or MX IP
is Medium (Low for a policy-only PBL listing); a Safe Browsing match is High. Discovered
hosts are reported with their scope status only: Albert never contacts them, and a later scan
of one needs its own scope.toml entry.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

from albert.checks.disclosure import SENSITIVE_PATH
from albert.core.intel_sources import IntelReport
from albert.core.models import Confidence, Evidence, Finding, Severity

S, C = Severity, Confidence
MAX_EVIDENCE = 60


def _f(
    fid: str,
    title: str,
    sev: Severity,
    conf: Confidence,
    url: str,
    ev: list[Evidence],
    impact: str,
    fix: str,
    refs: tuple[str, ...] = (),
) -> Finding:
    return Finding(fid, title, sev, conf, (url,), tuple(ev[:MAX_EVIDENCE]), impact, fix, refs)


def intel_findings(report: IntelReport, in_scope: Callable[[str], bool]) -> list[Finding]:
    """Findings for every source; ``in_scope(host)`` says whether scope.toml covers a host."""
    d = report.domain
    where = f"intel:{d}"
    out: list[Finding] = []
    unavailable = [r for r in report.results if r.status != "ok"]
    for r in report.results:
        if r.status != "ok":
            continue
        if r.source == "crt.sh" and r.data.get("subdomains"):
            subs = r.data["subdomains"]
            ev = [
                Evidence("ct", s, "in scope" if in_scope(s) else "not in scope: not contacted")
                for s in subs
            ]
            out.append(
                _f(
                    "INTEL-CT-SUBDOMAINS",
                    f"{r.data.get('total', len(subs))} subdomain(s) in "
                    "Certificate Transparency logs",
                    S.INFO,
                    C.HIGH,
                    where,
                    ev,
                    "Every certificate is public: forgotten or staging hosts become discoverable.",
                    "Review the list and retire unused hosts. To scan one, add it to scope.toml.",
                )
            )
        elif r.source == "wayback" and r.data.get("urls"):
            urls = r.data["urls"]
            sensitive = [u for u in urls if SENSITIVE_PATH.search(urlsplit(u["url"]).path)]
            ev = [
                Evidence(
                    "wayback",
                    f"{u['url']} ({u['timestamp'][:8]}, HTTP {u['status']})",
                    "sensitive-looking path",
                )
                for u in sensitive
            ]
            ev += [Evidence("wayback", f"{len(urls)} archived URL(s) in total", "summary")]
            out.append(
                _f(
                    "INTEL-WAYBACK-URLS",
                    "Historical URLs in the Wayback Machine",
                    S.INFO,
                    C.HIGH,
                    where,
                    ev,
                    "Old endpoints, backups or admin paths may still exist (reported only; Albert "
                    "did not fetch them).",
                    "Check that retired or sensitive paths are really gone or protected.",
                )
            )
        elif r.source == "blocklists":
            for hit in r.data.get("listings", []):
                is_mx = hit["zone"] == "zen.spamhaus.org"
                policy_only = is_mx and hit["reason"].startswith("PBL")
                out.append(
                    _f(
                        "INTEL-BLOCKLISTED-MX" if is_mx else "INTEL-BLOCKLISTED-DOMAIN",
                        ("MX IP" if is_mx else "Domain") + f" listed on {hit['zone']}",
                        S.LOW if policy_only else S.MEDIUM,
                        C.HIGH,
                        where,
                        [
                            Evidence(
                                "dnsbl",
                                f"{hit['subject']}: {hit['reason']} ({hit['code']})",
                                hit["zone"],
                            )
                        ],
                        "Mail and links from the domain are likely blocked or flagged; it may be "
                        "compromised or abused.",
                        "Investigate the listing reason and follow the list's delisting process.",
                    )
                )
            if r.data.get("refused"):
                unavailable.append(r)
        elif r.source == "safe_browsing" and r.data.get("matches"):
            out.append(
                _f(
                    "INTEL-SAFE-BROWSING",
                    "Google Safe Browsing flags the site",
                    S.HIGH,
                    C.HIGH,
                    where,
                    [
                        Evidence(
                            "safe_browsing",
                            f"{m['url']}: {m['threat']} ({m['platform']})",
                            "threat match",
                        )
                        for m in r.data["matches"]
                    ],
                    "Browsers show visitors a full-page warning; the site may be compromised.",
                    "Clean the site, then request a review in Google Search Console.",
                )
            )
    if unavailable:
        ev = []
        for r in unavailable:
            if r.source == "blocklists" and r.status == "ok":
                ev += [Evidence("intel", why, "blocklists") for why in r.data.get("refused", [])]
            else:
                ev.append(Evidence("intel", f"{r.status}: {r.reason}", r.source))
        out.append(
            _f(
                "INTEL-NOT-ASSESSED",
                "Some external-intelligence sources were not checked",
                S.INFO,
                C.HIGH,
                where,
                ev,
                "These sources did not contribute to this report.",
                "Re-run later, or provide the missing API key.",
            )
        )
    return out
