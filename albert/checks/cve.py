"""CVE matching for versioned technology detections. Pure over vulndb lookups.

Finding confidence = min(detection confidence, match certainty), so a version read from a
URL path (Low) can never produce a High-confidence CVE finding, however severe the CVE.
Match certainty: OSV package match High; NVD CPE version range Medium (distros backport fixes
without changing versions); NVD match that also needs a specific platform Low.
Severity comes from the advisory's CVSS (score, or computed from a v3 vector, else its label).
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from typing import Any

from albert.core.models import Confidence, Evidence, Finding, Severity, group_findings
from albert.core.vulndb import Lookup

S, C = Severity, Confidence

# --- CVSS v3.x base score -----------------------------------------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100_000)
    return i / 100_000 if i % 10_000 == 0 else (math.floor(i / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str | None) -> float | None:
    """CVSS 3.0/3.1 base score from a vector string, or None if it isn't one."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr[m["PR"]] * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = (impact + exploit) * (1.08 if scope_changed else 1)
    return _roundup(min(total, 10))


def severity_from_score(score: float | None, label: str | None = None) -> Severity:
    """CVSS qualitative rating (score wins over the label)."""
    if score is not None:
        if score >= 9.0:
            return S.CRITICAL
        if score >= 7.0:
            return S.HIGH
        if score >= 4.0:
            return S.MEDIUM
        return S.LOW if score > 0 else S.INFO
    names = {
        "CRITICAL": S.CRITICAL,
        "HIGH": S.HIGH,
        "MODERATE": S.MEDIUM,
        "MEDIUM": S.MEDIUM,
        "LOW": S.LOW,
    }
    return names.get((label or "").upper(), S.MEDIUM)


# --- versions -----------------------------------------------------------------------------


def version_key(version: str) -> tuple[int, ...]:
    """Numeric sort key: '2.4.49' -> (2, 4, 49). Non-numeric parts are ignored."""
    return tuple(int(p) for p in re.findall(r"\d+", version.split("-")[0].split("+")[0]))


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    n = max(len(ka), len(kb))
    ka, kb = ka + (0,) * (n - len(ka)), kb + (0,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def nvd_certainty(version: str, advisory: dict[str, Any]) -> Confidence | None:
    """Does ``version`` fall in one of this CVE's vulnerable ranges? Returns match certainty."""
    best: Confidence | None = None
    for m in advisory.get("matches", []):
        fields = m["criteria"].split(":")
        exact = fields[5] if len(fields) > 5 else "*"
        if exact not in ("*", "-"):
            ok = _cmp(version, exact) == 0
        elif exact == "-":
            ok = False
        else:
            ok = all(
                (
                    "versionStartIncluding" not in m
                    or _cmp(version, m["versionStartIncluding"]) >= 0,
                    "versionStartExcluding" not in m
                    or _cmp(version, m["versionStartExcluding"]) > 0,
                    "versionEndIncluding" not in m or _cmp(version, m["versionEndIncluding"]) <= 0,
                    "versionEndExcluding" not in m or _cmp(version, m["versionEndExcluding"]) < 0,
                )
            ) and any(k.startswith("version") for k in m)  # bare "*" = every version: too vague
        if ok:
            certainty = C.LOW if m.get("needs_platform") else C.MEDIUM
            best = certainty if best is None else max(best, certainty)
    return best


# --- findings -----------------------------------------------------------------------------


def _slug(advisory_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "_", advisory_id)


def _finding(lk: Lookup, adv: dict[str, Any], certainty: Confidence) -> Finding:
    d = lk.detection
    cves = [a for a in [adv["id"], *adv.get("aliases", [])] if a.startswith("CVE-")]
    primary = cves[0] if cves else adv["id"]
    score = adv.get("cvss_score")
    if score is None:
        score = cvss3_base_score(adv.get("cvss_vector"))
    severity = severity_from_score(score, adv.get("severity_label"))
    fixed = adv.get("fixed", [])
    fix = (
        f"Upgrade {d.name} to a fixed version ({', '.join(fixed[:3])} or later)."
        if fixed
        else f"Upgrade {d.name} to a release that fixes {primary}."
    )
    ev = [
        Evidence(
            "tech", f"{d.name} {d.version} (detection confidence: {d.confidence.label})", "detected"
        ),
        *(Evidence("tech", e, "signal") for e in d.evidence[:3]),
        Evidence(
            "advisory",
            f"{adv['id']}" + (f" (CVSS {score})" if score is not None else ""),
            lk.source,
        ),
    ]
    return Finding(
        id=f"VULN-{_slug(primary)}-{re.sub(r'[^A-Za-z0-9]+', '_', d.name)}",
        title=f"{d.name} {d.version} affected by {primary}",
        severity=severity,
        confidence=min(d.confidence, certainty),
        urls=d.urls or ("(site-wide)",),
        evidence=tuple(ev),
        impact=(adv.get("summary") or "Known vulnerability in this version.")[:300],
        remediation=fix + " Verify the version first: banners and paths can lag behind patches.",
        refs=tuple(dict.fromkeys([*cves, adv["id"], *adv.get("cwes", []), adv["url"]])),
    )


def match_cves(lookups: Sequence[Lookup]) -> list[Finding]:
    """CVE findings for matched advisories + one Info note for unavailable lookups."""
    out: list[Finding] = []
    unavailable = []
    for lk in lookups:
        version = lk.detection.version
        if version is None:  # presence-only detections are never matched
            continue
        if lk.status != "ok":
            unavailable.append(lk)
            continue
        for adv in lk.advisories:
            if lk.source == "osv":
                certainty: Confidence | None = C.HIGH  # OSV already filtered by version
            else:
                certainty = nvd_certainty(version, adv)
            if certainty is not None:
                out.append(_finding(lk, adv, certainty))
    if unavailable:
        out.append(
            Finding(
                "CVE-LOOKUP-UNAVAILABLE",
                "Versions detected, CVE lookup unavailable",
                S.INFO,
                C.HIGH,
                ("(site-wide)",),
                tuple(
                    Evidence(
                        "tech",
                        f"{lk.detection.name} {lk.detection.version}: {lk.reason}",
                        lk.source,
                    )
                    for lk in unavailable
                ),
                "These versions were not checked against vulnerability databases in this run.",
                "Re-run with --cve online (queries OSV.dev/NVD, never the target).",
                (),
            )
        )
    return group_findings(out)
