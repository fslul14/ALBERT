"""security.txt (RFC 9116) checks. Pure: the fetched /.well-known/security.txt in, findings out.

Only the well-known location is fetched (the legacy top-level /security.txt is not guessed).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from albert.core.models import CollectedResponse, Confidence, Evidence, Finding, Severity

WELL_KNOWN_PATH = "/.well-known/security.txt"
REFS = ("RFC 9116",)

S, C = Severity, Confidence

_SPECS: dict[str, tuple[str, Severity, str, str]] = {
    "SEC-TXT-MISSING": (
        "security.txt not published",
        S.INFO,
        "Researchers have no documented way to report vulnerabilities.",
        "Publish /.well-known/security.txt with Contact and Expires (RFC 9116).",
    ),
    "SEC-TXT-NOT-PLAIN": (
        "security.txt not served as text/plain",
        S.INFO,
        "RFC 9116 requires text/plain; some parsers will reject it.",
        "Serve it with Content-Type: text/plain; charset=utf-8.",
    ),
    "SEC-TXT-NO-CONTACT": (
        "security.txt has no Contact field",
        S.LOW,
        "The file exists but gives no way to reach the security team.",
        "Add at least one Contact: (mailto:, https:, or tel: URI).",
    ),
    "SEC-TXT-NO-EXPIRES": (
        "security.txt Expires missing or invalid",
        S.LOW,
        "Expires is required; without it readers can't tell if the file is stale.",
        "Add Expires: in RFC 3339 format, less than a year ahead.",
    ),
    "SEC-TXT-EXPIRED": (
        "security.txt has expired",
        S.LOW,
        "Readers should treat an expired file as stale; contacts may be outdated.",
        "Review the contacts and set a new Expires date.",
    ),
    "SEC-TXT-EXPIRES-FAR": (
        "security.txt Expires is more than a year ahead",
        S.INFO,
        "RFC 9116 recommends under a year so the file gets reviewed.",
        "Set Expires less than a year in the future.",
    ),
    "SEC-TXT-INSECURE-CONTACT": (
        "security.txt Contact uses plain http",
        S.INFO,
        "Reports sent to an http:// contact can be intercepted.",
        "Use https:, mailto:, or tel: contacts.",
    ),
    "SEC-TXT-PRESENT": (
        "security.txt published",
        S.INFO,
        "Informational: a vulnerability disclosure contact is available.",
        "None.",
    ),
}


def parse_security_txt(text: str) -> dict[str, list[str]]:
    """Field name (lowercased) -> values. Handles comments and PGP clear-signed files."""
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("-----BEGIN PGP SIGNATURE"):
            break
        if line.startswith("- "):  # dash-escaped line inside a signed message
            line = line[2:]
        if not line or line.startswith(("#", "-----BEGIN PGP SIGNED MESSAGE", "Hash:")):
            continue
        name, sep, value = line.partition(":")
        if sep and name and " " not in name.strip():
            fields.setdefault(name.strip().lower(), []).append(value.strip())
    return fields


def _parse_expires(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _hit(resp: CollectedResponse, fid: str, *evidence: Evidence) -> Finding:
    title, severity, impact, fix = _SPECS[fid]
    return Finding(fid, title, severity, C.HIGH, (resp.url,), evidence, impact, fix, REFS)


def check_security_txt(resp: CollectedResponse, now: datetime | None = None) -> list[Finding]:
    """Evaluate one fetched security.txt response (the final hop of its fetch)."""
    now = now or datetime.now(UTC)
    ctype = resp.content_type
    # Missing: non-200, empty, or an HTML soft-404 (SPAs often serve index.html for any path).
    if (
        resp.status != 200
        or not resp.text.strip()
        or ctype in {"text/html", "application/xhtml+xml"}
    ):
        return [
            _hit(
                resp,
                "SEC-TXT-MISSING",
                Evidence("http", f"status {resp.status}, {ctype or 'no type'}"),
            )
        ]

    fields = parse_security_txt(resp.text)
    out: list[Finding] = []
    if ctype != "text/plain":
        out.append(
            _hit(resp, "SEC-TXT-NOT-PLAIN", Evidence("header", ctype or "(absent)", "Content-Type"))
        )
    contacts = fields.get("contact", [])
    if not contacts:
        out.append(_hit(resp, "SEC-TXT-NO-CONTACT", Evidence("field", "(absent)", "Contact")))
    insecure = [c for c in contacts if c.lower().startswith("http://")]
    if insecure:
        out.append(
            _hit(
                resp,
                "SEC-TXT-INSECURE-CONTACT",
                *(Evidence("field", c, "Contact") for c in insecure),
            )
        )
    expires_raw = fields.get("expires", [])
    expires = _parse_expires(expires_raw[0]) if expires_raw else None
    if expires is None:
        shown = expires_raw[0] if expires_raw else "(absent)"
        out.append(_hit(resp, "SEC-TXT-NO-EXPIRES", Evidence("field", shown, "Expires")))
    elif expires < now:
        out.append(_hit(resp, "SEC-TXT-EXPIRED", Evidence("field", expires_raw[0], "Expires")))
    elif expires > now + timedelta(days=366):
        out.append(_hit(resp, "SEC-TXT-EXPIRES-FAR", Evidence("field", expires_raw[0], "Expires")))
    summary = [Evidence("field", c, "Contact") for c in contacts]
    out.append(_hit(resp, "SEC-TXT-PRESENT", *summary))
    return out


def run_security_txt_checks(responses: Sequence[CollectedResponse]) -> list[Finding]:
    """Family entry point: ``responses`` is the security.txt fetch chain; the final hop counts."""
    return check_security_txt(responses[-1]) if responses else []
