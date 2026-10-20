"""CORS as served. Pure and read-only: Albert never sends an Origin header, so it only sees
what the server returns to a plain request. Reflection can't be confirmed passively; signs of
it (a specific credentialed origin with ``Vary: Origin``) are reported at Low confidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    Severity,
    group_findings,
)
from albert.core.scope import registrable_domain

S, C = Severity, Confidence
REFS = ("CWE-942", "OWASP A05:2021")

_SPECS: dict[str, tuple[str, Severity, Confidence, str, str]] = {
    "CORS-WILDCARD": (
        "CORS allows any origin (Access-Control-Allow-Origin: *)",
        S.LOW,
        C.HIGH,
        "Any site can read this response from a visitor's browser. Fine for public data; a "
        "leak if the response is user-specific or reachable only from a private network.",
        "Keep * only on genuinely public resources; allow-list origins elsewhere.",
    ),
    "CORS-WILDCARD-CREDENTIALS": (
        "CORS wildcard combined with Allow-Credentials: true",
        S.MEDIUM,
        C.HIGH,
        "Browsers refuse this exact pair, so it isn't readable as served, but configurations "
        "that emit it commonly reflect the caller's Origin when one is sent, which would let "
        "any site read authenticated responses.",
        "Allow-list specific trusted origins; never reflect Origin with credentials.",
    ),
    "CORS-NULL": (
        "CORS allows the 'null' origin",
        S.LOW,
        C.HIGH,
        "Sandboxed iframes, data: and file: documents have origin 'null' and can read this.",
        "Never allow-list 'null'.",
    ),
    "CORS-NULL-CREDENTIALS": (
        "CORS allows the 'null' origin with credentials",
        S.HIGH,
        C.HIGH,
        "Any attacker page can use a sandboxed iframe (origin 'null') to read authenticated "
        "responses with the visitor's cookies.",
        "Never allow-list 'null'; use an explicit allow-list of trusted origins.",
    ),
    "CORS-DYNAMIC-CREDENTIALS": (
        "Credentialed CORS origin varies per request (possible Origin reflection)",
        S.MEDIUM,
        C.LOW,
        "Vary: Origin with a credentialed ACAO means the server picks the origin per request. "
        "If it reflects arbitrary origins, any site can read authenticated data. Unconfirmed: "
        "passive observation can't test reflection.",
        "Check the allow-list logic server-side (exact-match against trusted origins). "
        "Confirming needs an authorized active test.",
    ),
    "CORS-CREDENTIALS-INSECURE-ORIGIN": (
        "Credentialed CORS granted to a plain-HTTP origin",
        S.MEDIUM,
        C.HIGH,
        "Anyone who can tamper with that HTTP origin's traffic can read authenticated data.",
        "Only allow https:// origins.",
    ),
    "CORS-CREDENTIALS-THIRD-PARTY": (
        "Credentialed CORS granted to another site",
        S.LOW,
        C.MEDIUM,
        "That site (and anything that compromises it) can read authenticated responses.",
        "Confirm the origin is trusted and still needed.",
    ),
    "CORS-INVALID": (
        "Invalid Access-Control-Allow-Origin value",
        S.LOW,
        C.HIGH,
        "Browsers reject lists and patterns, so CORS fails; it often hints at hand-rolled "
        "origin handling that may be bypassable.",
        "Send exactly one origin (or *); match the allow-list server-side.",
    ),
}


def _hit(resp: CollectedResponse, fid: str, ev: list[Evidence]) -> Finding:
    title, sev, conf, impact, fix = _SPECS[fid]
    return Finding(fid, title, sev, conf, (resp.url,), tuple(ev), impact, fix, REFS)


def check_cors(resp: CollectedResponse) -> list[Finding]:
    """CORS headers on one response, as served."""
    values = resp.header_all("access-control-allow-origin")
    if not values:
        return []
    creds = (resp.header("access-control-allow-credentials") or "").strip().lower() == "true"
    vary = {v.strip().lower() for h in resp.header_all("vary") for v in h.split(",")}
    ev = [Evidence("header", v, "Access-Control-Allow-Origin") for v in values]
    if creds:
        ev.append(Evidence("header", "true", "Access-Control-Allow-Credentials"))
    if "origin" in vary:
        ev.append(Evidence("header", "Origin", "Vary"))

    raw = values[0].strip()
    if len(values) > 1 or "," in raw or " " in raw or "*." in raw:
        return [_hit(resp, "CORS-INVALID", ev)]
    origin = raw.lower()
    if origin == "*":
        return [_hit(resp, "CORS-WILDCARD-CREDENTIALS" if creds else "CORS-WILDCARD", ev)]
    if origin == "null":
        return [_hit(resp, "CORS-NULL-CREDENTIALS" if creds else "CORS-NULL", ev)]
    parts = urlsplit(origin)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/"):
        return [_hit(resp, "CORS-INVALID", ev)]
    if not creds:
        return []  # a single named origin without credentials is ordinary
    if parts.scheme == "http":
        return [_hit(resp, "CORS-CREDENTIALS-INSECURE-ORIGIN", ev)]
    if "origin" in vary:
        return [_hit(resp, "CORS-DYNAMIC-CREDENTIALS", ev)]
    own = registrable_domain(urlsplit(resp.url).hostname or "")
    if registrable_domain(parts.hostname) != own:
        return [_hit(resp, "CORS-CREDENTIALS-THIRD-PARTY", ev)]
    return []


def run_cors_checks(responses: Sequence[CollectedResponse]) -> list[Finding]:
    """Family entry point, grouped across pages."""
    return group_findings(f for r in responses for f in check_cors(r))
