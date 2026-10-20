"""HTTP response-header checks. Pure: collected responses in, findings out; no requests.

Titles are constant per issue (specifics go in evidence) so findings group across pages.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from typing import NamedTuple
from urllib.parse import urlsplit

from selectolax.lexbor import LexborHTMLParser

from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    Severity,
    group_findings,
)

S, C = Severity, Confidence
A05 = "OWASP A05:2021"


class _Spec(NamedTuple):
    title: str
    severity: Severity
    confidence: Confidence
    impact: str
    remediation: str
    refs: tuple[str, ...]


_SPECS: dict[str, _Spec] = {
    "HDR-CSP-MISSING": _Spec(
        "Content-Security-Policy missing",
        S.MEDIUM,
        C.HIGH,
        "No CSP to limit the impact of XSS or injected third-party content.",
        "Send a Content-Security-Policy; start with a nonce-based strict policy.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-META-ONLY": _Spec(
        "Content-Security-Policy set only via <meta>",
        S.LOW,
        C.HIGH,
        "Script/style rules apply, but frame-ancestors, report-uri and sandbox are ignored in "
        "<meta>, and the policy only covers content parsed after the tag.",
        "Send the policy as a Content-Security-Policy HTTP header.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-REPORT-ONLY": _Spec(
        "Content-Security-Policy is report-only",
        S.LOW,
        C.HIGH,
        "Violations are reported but nothing is blocked.",
        "Promote the policy to an enforced Content-Security-Policy header once tuned.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-NO-SCRIPT-POLICY": _Spec(
        "CSP does not restrict scripts",
        S.MEDIUM,
        C.HIGH,
        "Without script-src or default-src the policy does not mitigate XSS.",
        "Add script-src (nonce/hash + 'strict-dynamic') or a default-src.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-UNSAFE-INLINE": _Spec(
        "CSP allows inline scripts ('unsafe-inline')",
        S.MEDIUM,
        C.HIGH,
        "Injected inline scripts run, so the CSP gives little XSS protection.",
        "Replace 'unsafe-inline' in script-src with nonces or hashes.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-UNSAFE-EVAL": _Spec(
        "CSP allows eval ('unsafe-eval')",
        S.LOW,
        C.HIGH,
        "String-to-code sinks (eval, new Function) stay usable for injected input.",
        "Remove 'unsafe-eval'; refactor code that needs eval.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-WILDCARD": _Spec(
        "CSP script sources include wildcards",
        S.MEDIUM,
        C.HIGH,
        "Scripts can load from any host/scheme listed, bypassing the policy.",
        "Drop *, scheme-only (https:, data:) sources from script-src/default-src.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-NO-OBJECT-SRC": _Spec(
        "CSP missing object-src",
        S.LOW,
        C.HIGH,
        "Plugin content (<object>/<embed>) is unrestricted.",
        "Add object-src 'none'.",
        ("CWE-693", A05),
    ),
    "HDR-CSP-NO-BASE-URI": _Spec(
        "CSP missing base-uri",
        S.LOW,
        C.HIGH,
        "An injected <base> tag can redirect relative script URLs.",
        "Add base-uri 'none' (or 'self').",
        ("CWE-693", A05),
    ),
    "HDR-CLICKJACKING": _Spec(
        "No clickjacking protection (frame-ancestors / X-Frame-Options)",
        S.MEDIUM,
        C.MEDIUM,
        "The page can be framed by any site and used for clickjacking.",
        "Add CSP frame-ancestors 'self' (or 'none'); optionally X-Frame-Options: DENY.",
        ("CWE-1021", A05),
    ),
    "HDR-XFO-INVALID": _Spec(
        "X-Frame-Options value not supported",
        S.LOW,
        C.HIGH,
        "Values other than DENY/SAMEORIGIN (e.g. ALLOW-FROM) are ignored by modern browsers.",
        "Use CSP frame-ancestors for allow-lists; X-Frame-Options only DENY/SAMEORIGIN.",
        ("CWE-1021", A05),
    ),
    "HDR-FRAME-ANCESTORS-MISSING": _Spec(
        "X-Frame-Options set without CSP frame-ancestors",
        S.INFO,
        C.HIGH,
        "Protected today; frame-ancestors is the standard and supports allow-lists.",
        "Add CSP frame-ancestors matching the X-Frame-Options intent.",
        ("CWE-1021",),
    ),
    "HDR-FRAME-ANCESTORS-WILDCARD": _Spec(
        "CSP frame-ancestors allows any origin",
        S.LOW,
        C.HIGH,
        "Any site may frame the page; this also overrides X-Frame-Options.",
        "Restrict frame-ancestors to 'self' or named origins.",
        ("CWE-1021", A05),
    ),
    "HDR-HSTS-MISSING": _Spec(
        "Strict-Transport-Security missing",
        S.MEDIUM,
        C.HIGH,
        "First visits and typed http:// links can be downgraded/intercepted (SSL stripping).",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        ("CWE-319", A05),
    ),
    "HDR-HSTS-INVALID": _Spec(
        "Strict-Transport-Security malformed",
        S.MEDIUM,
        C.HIGH,
        "Browsers ignore an HSTS header without a valid max-age.",
        "Fix the header: max-age=<seconds>[; includeSubDomains][; preload].",
        ("CWE-319", A05),
    ),
    "HDR-HSTS-DISABLED": _Spec(
        "Strict-Transport-Security max-age=0",
        S.MEDIUM,
        C.HIGH,
        "max-age=0 tells browsers to forget HSTS for this host.",
        "Set a long max-age (≥ 1 year) unless intentionally decommissioning HTTPS.",
        ("CWE-319", A05),
    ),
    "HDR-HSTS-SHORT": _Spec(
        "Strict-Transport-Security max-age too short",
        S.LOW,
        C.HIGH,
        "Protection lapses quickly for infrequent visitors.",
        "Use max-age of at least 15552000 (180 days); 31536000+ recommended.",
        ("CWE-319",),
    ),
    "HDR-HSTS-NO-SUBDOMAINS": _Spec(
        "Strict-Transport-Security lacks includeSubDomains",
        S.LOW,
        C.HIGH,
        "Subdomains can still be reached over HTTP, enabling cookie injection.",
        "Add includeSubDomains once all subdomains serve HTTPS.",
        ("CWE-319",),
    ),
    "HDR-HSTS-NOT-PRELOAD-READY": _Spec(
        "Strict-Transport-Security not preload-ready",
        S.INFO,
        C.HIGH,
        "The host can't join browser HSTS preload lists, so first visits stay exposed.",
        "Use max-age≥31536000; includeSubDomains; preload, then submit to hstspreload.org.",
        ("CWE-319",),
    ),
    "HDR-REFERRER-MISSING": _Spec(
        "Referrer-Policy not set",
        S.INFO,
        C.HIGH,
        "Browser default (strict-origin-when-cross-origin) applies; behavior is implicit.",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
        ("CWE-200",),
    ),
    "HDR-REFERRER-UNSAFE": _Spec(
        "Referrer-Policy leaks full URLs",
        S.LOW,
        C.HIGH,
        "Full URLs (paths, query tokens) are sent to other origins.",
        "Use strict-origin-when-cross-origin, same-origin, or no-referrer.",
        ("CWE-200",),
    ),
    "HDR-PERMISSIONS-WILDCARD": _Spec(
        "Permissions-Policy grants powerful features to all origins",
        S.LOW,
        C.HIGH,
        "Any embedded origin may request the listed features.",
        "Replace =* with () or an explicit origin list.",
        ("CWE-693",),
    ),
    "HDR-CACHE-PUBLIC-SET-COOKIE": _Spec(
        "Response sets a cookie but is publicly cacheable",
        S.MEDIUM,
        C.MEDIUM,
        "A shared cache/CDN may store and serve one user's Set-Cookie to others.",
        "Use Cache-Control: no-store (or private) on responses that set cookies.",
        ("CWE-525", A05),
    ),
    "HDR-CACHE-SENSITIVE": _Spec(
        "Likely-sensitive page cacheable (no Cache-Control: no-store)",
        S.LOW,
        C.LOW,
        "Account/login content may persist in browser or proxy caches.",
        "Send Cache-Control: no-store on authenticated/sensitive pages.",
        ("CWE-525",),
    ),
    "HDR-NO-CONTENT-TYPE": _Spec(
        "Response has no Content-Type",
        S.LOW,
        C.MEDIUM,
        "Browsers sniff the type, which can turn uploaded or reflected content into HTML/script.",
        "Send an explicit Content-Type (with charset for text) on every response with a body.",
        ("CWE-430", A05),
    ),
    "HDR-CONFLICTING-HEADERS": _Spec(
        "Security header sent more than once with different values",
        S.LOW,
        C.HIGH,
        "Browsers keep the first value or ignore the header entirely, so the intended policy may "
        "not apply (often two layers, e.g. app and proxy, both setting it).",
        "Set each security header in exactly one place.",
        (A05,),
    ),
    "HDR-TIMING-ALLOW-ORIGIN": _Spec(
        "Timing-Allow-Origin: * exposes detailed timing to any site",
        S.INFO,
        C.HIGH,
        "Cross-origin pages can read precise resource timing, aiding cross-site leak attacks.",
        "Limit Timing-Allow-Origin to origins that need it.",
        ("CWE-208",),
    ),
    "HDR-INTERNAL-IP": _Spec(
        "Private IP address disclosed in headers",
        S.LOW,
        C.HIGH,
        "Reveals internal network layout.",
        "Strip or rewrite headers carrying internal addresses at the edge.",
        ("CWE-200",),
    ),
    "HDR-TRACE-ID": _Spec(
        "Request/trace ID headers exposed",
        S.INFO,
        C.HIGH,
        "Low risk; reveals tracing stack and lets requests be correlated.",
        "Optional: strip tracing headers at the edge.",
        ("CWE-200",),
    ),
    "HDR-SERVER-TIMING": _Spec(
        "Server-Timing exposes backend metrics",
        S.INFO,
        C.HIGH,
        "Timing data can reveal backend components and aid timing side-channels.",
        "Send Server-Timing only to internal/debug clients.",
        ("CWE-200",),
    ),
    "HDR-ETAG-INODE": _Spec(
        "ETag may disclose file inode (Apache)",
        S.LOW,
        C.MEDIUM,
        "Inode numbers leak filesystem details (CVE-2003-1418).",
        "Apache: FileETag MTime Size.",
        ("CWE-200", "CVE-2003-1418"),
    ),
    "HDR-CDN-WAF": _Spec(
        "CDN/WAF detected",
        S.INFO,
        C.HIGH,
        "Informational: edge provider in front of the origin.",
        "None.",
        (),
    ),
    "HDR-PROTOCOLS": _Spec(
        "HTTP/2 / HTTP/3 support",
        S.INFO,
        C.HIGH,
        "Informational.",
        "None.",
        (),
    ),
}

# id -> (severity, why) for deprecated headers; id becomes HDR-DEPRECATED-<NAME>.
_TRACE_HEADERS = {
    "x-request-id",
    "x-trace-id",
    "x-b3-traceid",
    "traceparent",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
    "x-correlation-id",
    "request-id",
    "x-amzn-requestid",
    "uber-trace-id",
}

# (provider, header, value regex or None for presence)
_CDN_SIGNATURES: tuple[tuple[str, str, str | None], ...] = (
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "server", r"^cloudflare"),
    ("Amazon CloudFront", "x-amz-cf-id", None),
    ("Amazon CloudFront", "via", r"cloudfront"),
    ("Akamai", "server", r"akamai"),
    ("Akamai", "akamai-grn", None),
    ("Fastly", "x-fastly-request-id", None),
    ("Fastly", "x-served-by", r"^cache-"),
    ("Varnish", "x-varnish", None),
    ("Sucuri WAF", "x-sucuri-id", None),
    ("Sucuri WAF", "server", r"sucuri"),
    ("Imperva Incapsula", "x-iinfo", None),
    ("Imperva Incapsula", "x-cdn", r"incapsula|imperva"),
    ("Azure Front Door", "x-azure-ref", None),
    ("Vercel", "x-vercel-id", None),
    ("Netlify", "x-nf-request-id", None),
    ("Google Cloud", "via", r"\bgoogle\b"),
    ("F5 BIG-IP", "server", r"big-?ip"),
    ("Barracuda WAF", "server", r"barracuda"),
    ("AWS ELB", "server", r"^awselb"),
    ("Imperva Incapsula", "set-cookie", r"^(?:incap_ses_|visid_incap_)"),
    ("Cloudflare", "set-cookie", r"^(?:__cf_bm|cf_clearance)="),
    ("F5 BIG-IP", "set-cookie", r"^BIGipServer"),
)

_SENSITIVE_PATH = re.compile(
    r"/(?:log-?in|sign-?in|account|profile|admin|checkout|cart|settings|password|auth|"
    r"dashboard|billing|session|user|my)(?:/|$|[-_.?])",
    re.I,
)
_PRIVATE_IPV4 = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})(?![\d.])"
)
_APACHE_ETAG = re.compile(r'^(?:W/)?"([0-9a-f]+)-([0-9a-f]+)-([0-9a-f]+)(?:-(?:gzip|br))?"$', re.I)
_NONCE_HASH = re.compile(r"^'(?:nonce-|sha256-|sha384-|sha512-)")
_WILDCARD_SOURCES = {
    "*",
    "http:",
    "https:",
    "data:",
    "blob:",
    "filesystem:",
    "http://*",
    "https://*",
}
_POWERFUL_FEATURES = {
    "camera",
    "microphone",
    "geolocation",
    "payment",
    "usb",
    "serial",
    "bluetooth",
    "display-capture",
    "clipboard-read",
    "hid",
}
_UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}
_REFERRER_TOKENS = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def _clip(value: str, limit: int = 300) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


def _hit(
    resp: CollectedResponse,
    fid: str,
    *evidence: Evidence,
    title: str | None = None,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    remediation: str | None = None,
) -> Finding:
    spec = _SPECS[fid]
    return Finding(
        id=fid,
        title=title or spec.title,
        severity=spec.severity if severity is None else severity,
        confidence=spec.confidence if confidence is None else confidence,
        urls=(resp.url,),
        evidence=evidence,
        impact=spec.impact,
        remediation=remediation or spec.remediation,
        refs=spec.refs,
    )


def header_evidence(header: str, value: str | None) -> Evidence:
    """Header evidence ("(absent)" when missing); shared with the YAML rule engine."""
    return Evidence("header", "(absent)" if value is None else _clip(value), location=header)


_ev = header_evidence


# --- CSP ----------------------------------------------------------------------------------


def parse_csp(value: str) -> list[dict[str, list[str]]]:
    """Parse a CSP header value (possibly several comma-joined policies). Lowercases tokens."""
    policies = []
    for raw_policy in value.split(","):
        policy: dict[str, list[str]] = {}
        for part in raw_policy.split(";"):
            tokens = part.strip().lower().split()
            if tokens and tokens[0] not in policy:  # first occurrence wins
                policy[tokens[0]] = tokens[1:]
        if policy:
            policies.append(policy)
    return policies


def _csp_policies(resp: CollectedResponse) -> list[dict[str, list[str]]]:
    return [p for v in resp.header_all("content-security-policy") for p in parse_csp(v)]


def _script_sources(policy: dict[str, list[str]]) -> list[str] | None:
    return policy.get("script-src", policy.get("default-src"))


def _allows_inline(srcs: list[str]) -> bool:
    neutralized = any(_NONCE_HASH.match(s) or s == "'strict-dynamic'" for s in srcs)
    return "'unsafe-inline'" in srcs and not neutralized


def _wildcards(srcs: list[str]) -> list[str]:
    if "'strict-dynamic'" in srcs:  # host/scheme sources are ignored
        return []
    return [s for s in srcs if s in _WILDCARD_SOURCES]


def meta_csp(html: str) -> list[str]:
    """CSP policies delivered in <meta http-equiv="Content-Security-Policy"> tags."""
    if "http-equiv" not in html.lower():
        return []
    tree = LexborHTMLParser(html)
    return [
        node.attributes.get("content") or ""
        for node in tree.css("meta[http-equiv]")
        if (node.attributes.get("http-equiv") or "").strip().lower() == "content-security-policy"
    ]


def check_csp(resp: CollectedResponse) -> list[Finding]:
    """CSP presence and quality on HTML documents (header, else <meta>)."""
    if not resp.is_document:
        return []
    raw = resp.header_all("content-security-policy")
    if raw:
        policies = _csp_policies(resp)
        return csp_quality(resp, policies, _ev("Content-Security-Policy", "; ".join(raw)))
    metas = [m for m in meta_csp(resp.text) if m.strip()] if resp.text else []
    if metas:
        ev = _ev("<meta> Content-Security-Policy", "; ".join(metas))
        policies = [p for m in metas for p in parse_csp(m)]
        return [_hit(resp, "HDR-CSP-META-ONLY", ev), *csp_quality(resp, policies, ev)]
    ro = resp.header("content-security-policy-report-only")
    if ro is not None:
        return [_hit(resp, "HDR-CSP-REPORT-ONLY", _ev("Content-Security-Policy-Report-Only", ro))]
    return [_hit(resp, "HDR-CSP-MISSING", _ev("Content-Security-Policy", None))]


def csp_quality(
    resp: CollectedResponse, policies: list[dict[str, list[str]]], ev: Evidence
) -> list[Finding]:
    """Weaknesses in the enforced policies (all are enforced, so a weakness must be in every
    script-restricting policy to count)."""
    out: list[Finding] = []
    scripts = [s for p in policies if (s := _script_sources(p)) is not None]
    if not scripts:
        out.append(_hit(resp, "HDR-CSP-NO-SCRIPT-POLICY", ev))
    else:
        if all(_allows_inline(s) for s in scripts):
            out.append(_hit(resp, "HDR-CSP-UNSAFE-INLINE", ev))
        if all("'unsafe-eval'" in s for s in scripts):
            out.append(_hit(resp, "HDR-CSP-UNSAFE-EVAL", ev))
        if all(_wildcards(s) for s in scripts):
            out.append(_hit(resp, "HDR-CSP-WILDCARD", ev))
    if not any("object-src" in p or "default-src" in p for p in policies):
        out.append(_hit(resp, "HDR-CSP-NO-OBJECT-SRC", ev))
    if not any("base-uri" in p for p in policies):
        out.append(_hit(resp, "HDR-CSP-NO-BASE-URI", ev))
    return out


def check_framing(resp: CollectedResponse) -> list[Finding]:
    """X-Frame-Options vs CSP frame-ancestors (frame-ancestors wins when present)."""
    if not resp.is_document:
        return []
    ancestors = [p["frame-ancestors"] for p in _csp_policies(resp) if "frame-ancestors" in p]
    xfo = resp.header("x-frame-options")
    if ancestors:
        if all(any(s in _WILDCARD_SOURCES for s in a) for a in ancestors):
            v = "; ".join("frame-ancestors " + " ".join(a) for a in ancestors)
            return [_hit(resp, "HDR-FRAME-ANCESTORS-WILDCARD", _ev("Content-Security-Policy", v))]
        return []
    if xfo is None:
        return [_hit(resp, "HDR-CLICKJACKING", _ev("X-Frame-Options", None))]
    if xfo.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return [_hit(resp, "HDR-XFO-INVALID", _ev("X-Frame-Options", xfo))]
    return [_hit(resp, "HDR-FRAME-ANCESTORS-MISSING", _ev("X-Frame-Options", xfo))]


# --- Transport / content headers ----------------------------------------------------------


def check_hsts(resp: CollectedResponse) -> list[Finding]:
    """HSTS on HTTPS responses: presence, max-age, includeSubDomains, preload readiness."""
    if not resp.is_https:
        return []
    value = resp.header("strict-transport-security")  # browsers honor the first
    if value is None:
        return [_hit(resp, "HDR-HSTS-MISSING", _ev("Strict-Transport-Security", None))]
    ev = _ev("Strict-Transport-Security", value)
    directives = {
        k.strip().lower(): v.strip().strip('"')
        for k, _, v in (d.partition("=") for d in value.split(";"))
        if k.strip()
    }
    try:
        max_age = int(directives["max-age"])
    except (KeyError, ValueError):
        return [_hit(resp, "HDR-HSTS-INVALID", ev)]
    if max_age <= 0:
        return [_hit(resp, "HDR-HSTS-DISABLED", ev)]
    subdomains = "includesubdomains" in directives
    out = []
    if max_age < 15552000:
        out.append(_hit(resp, "HDR-HSTS-SHORT", ev))
    if not subdomains:
        out.append(_hit(resp, "HDR-HSTS-NO-SUBDOMAINS", ev))
    if max_age < 31536000 or not subdomains or "preload" not in directives:
        out.append(_hit(resp, "HDR-HSTS-NOT-PRELOAD-READY", ev))
    return out


def check_referrer_policy(resp: CollectedResponse) -> list[Finding]:
    """Referrer-Policy presence and leaky values (last recognized token wins)."""
    if not resp.is_document:
        return []
    values = resp.header_all("referrer-policy")
    tokens = [t.strip().lower() for v in values for t in v.split(",")]
    known = [t for t in tokens if t in _REFERRER_TOKENS]
    if not known:
        return [
            _hit(resp, "HDR-REFERRER-MISSING", _ev("Referrer-Policy", ", ".join(values) or None))
        ]
    if known[-1] in _UNSAFE_REFERRER:
        return [_hit(resp, "HDR-REFERRER-UNSAFE", _ev("Referrer-Policy", ", ".join(values)))]
    return []


def check_permissions_policy(resp: CollectedResponse) -> list[Finding]:
    """Powerful features granted to every origin (missing header: rules/headers.yaml)."""
    if not resp.is_document:
        return []
    value = resp.header("permissions-policy")
    if value is None:
        return []
    wild = []
    for item in value.split(","):
        feature, _, allow = item.partition("=")
        if feature.strip().lower() in _POWERFUL_FEATURES and allow.strip() == "*":
            wild.append(item.strip())
    if wild:
        return [_hit(resp, "HDR-PERMISSIONS-WILDCARD", _ev("Permissions-Policy", ", ".join(wild)))]
    return []


def check_cache_control(resp: CollectedResponse) -> list[Finding]:
    """Public-cacheable responses that set cookies; sensitive-looking pages without no-store."""
    if not 200 <= resp.status < 300:
        return []
    cc = resp.header("cache-control")
    directives = {d.strip().split("=")[0].lower() for d in (cc or "").split(",") if d.strip()}
    if resp.header_all("set-cookie") and directives & {"public", "s-maxage"}:
        return [_hit(resp, "HDR-CACHE-PUBLIC-SET-COOKIE", _ev("Cache-Control", cc))]
    if _SENSITIVE_PATH.search(urlsplit(resp.url).path) and "no-store" not in directives:
        return [_hit(resp, "HDR-CACHE-SENSITIVE", _ev("Cache-Control", cc))]
    return []


# --- Disclosure ---------------------------------------------------------------------------


def _is_private_host(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def check_leaky_headers(resp: CollectedResponse) -> list[Finding]:
    """Private IPs, trace IDs, Server-Timing (debug/backend headers: rules/headers.yaml)."""
    out = []
    names = {k.lower() for k, _ in resp.headers}
    if not _is_private_host(resp.url):  # lab targets legitimately show private IPs
        for k, v in resp.headers:
            if _PRIVATE_IPV4.search(v):
                out.append(_hit(resp, "HDR-INTERNAL-IP", _ev(k, v)))
    traces = sorted(names & _TRACE_HEADERS)
    if traces:
        out.append(_hit(resp, "HDR-TRACE-ID", Evidence("header", "present", ", ".join(traces))))
    for value in resp.header_all("server-timing"):
        detailed = re.search(
            r"desc=|\b(?:db|sql|mysql|postgres|redis|mongo|cache|query)\b", value, re.I
        )
        out.append(
            _hit(
                resp,
                "HDR-SERVER-TIMING",
                _ev("Server-Timing", value),
                severity=S.LOW if detailed else None,
            )
        )
    return out


_SINGLE_VALUE_HEADERS = (
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-type",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "access-control-allow-credentials",
)


def check_misc(resp: CollectedResponse) -> list[Finding]:
    """Missing Content-Type, conflicting duplicate security headers, Timing-Allow-Origin: *."""
    out = []
    has_body = (resp.header("content-length") or "").strip() != "0"
    if (
        200 <= resp.status < 300
        and resp.status != 204
        and has_body
        and not resp.header("content-type")
    ):
        out.append(_hit(resp, "HDR-NO-CONTENT-TYPE", _ev("Content-Type", None)))
    for name in _SINGLE_VALUE_HEADERS:
        values = resp.header_all(name)
        if len({re.sub(r"\s+", "", v).lower() for v in values}) > 1:
            out.append(_hit(resp, "HDR-CONFLICTING-HEADERS", *(_ev(name, v) for v in values)))
    if any(v.strip() == "*" for v in resp.header_all("timing-allow-origin")):
        out.append(_hit(resp, "HDR-TIMING-ALLOW-ORIGIN", _ev("Timing-Allow-Origin", "*")))
    return out


def check_etag_inode(resp: CollectedResponse) -> list[Finding]:
    """Apache inode-size-mtime ETag format."""
    etag = resp.header("etag")
    if etag is None or not _APACHE_ETAG.match(etag.strip()):
        return []
    apache = "apache" in (resp.header("server") or "").lower()
    return [_hit(resp, "HDR-ETAG-INODE", _ev("ETag", etag), confidence=None if apache else C.LOW)]


def check_cdn_waf(resp: CollectedResponse) -> list[Finding]:
    """Identify CDN/WAF providers from their response headers and cookies."""
    seen: dict[str, Evidence] = {}
    for provider, header, pattern in _CDN_SIGNATURES:
        if provider in seen:
            continue
        for value in resp.header_all(header):
            if pattern is None or re.search(pattern, value, re.I):
                shown = value.split("=", 1)[0] + "=..." if header == "set-cookie" else value
                seen[provider] = _ev(header, shown)
                break
    return [
        _hit(resp, "HDR-CDN-WAF", ev, title=f"CDN/WAF detected: {provider}")
        for provider, ev in seen.items()
    ]


def check_protocols(resp: CollectedResponse) -> list[Finding]:
    """HTTP/2 and HTTP/3 support on documents.

    Albert's client speaks HTTP/1.1 only, so HTTP/2 is inferred from Alt-Svc or reported as
    not observed (which is not evidence the server lacks it).
    """
    if not resp.is_document:
        return []
    alt = "; ".join(resp.header_all("alt-svc"))
    version = resp.http_version.upper()
    if version.startswith(("HTTP/2", "HTTP/3")):
        h2 = f"HTTP/2+: negotiated ({version})"
    elif re.search(r"\bh2=", alt):
        h2 = "HTTP/2: advertised via Alt-Svc"
    else:
        h2 = "HTTP/2: not observed (client is HTTP/1.1-only)"
    h3 = (
        "HTTP/3: advertised via Alt-Svc"
        if re.search(r"\bh3(?:-\d+)?=", alt)
        else "HTTP/3: not advertised (no h3 in Alt-Svc)"
    )
    evidence = [Evidence("protocol", h2), Evidence("protocol", h3)]
    if alt:
        evidence.append(_ev("Alt-Svc", alt))
    return [_hit(resp, "HDR-PROTOCOLS", *evidence)]


HeaderCheck = Callable[[CollectedResponse], list[Finding]]

CHECKS: tuple[HeaderCheck, ...] = (
    check_csp,
    check_framing,
    check_hsts,
    check_referrer_policy,
    check_permissions_policy,
    check_cache_control,
    check_leaky_headers,
    check_misc,
    check_etag_inode,
    check_cdn_waf,
    check_protocols,
)


def run_header_checks(responses: Iterable[CollectedResponse]) -> list[Finding]:
    """Python header checks over every response, grouped. The engine adds the YAML rules
    (rules/headers.yaml) via ``run_family("headers", ...)``."""
    return group_findings(f for resp in responses for check in CHECKS for f in check(resp))
