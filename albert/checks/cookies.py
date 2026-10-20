"""Cookie checks on Set-Cookie headers as served. Pure and read-only: Albert never sets or
sends cookies. Per-cookie findings put the cookie name in the id and title, so grouping keeps
"cookie A" and "cookie B" separate while merging the same cookie across pages.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
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

S = Severity
A05 = "OWASP A05:2021"
MDN = "https://developer.mozilla.org/docs/Web/HTTP/Cookies"

# Names that usually carry a session or credential. CSRF tokens are sensitive but are often
# meant to be JS-readable (double-submit), so they're exempt from the HttpOnly check only.
# THE definition of a session/credential cookie name. YAML rules reference it as
# "@sensitive_cookie" (core/engine.py NAMED_PATTERNS), so the two can't drift.
SENSITIVE_COOKIE_NAME = re.compile(
    r"sess|sid$|^sid|auth|token|jwt|login|remember|identity|access|refresh|csrf|xsrf|"
    r"^connect\.sid$|phpsessid|jsessionid|asp\.net_sessionid|^_?session$|_session$",
    re.I,
)


@dataclass(frozen=True)
class SetCookie:
    """One parsed Set-Cookie header (value deliberately not kept)."""

    name: str
    attrs: dict[str, str] = field(default_factory=dict)  # lowercased names; flags map to ""
    flags: frozenset[str] = frozenset()  # "secure", "httponly", "partitioned"
    raw_attrs: str = ""  # attribute text as served, for evidence

    @property
    def secure(self) -> bool:
        return "secure" in self.flags

    @property
    def httponly(self) -> bool:
        return "httponly" in self.flags

    @property
    def samesite(self) -> str | None:
        v = self.attrs.get("samesite")
        return v.lower() if v is not None else None

    @property
    def sensitive(self) -> bool:
        return bool(SENSITIVE_COOKIE_NAME.search(self.name))


def parse_set_cookie(header: str) -> SetCookie | None:
    """Parse a Set-Cookie value (RFC 6265bis, lenient). None if there's no cookie name."""
    pair, _, rest = header.partition(";")
    name, eq, _value = pair.partition("=")
    name = name.strip()
    if not eq or not name:
        return None
    attrs: dict[str, str] = {}
    flags: set[str] = set()
    for part in rest.split(";"):
        key, has_value, val = part.strip().partition("=")
        key = key.strip().lower()
        if not key:
            continue
        if has_value:
            attrs.setdefault(key, val.strip())
        else:
            flags.add(key)
    return SetCookie(name, attrs, frozenset(flags), rest.strip())


def cookie_id_part(name: str) -> str:
    """Cookie name made safe for a finding id."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:64]


def cookie_evidence(cookie: SetCookie) -> Evidence:
    """Set-Cookie evidence without the value; shared with the YAML rule engine."""
    attrs = f"; {cookie.raw_attrs}" if cookie.raw_attrs else ""
    return Evidence("cookie", f"{cookie.name}=[value not recorded]{attrs}", "Set-Cookie")


def _hit(
    resp: CollectedResponse,
    cookie: SetCookie,
    code: str,
    title: str,
    severity: Severity,
    impact: str,
    fix: str,
    refs: tuple[str, ...],
) -> Finding:
    return Finding(
        id=f"COOKIE-{code}-{cookie_id_part(cookie.name)}",
        title=f"Cookie '{cookie.name}': {title}",
        severity=severity,
        confidence=Confidence.HIGH,
        urls=(resp.url,),
        evidence=(cookie_evidence(cookie),),
        impact=impact,
        remediation=fix,
        refs=(*refs, MDN),
    )


def _scope_checks(resp: CollectedResponse, c: SetCookie) -> list[Finding]:
    out = []
    host = (urlsplit(resp.url).hostname or "").lower()
    domain = c.attrs.get("domain", "").strip().lstrip(".").lower()
    if domain:
        site = registrable_domain(host)
        whole_site = site is not None and domain == site
        out.append(
            _hit(
                resp,
                c,
                "BROAD-DOMAIN",
                f"Domain={domain} shares it with all subdomains",
                S.LOW if c.sensitive and whole_site else S.INFO,
                "Every subdomain (including any compromised or third-party-hosted one) receives "
                "and can overwrite the cookie.",
                "Omit Domain to make the cookie host-only, or use the __Host- prefix.",
                ("CWE-1275",),
            )
        )
    resp_dir = urlsplit(resp.url).path.rsplit("/", 1)[0]
    if c.sensitive and c.attrs.get("path", "/") == "/" and resp_dir.count("/") >= 1:
        out.append(
            _hit(
                resp,
                c,
                "BROAD-PATH",
                "Path=/ set by a sub-path application",
                S.INFO,
                "Other applications on the same host receive the cookie (Path is not a strong "
                "boundary, but narrows exposure).",
                f"If the app lives under {resp_dir}/, set Path accordingly.",
                ("CWE-1275",),
            )
        )
    return out


def _prefix_checks(resp: CollectedResponse, c: SetCookie) -> list[Finding]:
    problems = []
    name = c.name.lower()
    if name.startswith(("__secure-", "__host-")):
        if not c.secure:
            problems.append("no Secure attribute")
        if not resp.is_https:
            problems.append("set over plain HTTP")
    if name.startswith("__host-"):
        if "domain" in c.attrs:
            problems.append("has a Domain attribute")
        if c.attrs.get("path") != "/":
            problems.append("Path is not /")
    if not problems:
        return []
    return [
        _hit(
            resp,
            c,
            "PREFIX-MISUSE",
            f"{c.name.split('-')[0]}- prefix rules broken ({', '.join(problems)})",
            S.LOW,
            "Browsers reject the cookie, so the protection the prefix promises is absent (and the "
            "feature relying on it may silently fail).",
            "__Secure-: Secure + HTTPS. __Host-: Secure + HTTPS + Path=/ + no Domain.",
            ("CWE-1275", "RFC 6265bis"),
        )
    ]


def check_cookies(resp: CollectedResponse) -> list[Finding]:
    """Domain/Path/prefix checks for one response (flag checks: rules/cookies.yaml)."""
    out: list[Finding] = []
    for header in resp.header_all("set-cookie"):
        cookie = parse_set_cookie(header)
        if cookie is None:
            continue
        out += _scope_checks(resp, cookie)
        out += _prefix_checks(resp, cookie)
    return out


def run_cookie_checks(responses: Sequence[CollectedResponse]) -> list[Finding]:
    """Family entry point: every response, grouped across pages per cookie."""
    return group_findings(f for r in responses for f in check_cookies(r))
