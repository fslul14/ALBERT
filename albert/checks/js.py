"""JavaScript analysis over scripts Albert already collected (crawler: same-host <script src>;
renderer: scripts it fetched; plus inline <script> in crawled HTML). Pure; never fetches.
Source maps are reported from references and headers; a .map is never requested.

Secret evidence is cut from text that was redacted *as a whole* first, so a snippet can never
hold a partial token that per-snippet redaction would miss.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser

from albert.checks.disclosure import INTERNAL_HOST, LOCAL_URL, is_lab_host
from albert.checks.rendered import secret_severity
from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    Severity,
    group_findings,
)
from albert.core.scope import registrable_domain
from albert.core.secrets import redact_with_matches

S, C = Severity, Confidence
MAX_ITEMS = 20
_JS_TYPES = {
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "text/ecmascript",
    "application/ecmascript",
    "module",
}
_SOURCE_MAP_COMMENT = re.compile(r"(?m)[/][/*][#@]\s*sourceMappingURL=([^\s*'\"]+)")
_PLACEHOLDER = re.compile(
    r"(?i)your[_-]?|x{4,}|<[^>]*>|\$\{|\{\{|changeme|example|placeholder|dummy|sample|test[_-]?key"
)
_STAGING_LABEL = re.compile(
    r"^(?:[a-z0-9]+-)?(?:staging|stage|stg|dev|develop|qa|uat|test|preprod|pre-prod|sandbox)"
    r"(?:-[a-z0-9]+|\d+)?$"  # "dev-2", "stg1"; not "developer"
)
_URL_HOST = re.compile(r"https?://([a-z0-9][a-z0-9.-]*[a-z0-9])(?::\d+)?(?=[/\"'`?#\s]|$)", re.I)
_DEV_BUILD = (
    (
        "React",
        re.compile(r"react(?:-dom)?\.development\.js|This is the development version of React"),
    ),
    ("Vue", re.compile(r"You are running Vue in development mode")),
    ("Angular", re.compile(r"Angular is running in development mode")),
    ("Webpack (dev server)", re.compile(r"\[webpack-dev-server\]|webpack/hot/dev-server")),
)
_DEBUG_FLAG = re.compile(
    r"\b(?:debug|isDebug|debugMode|enableDebug|DEBUG|devMode|isDev|DEV_MODE|verboseLogging)"
    r"[\"']?\s*[:=]\s*(?:!0|true|1|[\"']true[\"'])(?![\w])"
    r"|\bNODE_ENV\s*[:=]\s*[\"']development[\"']"
)


@dataclass(frozen=True)
class Script:
    """One piece of JavaScript and where it came from."""

    url: str  # script URL, or the page URL for inline scripts
    text: str
    where: str  # "external" or "inline script #n"
    headers: tuple[tuple[str, str], ...] = ()


def collect_scripts(
    pages: Sequence[CollectedResponse], scripts: Sequence[CollectedResponse]
) -> list[Script]:
    """External JS responses (deduped by URL) plus inline scripts from HTML pages."""
    out: dict[tuple[str, str], Script] = {}
    for r in scripts:
        if r.status == 200 and r.text and (r.content_type in _JS_TYPES or _is_js_url(r.url)):
            out.setdefault((r.url, "external"), Script(r.url, r.text, "external", r.headers))
    for page in pages:
        if page.status != 200 or not page.is_document or not page.text:
            continue
        for i, node in enumerate(LexborHTMLParser(page.text).css("script:not([src])"), 1):
            code = node.text() or ""
            if code.strip():
                out.setdefault(
                    (page.url, f"inline script #{i}"), Script(page.url, code, f"inline script #{i}")
                )
    return list(out.values())


def _is_js_url(url: str) -> bool:
    return urlsplit(url).path.endswith((".js", ".mjs"))


def _finding(
    s: Script,
    fid: str,
    title: str,
    sev: Severity,
    conf: Confidence,
    evidence: Sequence[Evidence],
    impact: str,
    fix: str,
    refs: tuple[str, ...],
) -> Finding:
    return Finding(fid, title, sev, conf, (s.url,), tuple(evidence[:MAX_ITEMS]), impact, fix, refs)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def check_secrets(s: Script) -> list[Finding]:
    """Known secret formats in the script. Evidence comes only from fully redacted text."""
    redacted, matches = redact_with_matches(s.text)
    # Per pattern, the k-th marker in the redacted text is that pattern's k-th match.
    reported: dict[str, list[bool]] = {}
    for name, value in matches:
        # "YOUR_API_KEY", "${TOKEN}", ...: redacted anyway, but not reported.
        keep = not (name == "generic_secret" and _PLACEHOLDER.search(value))
        reported.setdefault(name, []).append(keep)
    out = []
    for name, flags in reported.items():
        if not any(flags):
            continue
        markers = re.finditer(re.escape(f"[REDACTED-{name}]"), redacted)
        snippets = []
        for keep, m in zip(flags, markers, strict=False):
            if keep:
                line = _line_of(redacted, m.start())
                ctx = re.sub(r"\s+", " ", redacted[max(0, m.start() - 40) : m.end() + 15])
                snippets.append(Evidence("js", f"line {line}: ...{ctx}...", s.where))
        if not snippets:  # defensive: report without context rather than not at all
            snippets = [Evidence("js", f"{sum(flags)} match(es), redacted", s.where)]
        sev = secret_severity(name)
        conf = (
            C.LOW
            if name == "generic_secret"
            else C.MEDIUM
            if name in {"jwt", "google_api_key"}
            else C.HIGH
        )
        out.append(
            _finding(
                s,
                f"JS-SECRET-{name.upper()}",
                f"Secret in JavaScript ({name})",
                sev,
                conf,
                snippets,
                "Anyone loading the site can read it from the script; treat it as compromised.",
                "Remove it from client code, rotate it, and proxy the call through the server "
                "(for browser keys, restrict them by referrer/API).",
                ("CWE-798", "CWE-200", "OWASP A02:2021"),
            )
        )
    return out


def check_source_maps(s: Script) -> list[Finding]:
    """Source maps referenced by comment or header (never fetched), or embedded inline."""
    if s.where != "external" and "sourceMappingURL" not in s.text:
        return []
    refs = [m.group(1) for m in _SOURCE_MAP_COMMENT.finditer(s.text[-5000:])]
    refs += [v for k, v in s.headers if k.lower() in {"sourcemap", "x-sourcemap"}]
    out = []
    embedded = [r for r in refs if r.startswith("data:")]
    linked = [urljoin(s.url, r) for r in refs if not r.startswith("data:")]
    if embedded:
        out.append(
            _finding(
                s,
                "JS-SOURCEMAP-EMBEDDED",
                "Source map embedded in script",
                S.LOW,
                C.HIGH,
                [Evidence("js", "inline data: source map", s.where)],
                "The original, unminified source (comments, file layout) ships to every visitor.",
                "Don't inline source maps in production builds.",
                ("CWE-540", "CWE-200"),
            )
        )
    if linked:
        out.append(
            _finding(
                s,
                "JS-SOURCEMAP-REFERENCED",
                "Source map referenced (not fetched)",
                S.INFO,
                C.MEDIUM,
                [Evidence("js", u, "sourceMappingURL") for u in dict.fromkeys(linked)],
                "A publicly served .map exposes original source (Albert did not fetch it).",
                "Remove the reference or keep .map files off the public server.",
                ("CWE-540",),
            )
        )
    return out


def check_internal_refs(s: Script) -> list[Finding]:
    """Hardcoded internal hosts/local URLs and staging hostnames."""
    if is_lab_host(s.url):
        return []
    out = []
    internal = dict.fromkeys(
        [m.group(1).lower() for m in INTERNAL_HOST.finditer(s.text)] + LOCAL_URL.findall(s.text)
    )
    if internal:
        out.append(
            _finding(
                s,
                "JS-INTERNAL-URL",
                "Internal hostnames or local URLs in JavaScript",
                S.LOW,
                C.MEDIUM,
                [Evidence("js", h, s.where) for h in internal],
                "Reveals internal infrastructure and dev leftovers.",
                "Remove internal endpoints from client bundles (per-environment build config).",
                ("CWE-200",),
            )
        )
    staging: dict[str, None] = {}
    for m in _URL_HOST.finditer(s.text):
        host = m.group(1).lower()
        site = registrable_domain(host)
        if not site or host == site:
            continue
        sub_labels = host[: -len(site) - 1].split(".")
        if any(_STAGING_LABEL.match(label) for label in sub_labels):
            staging[host] = None
    if staging:
        out.append(
            _finding(
                s,
                "JS-STAGING-HOST",
                "Staging/test hostnames in JavaScript",
                S.LOW,
                C.MEDIUM,
                [Evidence("js", h, s.where) for h in staging],
                "Production code points at non-production systems, which are often less protected.",
                "Build production bundles with production endpoints only.",
                ("CWE-200", "CWE-489"),
            )
        )
    return out


def check_debug(s: Script) -> list[Finding]:
    """Framework development builds (Low) and debug-flag assignments (Info)."""
    out = []
    builds = [(name, m) for name, rx in _DEV_BUILD if (m := rx.search(s.text))]
    if builds:
        out.append(
            _finding(
                s,
                "JS-DEV-BUILD",
                "Development build of a framework in production",
                S.LOW,
                C.HIGH,
                [Evidence("js", f"{name}: {m.group(0)}", s.where) for name, m in builds],
                "Dev builds are slower and expose extra diagnostics and debug hooks.",
                "Ship production builds (NODE_ENV=production / enableProdMode).",
                ("CWE-489",),
            )
        )
    flags = list(dict.fromkeys(m.group(0) for m in _DEBUG_FLAG.finditer(s.text)))
    if flags:
        out.append(
            _finding(
                s,
                "JS-DEBUG-FLAG",
                "Debug flag enabled in JavaScript",
                S.INFO,
                C.LOW,
                [Evidence("js", f, s.where) for f in flags],
                "May enable verbose logging or hidden diagnostics in the browser.",
                "Disable debug flags in production builds.",
                ("CWE-489",),
            )
        )
    return out


def check_served_source_maps(responses: Sequence[CollectedResponse]) -> list[Finding]:
    """A .map Albert happened to receive as a normal response (never requested to probe)."""
    out = []
    for r in responses:
        if r.status == 200 and urlsplit(r.url).path.endswith(".map") and '"mappings"' in r.text:
            out.append(
                Finding(
                    "JS-SOURCEMAP-SERVED",
                    "Source map publicly served",
                    S.LOW,
                    C.HIGH,
                    (r.url,),
                    (Evidence("js", 'JSON with "mappings"/"sources"', "response"),),
                    "Original source code is downloadable by anyone.",
                    "Remove .map files from the public server or restrict access.",
                    ("CWE-540",),
                )
            )
    return out


def run_js_checks(
    pages: Sequence[CollectedResponse], scripts: Sequence[CollectedResponse]
) -> list[Finding]:
    """All JS checks over collected scripts + inline code, grouped across scripts/pages."""
    checks = (check_secrets, check_source_maps, check_internal_refs, check_debug)
    found = [f for s in collect_scripts(pages, scripts) for c in checks for f in c(s)]
    return group_findings([*found, *check_served_source_maps([*pages, *scripts])])
