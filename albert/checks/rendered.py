"""Rendered-content checks. Pure: RenderedPage (post-JS DOM + attempted sub-requests) in,
findings out. Also reconciles the header CSP finding with <meta> CSPs found after rendering.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urljoin, urlsplit

from selectolax.lexbor import LexborHTMLParser

from albert.checks.disclosure import markup_without_scripts
from albert.checks.headers import check_csp, meta_csp
from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    RenderedPage,
    Severity,
    group_findings,
)
from albert.core.secrets import PATTERN_SEVERITY, PATTERNS

S, C = Severity, Confidence
A02, A05, A08 = "OWASP A02:2021", "OWASP A05:2021", "OWASP A08:2021"
MAX_ITEMS = 20

_ACTIVE_TYPES = {"script", "stylesheet", "document", "xhr", "fetch", "websocket", "font", "object"}
_ACTIVE_SELECTORS = (
    ("script[src]", "src"),
    ("iframe[src]", "src"),
    ("frame[src]", "src"),
    ("object[data]", "data"),
    ("embed[src]", "src"),
)
_PASSIVE_SELECTORS = (
    ("img[src]", "src"),
    ("audio[src]", "src"),
    ("video[src]", "src"),
    ("source[src]", "src"),
)
_DEFAULT_PORT = {"http": 80, "https": 443}


def secret_severity(pattern_name: str) -> Severity:
    """Severity for a secret of this type found in served content (shared with JS checks)."""
    return Severity.from_label(PATTERN_SEVERITY.get(pattern_name, "medium"))


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    return p.scheme, (p.hostname or "").lower(), p.port or _DEFAULT_PORT.get(p.scheme, 0)


def _finding(
    page: RenderedPage,
    fid: str,
    title: str,
    sev: Severity,
    conf: Confidence,
    evidence: Sequence[Evidence],
    impact: str,
    fix: str,
    refs: tuple[str, ...],
) -> Finding:
    return Finding(
        fid, title, sev, conf, (page.final_url,), tuple(evidence[:MAX_ITEMS]), impact, fix, refs
    )


def _tree(page: RenderedPage) -> LexborHTMLParser | None:
    return LexborHTMLParser(page.dom) if page.dom else None


def check_mixed_content(page: RenderedPage) -> list[Finding]:
    """HTTPS page referencing or requesting http:// sub-resources."""
    if urlsplit(page.final_url).scheme != "https" or (tree := _tree(page)) is None:
        return []
    active: dict[str, str] = {}
    passive: dict[str, str] = {}
    for r in page.requests:
        if r.url.startswith("http://") and r.url != page.url:
            (active if r.resource_type in _ACTIVE_TYPES else passive)[r.url] = r.resource_type
    # Browsers block active mixed content before requesting it, so read the DOM too.
    for selectors, bucket in ((_ACTIVE_SELECTORS, active), (_PASSIVE_SELECTORS, passive)):
        for css, attr in selectors:
            for node in tree.css(css):
                url = urljoin(page.final_url, (node.attributes.get(attr) or "").strip())
                if url.startswith("http://"):
                    bucket.setdefault(url, node.tag or css)
    for node in tree.css("link[href]"):
        if "stylesheet" in (node.attributes.get("rel") or "").lower():
            url = urljoin(page.final_url, node.attributes.get("href") or "")
            if url.startswith("http://"):
                active.setdefault(url, "stylesheet")
    out = []
    if active:
        out.append(
            _finding(
                page,
                "RND-MIXED-ACTIVE",
                "Active mixed content (HTTP scripts/styles/frames)",
                S.MEDIUM,
                C.HIGH,
                [Evidence("resource", u, t) for u, t in active.items()],
                "Browsers block these (breaking the page); legacy clients load attacker-modifiable "
                "code into an HTTPS page.",
                "Load every sub-resource over https://.",
                ("CWE-319", A02),
            )
        )
    if passive:
        out.append(
            _finding(
                page,
                "RND-MIXED-PASSIVE",
                "Passive mixed content (HTTP images/media)",
                S.LOW,
                C.HIGH,
                [Evidence("resource", u, t) for u, t in passive.items()],
                "Images/media can be swapped or observed on the network; the padlock is degraded.",
                "Serve these over https:// (browsers auto-upgrade some, not all).",
                ("CWE-319",),
            )
        )
    return out


def check_forms(page: RenderedPage) -> list[Finding]:
    """Password fields on HTTP pages, forms submitting over HTTP, cross-origin form posts."""
    if (tree := _tree(page)) is None:
        return []
    page_origin = _origin(page.final_url)
    http_page = page_origin[0] == "http"
    out = []
    if http_page and tree.css_first("input[type=password]"):
        out.append(
            _finding(
                page,
                "RND-PASSWORD-ON-HTTP",
                "Password field on a page served over HTTP",
                S.HIGH,
                C.HIGH,
                [Evidence("form", page.final_url, "page")],
                "Credentials (and the page that collects them) travel unencrypted; anyone on the "
                "path can read or alter them.",
                "Serve the page and its form target over HTTPS.",
                ("CWE-319", "CWE-523", A02),
            )
        )
    insecure, cross = [], []
    for form in tree.css("form"):
        raw = (form.attributes.get("action") or "").strip()
        if raw.lower().startswith("javascript:"):
            continue
        action = urljoin(page.final_url, raw or page.final_url)
        has_pw = form.css_first("input[type=password]") is not None
        scheme = urlsplit(action).scheme
        if scheme == "http" and not http_page:  # HTTP pages: covered by TLS + password check
            insecure.append((action, has_pw))
        # Another *site*: a scheme-only change (http form on an https page) is the
        # HTTP-action finding above, not a cross-origin post.
        if scheme in ("http", "https") and _origin(action)[1] != page_origin[1]:
            cross.append((action, has_pw))
    if insecure:
        pw = any(p for _, p in insecure)
        out.append(
            _finding(
                page,
                "RND-FORM-HTTP-ACTION",
                "Form submits over HTTP" + (" (with a password field)" if pw else ""),
                S.HIGH if pw else S.MEDIUM,
                C.HIGH,
                [Evidence("form", a, "action") for a, _ in insecure],
                "Submitted data is sent unencrypted even if the page itself is HTTPS.",
                "Point form actions at https:// URLs.",
                ("CWE-319", A02),
            )
        )
    if cross:
        pw = any(p for _, p in cross)
        out.append(
            _finding(
                page,
                "RND-FORM-CROSS-ORIGIN",
                "Form posts to another origin",
                S.MEDIUM if pw else S.LOW,
                C.MEDIUM,
                [Evidence("form", a, "action") for a, _ in cross],
                "Entered data goes to another site; fine for known processors, risky otherwise.",
                "Confirm each external form target is intended and trusted.",
                ("CWE-201",),
            )
        )
    return out


def check_sri(page: RenderedPage) -> list[Finding]:
    """Third-party scripts/styles without Subresource Integrity, or SRI without crossorigin."""
    if (tree := _tree(page)) is None:
        return []
    origin = _origin(page.final_url)
    no_sri, no_cors, styles = [], [], []
    for node in tree.css("script[src]"):
        src = urljoin(page.final_url, node.attributes.get("src") or "")
        if not src.startswith(("http://", "https://")) or _origin(src) == origin:
            continue
        if not node.attributes.get("integrity"):
            no_sri.append(src)
        elif "crossorigin" not in node.attributes:
            no_cors.append(src)
    for node in tree.css("link[href]"):
        if "stylesheet" not in (node.attributes.get("rel") or "").lower():
            continue
        href = urljoin(page.final_url, node.attributes.get("href") or "")
        if href.startswith(("http://", "https://")) and _origin(href) != origin:
            if not node.attributes.get("integrity"):
                styles.append(href)
    out = []
    if no_sri:
        out.append(
            _finding(
                page,
                "RND-SCRIPT-NO-SRI",
                "Third-party script loaded without SRI",
                S.LOW,
                C.HIGH,
                [Evidence("script", u, "src") for u in dict.fromkeys(no_sri)],
                "If the third party (or its CDN) is compromised, its code runs with this site's "
                "privileges.",
                'Add integrity="sha384-..." crossorigin="anonymous", or self-host.',
                ("CWE-353", "CWE-829", A08),
            )
        )
    if no_cors:
        out.append(
            _finding(
                page,
                "RND-SRI-NO-CROSSORIGIN",
                "SRI on a cross-origin script without crossorigin",
                S.LOW,
                C.HIGH,
                [Evidence("script", u, "src") for u in dict.fromkeys(no_cors)],
                "Without CORS mode the integrity check fails, so browsers block the script.",
                'Add crossorigin="anonymous" next to integrity.',
                ("CWE-353",),
            )
        )
    if styles:
        out.append(
            _finding(
                page,
                "RND-STYLE-NO-SRI",
                "Third-party stylesheet loaded without SRI",
                S.INFO,
                C.HIGH,
                [Evidence("stylesheet", u, "href") for u in dict.fromkeys(styles)],
                "A compromised stylesheet can deface the page or exfiltrate data via CSS.",
                "Add integrity + crossorigin, or self-host.",
                ("CWE-353",),
            )
        )
    return out


def check_blank_targets(page: RenderedPage) -> list[Finding]:
    """Cross-origin target=_blank links without rel=noopener/noreferrer."""
    if (tree := _tree(page)) is None:
        return []
    origin = _origin(page.final_url)
    hits = []
    for a in tree.css("a[target]"):
        if (a.attributes.get("target") or "").lower() != "_blank":
            continue
        href = urljoin(page.final_url, a.attributes.get("href") or "")
        rel = (a.attributes.get("rel") or "").lower().split()
        if href.startswith(("http://", "https://")) and _origin(href) != origin:
            if "noopener" not in rel and "noreferrer" not in rel:
                hits.append(href)
    if not hits:
        return []
    return [
        _finding(
            page,
            "RND-BLANK-NOOPENER",
            "target=_blank links without rel=noopener",
            S.INFO,
            C.HIGH,
            [Evidence("link", u, "href") for u in dict.fromkeys(hits)],
            "Modern browsers imply noopener; older ones let the opened page navigate this tab "
            "(reverse tabnabbing).",
            'Add rel="noopener noreferrer".',
            ("CWE-1022",),
        )
    ]


def check_dom_secrets(page: RenderedPage) -> list[Finding]:
    """Known secret formats in the rendered markup outside <script> (evidence is redacted)."""
    if not page.dom:
        return []
    markup = markup_without_scripts(page.dom)  # script contents: JS-SECRET-* (checks/js.py)
    out = []
    for pat in PATTERNS:
        if pat.name == "generic_secret":
            continue  # too noisy in markup; JS analysis (step 14) handles assignments
        matches = list(pat.regex.finditer(markup))
        if not matches:
            continue
        snippets = [
            re.sub(r"\s+", " ", markup[max(0, m.start() - 30) : m.end() + 10]) for m in matches
        ]
        out.append(
            _finding(
                page,
                f"RND-SECRET-{pat.name.upper()}",
                f"Secret visible in rendered page ({pat.name})",
                secret_severity(pat.name),
                C.MEDIUM,
                [Evidence("dom", s, pat.name) for s in dict.fromkeys(snippets)],
                "Anyone loading the page can read it; treat it as compromised.",
                "Remove it from client-side output, rotate it, and keep secrets server-side.",
                ("CWE-200", "CWE-798"),
            )
        )
    return out


def run_rendered_checks(pages: Sequence[RenderedPage]) -> list[Finding]:
    """All rendered-content checks, grouped across pages."""
    checks = (check_mixed_content, check_forms, check_sri, check_blank_targets, check_dom_secrets)
    return group_findings(f for p in pages if not p.error for c in checks for f in c(p))


def reconcile_meta_csp(findings: list[Finding], pages: Sequence[RenderedPage]) -> list[Finding]:
    """Pages whose rendered DOM carries a <meta> CSP lose their HDR-CSP-MISSING entry and get
    the meta-CSP findings instead (covers CSPs injected by JavaScript)."""
    meta_urls: dict[str, RenderedPage] = {}
    for p in pages:
        if p.dom and any(m.strip() for m in meta_csp(p.dom)):
            meta_urls[p.url] = meta_urls[p.final_url] = p
    if not meta_urls:
        return findings
    out: list[Finding] = []
    replaced: dict[str, RenderedPage] = {}
    for f in findings:
        if f.id != "HDR-CSP-MISSING":
            out.append(f)
            continue
        keep = tuple(u for u in f.urls if u not in meta_urls)
        replaced.update({u: meta_urls[u] for u in f.urls if u in meta_urls})
        if keep:
            out.append(
                Finding(
                    f.id,
                    f.title,
                    f.severity,
                    f.confidence,
                    keep,
                    f.evidence,
                    f.impact,
                    f.remediation,
                    f.refs,
                )
            )
    for url, page in replaced.items():
        synthetic = CollectedResponse(url, 200, (("Content-Type", "text/html"),), text=page.dom)
        out += check_csp(synthetic)
    return group_findings(out)
