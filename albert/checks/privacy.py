"""Privacy / tracking observations. Pure over data already collected; never fetches.

Main input: the renderer's recorded request attempts (step 11), including the third-party
loads it refused. Albert never contacts a tracker; it reports what the page tried to load.
Without rendering, <script>/<img>/<iframe> references in crawled HTML are used (lower
confidence). Signatures live in ``albert/data/trackers.yaml``.

Limit: third-party Set-Cookie is never observable (third-party responses are never fetched).
"Tracking before consent" is inferred from tracker loads attempted on first load (Albert never
interacts with a page, so nothing was consented to) and from first-party tracking cookies.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import yaml
from selectolax.lexbor import LexborHTMLParser

from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    RenderedPage,
    Severity,
)
from albert.core.scope import registrable_domain

TRACKERS_PATH = Path(__file__).resolve().parent.parent / "data" / "trackers.yaml"
TRACKING = {"analytics", "advertising", "social", "session-replay", "fingerprinting", "tag-manager"}
CATEGORIES = TRACKING | {"monitoring", "consent"}
S, C = Severity, Confidence
_KEYS = {"name", "category", "domains", "cookies", "dom", "script_body"}
_HOST = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
_STATIC_REFS = (
    ("script[src]", "src"),
    ("img[src]", "src"),
    ("iframe[src]", "src"),
    ("link[href]", "href"),
    ("source[src]", "src"),
    ("embed[src]", "src"),
)
_JS_TYPES = {"", "text/javascript", "application/javascript", "module"}
_PRIVACY_LINK = re.compile(
    r"privacy|datenschutz|confidentialit|privacidad|privacit|privacybeleid|integritet|"
    r"polityka-prywatnosci|cookie[-_ ]?policy",
    re.I,
)
_GENERIC_BANNER = re.compile(
    r"cookie[-_]?(?:consent|banner|notice|bar|popup|law)|gdpr[-_]?(?:banner|consent|cookie)|"
    r"consent[-_]?(?:banner|modal|popup|manager)",
    re.I,
)
_CANVAS_FP = (
    re.compile(r"toDataURL|getImageData"),
    re.compile(r"WEBGL_debug_renderer_info|UNMASKED_RENDERER_WEBGL"),
    re.compile(r"OfflineAudioContext|createOscillator"),
)


class TrackerSignatureError(Exception):
    """The tracker signature file is invalid."""


@dataclass(frozen=True)
class Service:
    """One tracker / consent manager / fingerprinting vendor."""

    name: str
    category: str
    domains: tuple[str, ...] = ()
    cookies: tuple[re.Pattern[str], ...] = ()
    dom: tuple[str, ...] = ()
    script_body: tuple[re.Pattern[str], ...] = ()

    def owns(self, host: str) -> bool:
        return any(host == d or host.endswith("." + d) for d in self.domains)


@dataclass(frozen=True)
class PrivacyInput:
    """Everything collected that the privacy checks may look at."""

    target_url: str
    rendered: Sequence[RenderedPage] = ()
    responses: Sequence[CollectedResponse] = ()  # crawled pages (static HTML, Set-Cookie)
    scripts: Sequence[CollectedResponse] = ()  # collected JS bodies (first-party)


# --- signatures -------------------------------------------------------------------------------


def _parse(raw: Any, i: int) -> Service:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise TrackerSignatureError(f"service #{i}: needs a name")
    where = f"service #{i} ({raw['name']})"
    if extra := set(raw) - _KEYS:
        raise TrackerSignatureError(f"{where}: unknown key(s): {', '.join(sorted(extra))}")
    if raw.get("category") not in CATEGORIES:
        raise TrackerSignatureError(
            f"{where}: category must be one of {', '.join(sorted(CATEGORIES))}"
        )
    lists = {k: raw.get(k, []) for k in ("domains", "cookies", "dom", "script_body")}
    if not all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in lists.values()):
        raise TrackerSignatureError(
            f"{where}: domains/cookies/dom/script_body must be string lists"
        )
    if not any(lists.values()):
        raise TrackerSignatureError(f"{where}: needs at least one signal")
    if bad := [d for d in lists["domains"] if not _HOST.match(d)]:
        raise TrackerSignatureError(f"{where}: bad domain(s): {', '.join(bad)}")
    try:
        cookies = tuple(re.compile(p) for p in lists["cookies"])
        bodies = tuple(re.compile(p) for p in lists["script_body"])
    except re.error as e:
        raise TrackerSignatureError(f"{where}: bad regex: {e}") from None
    for sel in lists["dom"]:
        try:
            LexborHTMLParser("<p></p>").css(sel)
        except Exception as e:  # selectolax raises its own error types
            raise TrackerSignatureError(f"{where}: bad CSS selector {sel!r}: {e}") from None
    return Service(
        raw["name"], raw["category"], tuple(lists["domains"]), cookies, tuple(lists["dom"]), bodies
    )


def lint_trackers(path: Path = TRACKERS_PATH) -> tuple[list[Service], list[str]]:
    """Parse the tracker file; return valid services and problems."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        return [], [f"{path.name}: {e}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), list):
        return [], [f"{path.name}: expected a mapping with a 'services' list"]
    services, problems, names = [], [], set()
    for i, raw in enumerate(doc["services"], 1):
        try:
            svc = _parse(raw, i)
        except TrackerSignatureError as e:
            problems.append(f"{path.name}: {e}")
            continue
        if svc.name in names:
            problems.append(f"{path.name}: duplicate service {svc.name!r}")
            continue
        names.add(svc.name)
        services.append(svc)
    return services, problems


@lru_cache(maxsize=1)
def default_trackers() -> tuple[Service, ...]:
    services, problems = lint_trackers()
    if problems:
        raise TrackerSignatureError("; ".join(problems))
    return tuple(services)


# --- collection of observations ---------------------------------------------------------------


@dataclass
class _Observed:
    origins: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    rendered: bool = False  # True if any origin came from real request attempts

    def add(self, origin: str, page: str) -> None:
        self.origins[origin][page] += 1


def _origin(url: str) -> tuple[str, str] | None:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    return f"{p.scheme}://{p.hostname.lower()}", p.hostname.lower()


def _observe(data: PrivacyInput) -> _Observed:
    own = registrable_domain(urlsplit(data.target_url).hostname or "")
    obs = _Observed()

    def third_party(host: str) -> bool:
        return registrable_domain(host) != own

    for page in data.rendered:
        for r in page.requests:
            if (o := _origin(r.url)) and third_party(o[1]):
                obs.add(o[0], page.final_url)
                obs.rendered = True
    rendered_pages = {p.url for p in data.rendered} | {p.final_url for p in data.rendered}
    for resp in data.responses:
        if not resp.is_document or not resp.text or resp.url in rendered_pages:
            continue
        tree = LexborHTMLParser(resp.text)
        for css, attr in _STATIC_REFS:
            for node in tree.css(css):
                if (
                    css == "script[src]"
                    and (node.attributes.get("type") or "").lower() not in _JS_TYPES
                ):
                    continue  # e.g. type="text/plain" consent-gated: a browser wouldn't load it
                if (
                    css == "link[href]"
                    and "stylesheet" not in (node.attributes.get("rel") or "").lower()
                ):
                    continue
                url = urljoin(resp.url, (node.attributes.get(attr) or "").strip())
                if (o := _origin(url)) and third_party(o[1]):
                    obs.add(o[0], resp.url)
    return obs


def _documents(data: PrivacyInput) -> list[tuple[str, str]]:
    docs = [(p.final_url, p.dom) for p in data.rendered if p.dom]
    docs += [(r.url, r.text) for r in data.responses if r.is_document and r.text]
    return docs


# --- findings ---------------------------------------------------------------------------------


def _finding(
    fid: str,
    title: str,
    sev: Severity,
    conf: Confidence,
    urls: Sequence[str],
    evidence: Sequence[Evidence],
    impact: str,
    fix: str,
    refs: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        fid,
        title,
        sev,
        conf,
        tuple(dict.fromkeys(urls))[:20] or ("(site-wide)",),
        tuple(evidence)[:40],
        impact,
        fix,
        refs,
    )


def run_privacy_checks(
    data: PrivacyInput, services: Sequence[Service] | None = None
) -> list[Finding]:
    """All privacy observations for the scan."""
    svcs = list(default_trackers() if services is None else services)
    obs = _observe(data)
    docs = _documents(data)
    conf = C.HIGH if obs.rendered else C.LOW
    note = (
        "attempted by the rendered page; Albert did not fetch it"
        if obs.rendered
        else ("referenced in page HTML (not rendered); Albert did not fetch it")
    )
    out: list[Finding] = []

    def owner(origin: str) -> Service | None:
        host = urlsplit(origin).hostname or ""
        return next((s for s in svcs if s.owns(host)), None)

    # Third-party origins (count + list).
    if obs.origins:
        rows = sorted(obs.origins.items(), key=lambda kv: -sum(kv[1].values()))
        ev = []
        for origin, pages in rows:
            svc = owner(origin)
            tag = f" [{svc.name}, {svc.category}]" if svc else ""
            ev.append(
                Evidence(
                    "origin",
                    f"{origin}: {sum(pages.values())} request(s) on {len(pages)} page(s){tag}",
                    note,
                )
            )
        out.append(
            _finding(
                "PRIV-THIRD-PARTY-ORIGINS",
                f"Pages load resources from {len(rows)} third-party origin(s)",
                S.INFO,
                conf,
                [p for _, pages in rows for p in pages],
                ev,
                "Each third-party origin learns the visitor's IP, browser and the page viewed.",
                "Self-host what you can; keep third parties to the ones you need.",
            )
        )

    # Known trackers among them.
    trackers: dict[str, tuple[Service, set[str], set[str]]] = {}
    for origin, pages in obs.origins.items():
        svc = owner(origin)
        if svc and svc.category in TRACKING:
            entry = trackers.setdefault(svc.name, (svc, set(), set()))
            entry[1].add(urlsplit(origin).hostname or origin)
            entry[2].update(pages)
    for s in data.scripts:
        for svc in svcs:
            if svc.category in TRACKING and any(rx.search(s.text) for rx in svc.script_body):
                entry = trackers.setdefault(svc.name, (svc, set(), set()))
                entry[1].add(f"script {s.url}")
                entry[2].add(s.url)
    if trackers:
        out.append(
            _finding(
                "PRIV-TRACKERS",
                "Known trackers / analytics on the site",
                S.INFO,
                conf,
                [p for _, _, pages in trackers.values() for p in pages],
                [
                    Evidence(
                        "tracker", f"{svc.name} ({svc.category}): {', '.join(sorted(hosts))}", note
                    )
                    for svc, hosts, _ in sorted(trackers.values(), key=lambda t: t[0].name)
                ],
                "Visitors' behavior is shared with these services.",
                "Load only what you need, and only after consent where the law requires it.",
            )
        )

    # First-party tracking cookies set by the server on first load.
    cookie_hits: dict[str, set[str]] = defaultdict(set)
    for r in data.responses:
        for header in r.header_all("set-cookie"):
            name = header.split("=", 1)[0].strip()
            for svc in svcs:
                if svc.category in TRACKING and any(rx.search(name) for rx in svc.cookies):
                    cookie_hits[f"{name} ({svc.name})"].add(r.url)

    # Fingerprinting: vendor signatures, or canvas+WebGL+audio probing in first-party JS.
    fp = [
        (svc.name, hosts) for svc, hosts, _ in trackers.values() if svc.category == "fingerprinting"
    ]
    heuristic = [s.url for s in data.scripts if all(rx.search(s.text) for rx in _CANVAS_FP)]
    if fp or heuristic:
        ev = [
            Evidence("fingerprinting", f"{n}: {', '.join(sorted(h))}", "signature") for n, h in fp
        ]
        ev += [
            Evidence("fingerprinting", "canvas + WebGL renderer + audio probing", u)
            for u in heuristic
        ]
        out.append(
            _finding(
                "PRIV-FINGERPRINTING",
                "Browser-fingerprinting script detected",
                S.LOW,
                C.MEDIUM if fp else C.LOW,
                [
                    *(
                        p
                        for svc, _, pages in trackers.values()
                        if svc.category == "fingerprinting"
                        for p in pages
                    ),
                    *heuristic,
                ],
                ev,
                "Fingerprinting identifies visitors without cookies and survives clearing them.",
                "Use it only where justified (e.g. fraud prevention), disclosed, and consented to.",
            )
        )

    # Consent mechanism and privacy policy.
    cmps = {
        svc.name
        for svc in svcs
        if svc.category == "consent"
        and (
            any(svc.owns(urlsplit(o).hostname or "") for o in obs.origins)
            or any(LexborHTMLParser(html).css_first(sel) for _, html in docs for sel in svc.dom)
        )
    }
    generic = any(
        _GENERIC_BANNER.search(
            " ".join(filter(None, (n.attributes.get("id"), n.attributes.get("class"))))
        )
        for _, html in docs
        for n in LexborHTMLParser(html).css("[id], [class]")
    )
    if cmps:
        out.append(
            _finding(
                "PRIV-CONSENT-MANAGER",
                "Consent manager detected",
                S.INFO,
                C.HIGH,
                [data.target_url],
                [Evidence("consent", name, "consent manager") for name in sorted(cmps)],
                "Informational.",
                "None.",
            )
        )
    before = [
        Evidence("tracker", f"{name} load attempted on first visit", note)
        for name in sorted(trackers)
    ]
    before += [
        Evidence("cookie", f"{c} set by the server on first visit", "Set-Cookie")
        for c in sorted(cookie_hits)
    ]
    if before:
        out.append(
            _finding(
                "PRIV-TRACKING-BEFORE-CONSENT",
                "Tracking starts before any consent",
                S.LOW,
                C.MEDIUM if obs.rendered or cookie_hits else C.LOW,
                [
                    *(p for _, _, pages in trackers.values() for p in pages),
                    *(u for urls in cookie_hits.values() for u in urls),
                ],
                before,
                "Albert never interacts with the page, so nothing was consented to; these trackers "
                "still loaded (or tracking cookies were set). Under GDPR/ePrivacy non-essential "
                "tracking needs prior consent. (Third-party cookies themselves can't be observed: "
                "Albert never fetches third-party resources.)",
                "Gate non-essential tags behind the consent manager (block until opt-in).",
                ("GDPR Art. 6/7", "ePrivacy Art. 5(3)"),
            )
        )
    if trackers and not cmps and not generic:
        out.append(
            _finding(
                "PRIV-NO-CONSENT-MECHANISM",
                "Trackers present but no consent banner detected",
                S.LOW,
                C.LOW,
                [data.target_url],
                [Evidence("consent", "no known consent manager or banner markup", "DOM/requests")],
                "Visitors may have no way to refuse tracking. (A banner injected by a third-party "
                "script Albert didn't load can be missed.)",
                "Add a consent manager that blocks trackers until consent.",
                ("GDPR Art. 7",),
            )
        )
    has_policy = any(
        _PRIVACY_LINK.search((a.attributes.get("href") or "") + " " + (a.text() or ""))
        for _, html in docs
        for a in LexborHTMLParser(html).css("a[href]")
    )
    if docs and not has_policy:
        out.append(
            _finding(
                "PRIV-NO-PRIVACY-POLICY",
                "No privacy policy link found",
                S.INFO,
                C.MEDIUM,
                [u for u, _ in docs][:5],
                [Evidence("dom", f"checked {len(docs)} page(s)", "links")],
                "Visitors can't find how their data is used (often a legal requirement).",
                "Link a privacy policy from every page (usually the footer).",
                ("GDPR Art. 13",),
            )
        )
    return out
