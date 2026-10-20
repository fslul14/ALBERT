"""Technology fingerprinting from signals already collected. Pure; never fetches.

Signatures live in ``albert/data/fingerprints.yaml`` (Wappalyzer-style, extendable as data).
Detections are recorded for the report appendix, not reported as findings; judging them
(CVE matching) is a separate step.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from selectolax.lexbor import LexborHTMLParser

from albert.core.models import CollectedResponse, Confidence, RenderedPage, TechDetection

SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "fingerprints.yaml"

C = Confidence
_KEYED = ("headers", "meta")  # {name: regex}
_LISTED = ("cookies", "html", "script_src", "script_body", "url")  # [regex]
_TECH_KEYS = {"name", "category", "cpe", "npm", "implies", "favicon_md5", *_KEYED, *_LISTED}
# Where a captured version is an exact version string (High) vs read from a path (Low).
_EXACT_VERSION = {"headers", "meta", "html", "script_body"}
_PRESENCE = {"headers": C.HIGH, "meta": C.HIGH}  # others: Medium


class SignatureError(Exception):
    """The signature file is invalid."""


@dataclass(frozen=True)
class Technology:
    """One technology's signatures."""

    name: str
    category: str
    cpe: str | None = None
    npm: str | None = None
    implies: tuple[str, ...] = ()
    keyed: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = field(default_factory=dict)
    listed: dict[str, tuple[re.Pattern[str], ...]] = field(default_factory=dict)
    favicon_md5: frozenset[str] = frozenset()


@dataclass(frozen=True)
class FingerprintInput:
    """Everything collected that fingerprinting may look at."""

    responses: Sequence[CollectedResponse] = ()  # pages, redirects, robots, sitemaps, scripts
    scripts: Sequence[CollectedResponse] = ()  # script bodies (crawler + renderer)
    rendered: Sequence[RenderedPage] = ()
    favicons: Sequence[tuple[str, bytes]] = ()  # (url, bytes) of icons pages referenced


# --- signatures ---------------------------------------------------------------------------


def _compile(pattern: Any, where: str) -> re.Pattern[str]:
    if not isinstance(pattern, str):
        raise SignatureError(f"{where}: pattern must be a string")
    try:
        return re.compile(pattern, re.I)
    except re.error as e:
        raise SignatureError(f"{where}: bad regex {pattern!r}: {e}") from None


def _parse(raw: Any, i: int) -> Technology:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise SignatureError(f"technology #{i}: needs a name")
    where = f"technology #{i} ({raw['name']})"
    if extra := set(raw) - _TECH_KEYS:
        raise SignatureError(f"{where}: unknown key(s): {', '.join(sorted(extra))}")
    if not isinstance(raw.get("category"), str):
        raise SignatureError(f"{where}: needs a category")
    keyed = {}
    for kind in _KEYED:
        spec = raw.get(kind, {})
        if not isinstance(spec, dict):
            raise SignatureError(f"{where}: {kind} must be a mapping")
        keyed[kind] = tuple((str(k), _compile(v, f"{where} {kind}.{k}")) for k, v in spec.items())
    listed = {}
    for kind in _LISTED:
        spec = raw.get(kind, [])
        if not isinstance(spec, list):
            raise SignatureError(f"{where}: {kind} must be a list")
        listed[kind] = tuple(_compile(v, f"{where} {kind}") for v in spec)
    favicons = raw.get("favicon_md5", [])
    if not isinstance(favicons, list) or not all(
        isinstance(h, str) and re.fullmatch(r"[0-9a-f]{32}", h) for h in favicons
    ):
        raise SignatureError(f"{where}: favicon_md5 must be a list of 32-hex md5 strings")
    return Technology(
        name=raw["name"],
        category=raw["category"],
        cpe=raw.get("cpe"),
        npm=raw.get("npm"),
        implies=tuple(raw.get("implies", [])),
        keyed=keyed,
        listed=listed,
        favicon_md5=frozenset(favicons),
    )


def lint_signatures(path: Path = SIGNATURES_PATH) -> tuple[list[Technology], list[str]]:
    """Parse the signature file; return valid technologies and a list of problems."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        return [], [f"{path.name}: {e}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("technologies"), list):
        return [], [f"{path.name}: expected a mapping with a 'technologies' list"]
    techs, problems, names = [], [], set()
    for i, raw in enumerate(doc["technologies"], 1):
        try:
            tech = _parse(raw, i)
        except SignatureError as e:
            problems.append(f"{path.name}: {e}")
            continue
        if tech.name in names:
            problems.append(f"{path.name}: duplicate technology {tech.name!r}")
            continue
        names.add(tech.name)
        techs.append(tech)
    for tech in techs:
        for implied in tech.implies:
            if implied not in names:
                problems.append(f"{path.name}: {tech.name} implies unknown {implied!r}")
    return techs, problems


@lru_cache(maxsize=1)
def default_signatures() -> tuple[Technology, ...]:
    """The bundled signatures (loaded once); raises SignatureError if invalid."""
    techs, problems = lint_signatures()
    if problems:
        raise SignatureError("; ".join(problems))
    return tuple(techs)


# --- detection ----------------------------------------------------------------------------


@dataclass
class _Hit:
    version: str | None
    confidence: Confidence
    evidence: str
    url: str


def _clip(s: str, n: int = 100) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[:n] + "..."


def _version(m: re.Match[str]) -> str | None:
    if "version" in m.re.groupindex and m.group("version"):
        return m.group("version").rstrip(".")
    return None


def _confidence(kind: str, version: str | None) -> Confidence:
    if version:
        return C.HIGH if kind in _EXACT_VERSION else C.LOW
    return _PRESENCE.get(kind, C.MEDIUM)


def _documents(data: FingerprintInput) -> list[tuple[str, str]]:
    """(url, html) for crawled HTML pages and rendered DOMs."""
    docs = [(r.url, r.text) for r in data.responses if r.is_document and r.text]
    docs += [(p.final_url, p.dom) for p in data.rendered if p.dom]
    return docs


def _script_srcs(data: FingerprintInput, docs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """(page url, script url) from markup and from rendered pages' script requests."""
    from urllib.parse import urljoin

    out = []
    for page, html in docs:
        for node in LexborHTMLParser(html).css("script[src]"):
            src = (node.attributes.get("src") or "").strip()
            if src:
                out.append((page, urljoin(page, src)))
    for p in data.rendered:
        out += [(p.final_url, r.url) for r in p.requests if r.resource_type == "script"]
    return list(dict.fromkeys(out))


def _metas(html: str) -> list[tuple[str, str]]:
    return [
        ((n.attributes.get("name") or "").strip().lower(), n.attributes.get("content") or "")
        for n in LexborHTMLParser(html).css("meta[name][content]")
    ]


def _scan(tech: Technology, data: FingerprintInput, ctx: dict[str, Any]) -> list[_Hit]:
    hits: list[_Hit] = []

    def add(kind: str, m: re.Match[str], what: str, url: str) -> None:
        v = _version(m)
        hits.append(_Hit(v, _confidence(kind, v), what, url))

    for name, rx in tech.keyed["headers"]:
        for r in data.responses:
            for value in r.header_all(name):
                if m := rx.search(value):
                    add("headers", m, f"header {name}: {_clip(value)}", r.url)
    for rx in tech.listed["cookies"]:
        for url, cookie in ctx["cookies"]:
            if m := rx.search(cookie):
                add("cookies", m, f"cookie {cookie}", url)
    for name, rx in tech.keyed["meta"]:
        for url, metas in ctx["metas"]:
            for meta_name, content in metas:
                if meta_name == name.lower() and (m := rx.search(content)):
                    add("meta", m, f"meta {meta_name}: {_clip(content)}", url)
    for rx in tech.listed["html"]:
        for url, html in ctx["docs"]:
            if m := rx.search(html):
                add("html", m, f"markup: {_clip(m.group(0))}", url)
    for rx in tech.listed["script_src"]:
        for page, src in ctx["srcs"]:
            if m := rx.search(src):
                add("script_src", m, f"script src {_clip(src)}", page)
    for rx in tech.listed["script_body"]:
        for s in data.scripts:
            if m := rx.search(s.text):
                add("script_body", m, f"script {_clip(s.url, 60)}: {_clip(m.group(0), 60)}", s.url)
    for rx in tech.listed["url"]:
        for r in data.responses:
            if r.is_document and (m := rx.search(r.url)):
                add("url", m, f"page URL {_clip(r.url)}", r.url)
    for url, digest in ctx["favicons"]:
        if digest in tech.favicon_md5:
            hits.append(_Hit(None, C.MEDIUM, f"favicon md5 {digest}", url))
    return hits


def _merge(tech: Technology, hits: list[_Hit]) -> list[TechDetection]:
    """One detection per version seen; unversioned evidence folds into the best one."""
    by_version: dict[str | None, list[_Hit]] = {}
    for h in hits:
        by_version.setdefault(h.version, []).append(h)
    unversioned = by_version.pop(None, [])
    if not by_version:
        by_version[None] = unversioned
        unversioned = []
    ranked = sorted(by_version, key=lambda v: -max(h.confidence for h in by_version[v]))
    by_version[ranked[0]] += unversioned  # supporting presence signals
    out = []
    for version in ranked:
        group = by_version[version]
        out.append(
            TechDetection(
                name=tech.name,
                category=tech.category,
                version=version,
                confidence=max(h.confidence for h in group),
                evidence=tuple(dict.fromkeys(h.evidence for h in group))[:10],
                urls=tuple(dict.fromkeys(h.url for h in group))[:10],
                cpe=tech.cpe,
                npm=tech.npm,
            )
        )
    return out


def favicon_md5(data: bytes) -> str:
    """MD5 of favicon bytes (OWASP favicon-database format)."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def detect_technologies(
    data: FingerprintInput, signatures: Iterable[Technology] | None = None
) -> list[TechDetection]:
    """All technologies the collected signals reveal, sorted by category then name."""
    techs = list(default_signatures() if signatures is None else signatures)
    docs = _documents(data)
    ctx: dict[str, Any] = {
        "docs": docs,
        "metas": [(url, _metas(html)) for url, html in docs],
        "srcs": _script_srcs(data, docs),
        "cookies": [
            (r.url, h.split("=", 1)[0].strip())
            for r in data.responses
            for h in r.header_all("set-cookie")
            if "=" in h
        ],
        "favicons": [(url, favicon_md5(raw)) for url, raw in data.favicons],
    }
    found: dict[str, list[TechDetection]] = {}
    for tech in techs:
        if hits := _scan(tech, data, ctx):
            found[tech.name] = _merge(tech, hits)
    by_name = {t.name: t for t in techs}
    for name in list(found):
        for implied in by_name[name].implies:
            if implied not in found and implied in by_name:
                t = by_name[implied]
                found[implied] = [
                    TechDetection(
                        t.name, t.category, None, C.LOW, (f"implied by {name}",), (), t.cpe, t.npm
                    )
                ]
    return sorted(
        (d for ds in found.values() for d in ds),
        key=lambda d: (d.category, d.name.lower(), d.version or ""),
    )
