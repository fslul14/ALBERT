"""Runs check families over already-collected data: Python checks plus YAML rules.

Rules live in ``albert/rules/<family>.yaml`` as ``{rules: [...]}`` (top-level ``x-*`` keys are
free for YAML anchors). A rule says what to match, the finding it produces, and where it
applies. Pattern-style checks belong here; anything needing parsing or cross-field logic stays
in ``albert/checks/``. ``albert rules lint`` validates every rule.

Rule fields: ``id``, ``title``, ``severity``, ``confidence``, ``impact``, ``remediation``,
``refs`` (list), optional ``applies_to`` (``status: success|any``, ``document: bool``,
``https: bool``), optional ``escalate`` (cookie rules: ``[{cookie_name_matches, severity}]``),
and ``match`` with exactly one of:

- ``header: <Name>`` + one of ``missing_or_not: [ok values]`` (fires if absent or first value
  not listed), ``missing_or: [bad values]`` (absent or listed), ``present: true`` (+ ``unless``)
- ``headers: [names]`` + one of ``each_present: true`` (every occurrence, received order),
  ``value_matches: <regex>``, ``value_not_matches: <regex>``
- ``cookie: {flag_missing: secure|httponly, samesite: missing|none|lax|strict,
  name_matches / name_not_matches: <regex>}`` (all given conditions must hold). Ids/titles may
  use ``{cookie_id}`` / ``{cookie}``; cookie rule ids must, so each cookie stays distinct.
"""

from __future__ import annotations

import hashlib
import re
import string
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from albert.checks.cookies import (
    SetCookie,
    cookie_evidence,
    cookie_id_part,
    parse_set_cookie,
    run_cookie_checks,
)
from albert.checks.cors import run_cors_checks
from albert.checks.disclosure import run_disclosure_checks
from albert.checks.headers import header_evidence, run_header_checks
from albert.checks.security_txt import run_security_txt_checks
from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    ScanResult,
    Severity,
    group_findings,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

CheckFamily = Callable[[Sequence[CollectedResponse]], list[Finding]]

FAMILIES: dict[str, CheckFamily] = {
    "headers": run_header_checks,
    "cookies": run_cookie_checks,
    "cors": run_cors_checks,
    "disclosure": run_disclosure_checks,
    "security_txt": run_security_txt_checks,
}

_RULE_KEYS = {
    "id",
    "title",
    "severity",
    "confidence",
    "impact",
    "remediation",
    "refs",
    "applies_to",
    "match",
    "escalate",
}
_TEXT_FIELDS = ("id", "title", "severity", "confidence", "impact", "remediation")
_HEADER_MODES = {"missing_or_not", "missing_or", "present"}
_HEADERS_MODES = {"each_present", "value_matches", "value_not_matches"}
_COOKIE_KEYS = {"flag_missing", "samesite", "name_matches", "name_not_matches"}
_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]*(?:\{cookie_id\})?$")


class RuleError(Exception):
    """A rule file or rule is invalid."""


@dataclass(frozen=True)
class Rule:
    """One validated rule."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    impact: str
    remediation: str
    refs: tuple[str, ...]
    family: str
    source: str
    match: dict[str, Any] = field(hash=False, compare=False)
    applies_to: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    regexes: dict[str, re.Pattern[str]] = field(default_factory=dict, hash=False, compare=False)
    escalate: tuple[tuple[re.Pattern[str], Severity], ...] = ()


# --- parsing / validation -----------------------------------------------------------------


def _regex(pattern: Any) -> re.Pattern[str]:
    if not isinstance(pattern, str):
        raise RuleError(f"regex must be a string, got {pattern!r}")
    try:
        return re.compile(pattern)
    except re.error as e:
        raise RuleError(f"bad regex {pattern!r}: {e}") from None


def _severity(value: Any, what: str) -> Severity:
    try:
        return Severity.from_label(str(value))
    except KeyError:
        raise RuleError(f"{what} {value!r} is not one of: {_labels(Severity)}") from None


def _confidence(value: Any) -> Confidence:
    try:
        return Confidence.from_label(str(value))
    except KeyError:
        raise RuleError(f"confidence {value!r} is not one of: {_labels(Confidence)}") from None


def _labels(cls: type[Severity] | type[Confidence]) -> str:
    return ", ".join(x.label for x in cls)


def _fields(template: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(template) if f is not None}


def _exactly_one(match: dict[str, Any], modes: set[str], what: str) -> str:
    found = modes & set(match)
    if len(found) != 1:
        raise RuleError(f"{what} needs exactly one of: {', '.join(sorted(modes))}")
    return found.pop()


def _parse_match(match: Any) -> tuple[str, dict[str, re.Pattern[str]]]:
    if not isinstance(match, dict):
        raise RuleError("match must be a mapping")
    kinds = [k for k in ("header", "headers", "cookie") if k in match]
    if len(kinds) != 1:
        raise RuleError("match needs exactly one of: header, headers, cookie")
    kind = kinds[0]
    regexes: dict[str, re.Pattern[str]] = {}
    if kind == "header":
        if not isinstance(match["header"], str) or not match["header"]:
            raise RuleError("match.header must be a header name")
        mode = _exactly_one(match, _HEADER_MODES, "match.header")
        if mode != "present" and not isinstance(match[mode], list):
            raise RuleError(f"match.{mode} must be a list of values")
        allowed = {"header", "unless", mode}
    elif kind == "headers":
        names = match["headers"]
        if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
            raise RuleError("match.headers must be a non-empty list of header names")
        mode = _exactly_one(match, _HEADERS_MODES, "match.headers")
        if mode != "each_present":
            regexes["value"] = _regex(match[mode])
        allowed = {"headers", mode}
    else:
        cond = match["cookie"]
        if not isinstance(cond, dict) or not cond or set(cond) - _COOKIE_KEYS:
            raise RuleError(f"match.cookie may only use: {', '.join(sorted(_COOKIE_KEYS))}")
        if "flag_missing" not in cond and "samesite" not in cond:
            raise RuleError("match.cookie needs flag_missing and/or samesite")
        if cond.get("flag_missing", "secure") not in ("secure", "httponly"):
            raise RuleError("match.cookie.flag_missing must be secure or httponly")
        if cond.get("samesite", "missing") not in ("missing", "none", "lax", "strict"):
            raise RuleError("match.cookie.samesite must be missing, none, lax or strict")
        for key in ("name_matches", "name_not_matches"):
            if key in cond:
                regexes[key] = _regex(cond[key])
        allowed = {"cookie"}
    if extra := set(match) - allowed:
        raise RuleError(f"unexpected match key(s): {', '.join(sorted(extra))}")
    return kind, regexes


def _parse_escalate(raw: Any, kind: str) -> tuple[tuple[re.Pattern[str], Severity], ...]:
    steps = []
    for step in raw or []:
        if kind != "cookie" or not isinstance(step, dict):
            raise RuleError("escalate is only for cookie rules")
        if set(step) != {"cookie_name_matches", "severity"}:
            raise RuleError("escalate entries need exactly cookie_name_matches + severity")
        steps.append((_regex(step["cookie_name_matches"]), _severity(step["severity"], "escalate")))
    return tuple(steps)


def _parse_applies(applies: Any) -> dict[str, Any]:
    if not isinstance(applies, dict) or set(applies) - {"status", "document", "https"}:
        raise RuleError("applies_to may only use: status, document, https")
    if applies.get("status", "any") not in ("any", "success"):
        raise RuleError("applies_to.status must be any or success")
    if any(not isinstance(applies.get(k, False), bool) for k in ("document", "https")):
        raise RuleError("applies_to.document/https must be true or false")
    return applies


def _parse_rule(raw: Any, family: str, source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError("rule must be a mapping")
    if extra := set(raw) - _RULE_KEYS:
        raise RuleError(f"unknown key(s): {', '.join(sorted(map(str, extra)))}")
    for key in _TEXT_FIELDS:
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise RuleError(f"{key} is required and must be a non-empty string")
    if "match" not in raw:
        raise RuleError("match is required")
    kind, regexes = _parse_match(raw["match"])
    rid, title = raw["id"], raw["title"]
    if not _ID.match(rid):
        raise RuleError(f"id {rid!r} must be UPPER-KEBAB (optionally ending in {{cookie_id}})")
    allowed = {"cookie", "cookie_id"} if kind == "cookie" else set()
    if bad := (_fields(rid) | _fields(title)) - allowed:
        raise RuleError(f"unknown placeholder(s): {', '.join(sorted(bad))}")
    if kind == "cookie" and "{cookie_id}" not in rid:
        raise RuleError("cookie rule ids must contain {cookie_id} so cookies stay distinct")
    refs = raw.get("refs", [])
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
        raise RuleError("refs must be a list of strings")
    return Rule(
        id=rid,
        title=title,
        severity=_severity(raw["severity"], "severity"),
        confidence=_confidence(raw["confidence"]),
        impact=raw["impact"].strip(),
        remediation=raw["remediation"].strip(),
        refs=tuple(refs),
        family=family,
        source=source,
        match=raw["match"],
        applies_to=_parse_applies(raw.get("applies_to", {})),
        regexes=regexes,
        escalate=_parse_escalate(raw.get("escalate"), kind),
    )


def lint_rules(directory: Path = RULES_DIR) -> tuple[list[Rule], list[str]]:
    """Parse every rule file; return the valid rules and a list of problems."""
    rules: list[Rule] = []
    problems: list[str] = []
    seen: dict[str, str] = {}
    files = sorted(directory.glob("*.yaml"))
    if not files:
        problems.append(f"{directory}: no rule files")
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            problems.append(f"{path.name}: invalid YAML: {e}")
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            problems.append(f"{path.name}: expected a mapping with a 'rules' list")
            continue
        if extra := [k for k in doc if k != "rules" and not str(k).startswith("x-")]:
            problems.append(f"{path.name}: unknown top-level key(s): {', '.join(map(str, extra))}")
        for i, raw in enumerate(doc["rules"], 1):
            rid = raw.get("id") if isinstance(raw, dict) else None
            where = f"{path.name} rule #{i}" + (f" ({rid})" if rid else "")
            try:
                rule = _parse_rule(raw, path.stem, path.name)
            except RuleError as e:
                problems.append(f"{where}: {e}")
                continue
            if rule.id in seen:
                problems.append(f"{where}: duplicate id (first in {seen[rule.id]})")
                continue
            seen[rule.id] = where
            rules.append(rule)
    return rules, problems


def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    """Valid rules, or RuleError listing every problem."""
    rules, problems = lint_rules(directory)
    if problems:
        raise RuleError("; ".join(problems))
    return rules


@lru_cache(maxsize=1)
def default_rules() -> tuple[Rule, ...]:
    """The bundled rules (loaded once)."""
    return tuple(load_rules())


def rules_version(directory: Path = RULES_DIR) -> str:
    """'<n> rules, sha256:<12 hex>' over the rule files, for report headers."""
    digest = hashlib.sha256()
    for path in sorted(directory.glob("*.yaml")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    count = len(default_rules()) if directory == RULES_DIR else len(load_rules(directory))
    return f"{count} rules, sha256:{digest.hexdigest()[:12]}"


# --- evaluation ---------------------------------------------------------------------------


def _applies(rule: Rule, resp: CollectedResponse) -> bool:
    a = rule.applies_to
    if a.get("status", "any") == "success" and not 200 <= resp.status < 300:
        return False
    if a.get("document") and not resp.is_document:
        return False
    return not (a.get("https") and not resp.is_https)


def _finding(
    rule: Rule,
    resp: CollectedResponse,
    evidence: Evidence,
    *,
    severity: Severity | None = None,
    **fmt: str,
) -> Finding:
    return Finding(
        id=rule.id.format(**fmt) if fmt else rule.id,
        title=rule.title.format(**fmt) if fmt else rule.title,
        severity=severity or rule.severity,
        confidence=rule.confidence,
        urls=(resp.url,),
        evidence=(evidence,),
        impact=rule.impact,
        remediation=rule.remediation,
        refs=rule.refs,
    )


def _cookie_matches(rule: Rule, c: SetCookie) -> bool:
    cond = rule.match["cookie"]
    if (flag := cond.get("flag_missing")) and flag in c.flags:
        return False
    if (want := cond.get("samesite")) and (c.samesite or "missing") != want:
        return False
    if (rx := rule.regexes.get("name_matches")) and not rx.search(c.name):
        return False
    return not ((rx := rule.regexes.get("name_not_matches")) and rx.search(c.name))


def _eval_cookies(rule: Rule, resp: CollectedResponse) -> list[Finding]:
    out = []
    for header in resp.header_all("set-cookie"):
        c = parse_set_cookie(header)
        if c is None or not _cookie_matches(rule, c):
            continue
        severity = next((s for rx, s in rule.escalate if rx.search(c.name)), None)
        out.append(
            _finding(
                rule,
                resp,
                cookie_evidence(c),
                severity=severity,
                cookie=c.name,
                cookie_id=cookie_id_part(c.name),
            )
        )
    return out


def _eval_header(rule: Rule, resp: CollectedResponse) -> list[Finding]:
    m = rule.match
    name = m["header"]
    value = resp.header(name)
    norm = value.strip().lower() if value is not None else None
    if "missing_or_not" in m:
        fire = norm is None or norm not in {str(v).lower() for v in m["missing_or_not"]}
    elif "missing_or" in m:
        fire = norm is None or norm in {str(v).lower() for v in m["missing_or"]}
    else:
        fire = norm is not None and norm not in {str(v).lower() for v in m.get("unless", [])}
    return [_finding(rule, resp, header_evidence(name, value))] if fire else []


def evaluate(rule: Rule, resp: CollectedResponse) -> list[Finding]:
    """Findings one rule produces for one response."""
    if not _applies(rule, resp):
        return []
    m = rule.match
    if "cookie" in m:
        return _eval_cookies(rule, resp)
    if "header" in m:
        return _eval_header(rule, resp)
    if m.get("each_present"):
        wanted = {n.lower() for n in m["headers"]}
        return [
            _finding(rule, resp, header_evidence(k, v))
            for k, v in resp.headers
            if k.lower() in wanted
        ]
    rx, negate = rule.regexes["value"], "value_not_matches" in m
    return [
        _finding(rule, resp, header_evidence(name, v))
        for name in m["headers"]
        for v in resp.header_all(name)
        if bool(rx.search(v)) != negate
    ]


def run_family(
    name: str, responses: Sequence[CollectedResponse], rules: Iterable[Rule] | None = None
) -> list[Finding]:
    """A family's Python checks plus its YAML rules, grouped across pages."""
    python = FAMILIES[name](responses) if name in FAMILIES else []
    family_rules = [r for r in (default_rules() if rules is None else rules) if r.family == name]
    if not family_rules:
        return python
    from_rules = [f for resp in responses for r in family_rules for f in evaluate(r, resp)]
    return group_findings([*python, *from_rules])


def run_checks(
    result: ScanResult,
    responses: Sequence[CollectedResponse],
    families: Iterable[str] | None = None,
) -> None:
    """Run the named families (default: all) and record findings + checks run on ``result``."""
    if not result.rules_version:
        result.rules_version = rules_version()
    for name in families or FAMILIES:
        result.findings.extend(run_family(name, responses))
        result.checks_run.append(name)
