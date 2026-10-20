"""Rule engine: linting catches bad rules; adding a check is a YAML file, not code."""

from pathlib import Path

import pytest

from albert.cli import main
from albert.core.engine import RuleError, lint_rules, load_rules, rules_version, run_family
from albert.core.models import CollectedResponse, Severity

GOOD = """
rules:
- id: HDR-X-POWERED-BY-PRESENT
  title: X-Powered-By header present
  severity: info
  confidence: high
  impact: Reveals the framework.
  remediation: Remove it.
  refs: [CWE-497]
  match:
    header: X-Powered-By
    present: true
"""


def write(tmp_path: Path, text: str, name: str = "headers.yaml") -> Path:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_bundled_rules_are_valid() -> None:
    rules, problems = lint_rules()
    assert problems == []
    assert {r.family for r in rules} == {"headers", "cookies"}
    assert len({r.id for r in rules}) == len(rules)
    assert rules_version().startswith(f"{len(rules)} rules, sha256:")


def test_new_check_is_just_a_rule(tmp_path: Path) -> None:
    rules = load_rules(write(tmp_path, GOOD))
    resp = CollectedResponse("https://x.test/", 200, (("X-Powered-By", "Express"),))
    found = [f for f in run_family("headers", [resp], rules) if f.id == "HDR-X-POWERED-BY-PRESENT"]
    (f,) = found
    assert f.severity is Severity.INFO and f.evidence[0].value == "Express"


@pytest.mark.parametrize(
    ("mutation", "problem"),
    [
        (("severity: info", "severity: catastrophic"), "is not one of"),
        (("confidence: high", "confidence: sure"), "is not one of"),
        (("  impact: Reveals the framework.\n", ""), "impact is required"),
        (
            ("    present: true", "    present: true\n    value_matches: '('"),
            "unexpected match key",
        ),
        (("id: HDR-X-POWERED-BY-PRESENT", "id: lower-case"), "UPPER-KEBAB"),
        (("  refs: [CWE-497]", "  refs: CWE-497\n  colour: red"), "unknown key"),
        (
            (
                "    header: X-Powered-By\n    present: true",
                "    headers: [a]\n    value_matches: '(['",
            ),
            "bad regex",
        ),
    ],
)
def test_lint_catches(tmp_path: Path, mutation: tuple[str, str], problem: str) -> None:
    old, new = mutation
    assert old in GOOD
    _, problems = lint_rules(write(tmp_path, GOOD.replace(old, new)))
    assert any(problem in p for p in problems), problems
    assert all(p.startswith("headers.yaml rule #1") for p in problems)


def test_lint_catches_duplicates_and_cookie_ids(tmp_path: Path) -> None:
    write(tmp_path, GOOD + GOOD.split("rules:\n", 1)[1])
    cookie = GOOD.replace("HDR-X-POWERED-BY-PRESENT", "COOKIE-X").replace(
        "    header: X-Powered-By\n    present: true", "    cookie: {flag_missing: secure}"
    )
    write(tmp_path, cookie, "cookies.yaml")
    _, problems = lint_rules(tmp_path)
    assert any("duplicate id" in p for p in problems)
    assert any("must contain {cookie_id}" in p for p in problems)
    with pytest.raises(RuleError):
        load_rules(tmp_path)


def test_lint_catches_bad_yaml_and_shape(tmp_path: Path) -> None:
    write(tmp_path, "rules: [unclosed", "a.yaml")
    write(tmp_path, "- just a list", "b.yaml")
    _, problems = lint_rules(tmp_path)
    assert any("invalid YAML" in p for p in problems)
    assert any("expected a mapping with a 'rules' list" in p for p in problems)


def test_cli_lint_and_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "lint"]) == 0
    assert "OK" in capsys.readouterr().out
    assert main(["rules", "list"]) == 0
    assert "COOKIE-NO-SECURE-{cookie_id}" in capsys.readouterr().out
    bad = write(tmp_path, GOOD.replace("severity: info", "severity: huge"))
    assert main(["rules", "lint", "--dir", str(bad)]) == 1
    assert "is not one of" in capsys.readouterr().err
