"""Tests for the Markdown/JSON report writer, including the redaction backstop."""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from albert.core.models import Confidence, Evidence, Finding, ScanResult, Severity, Target
from albert.core.report import build_report_data, write_report

FAKE_KEY = "sk" + "_live_" + "9" * 24  # built at runtime: no token literal in the repo


def _f(fid: str, sev: Severity, conf: Confidence, *urls: str, ev: str = "v") -> Finding:
    return Finding(
        fid,
        f"Title {fid}",
        sev,
        conf,
        urls=urls,
        evidence=(Evidence("header", ev, "x-h"),),
        impact="impact",
        remediation="fix",
        refs=("CWE-200",),
    )


def _result() -> ScanResult:
    r = ScanResult(
        Target("https://shop.test/", "scan", authorized_by="self", scope_date="2026-10-20")
    )
    r.started_at = datetime(2026, 10, 20, 9, 30, tzinfo=UTC)
    r.findings = [
        _f("L1", Severity.LOW, Confidence.HIGH, "https://shop.test/"),
        _f("M1", Severity.MEDIUM, Confidence.LOW, "https://shop.test/"),
        _f("M2", Severity.MEDIUM, Confidence.HIGH, "https://shop.test/"),
        _f("H1", Severity.HIGH, Confidence.MEDIUM, "https://shop.test/"),
        _f("I1", Severity.INFO, Confidence.HIGH, "https://shop.test/a", ev="a|b `c`"),
        _f("I1", Severity.INFO, Confidence.HIGH, "https://shop.test/b", ev="a|b `c`"),
    ]
    r.pages = ["https://shop.test/", "https://shop.test/a", "https://shop.test/b"]
    r.checks_run = ["headers"]
    r.finish()
    return r


def _write(tmp_path: Path, result: ScanResult) -> tuple[str, dict]:  # type: ignore[type-arg]
    md_path, json_path = write_report(result, tmp_path)
    return md_path.read_text(encoding="utf-8"), json.loads(json_path.read_text(encoding="utf-8"))


def test_filenames_and_no_overwrite(tmp_path: Path) -> None:
    r = _result()
    first = write_report(r, tmp_path)
    second = write_report(r, tmp_path)
    stem = re.escape("shop.test_") + r"\d{4}-\d{2}-\d{2}_\d{4}"
    assert re.fullmatch(stem + r"\.md", first[0].name)
    assert re.fullmatch(stem + r"\.json", first[1].name)
    assert re.fullmatch(stem + r"_2\.md", second[0].name)


def test_sections_order_and_info_collapsed(tmp_path: Path) -> None:
    md, data = _write(tmp_path, _result())
    headings = [ln for ln in md.splitlines() if ln.startswith("## ")]
    assert headings == [
        "## Header",
        "## Executive summary",
        "## Findings",
        "## Posture notes (Info)",
        "## Appendix",
    ]
    md_order = re.findall(r"^### \d+\. \[\w+\] Title (\w+)", md, re.M)
    assert md_order == ["H1", "M2", "M1", "L1"]  # severity, then confidence
    assert [f["id"] for f in data["findings"]] == md_order  # JSON mirrors MD
    assert "Title I1" not in md.split("## Posture notes")[0]  # Info not a full entry
    assert [f["id"] for f in data["posture_notes"]] == ["I1"]
    assert data["posture_notes"][0]["urls"] == ["https://shop.test/a", "https://shop.test/b"]
    counts = data["summary"]["severity_counts"]
    assert counts == {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 1}
    assert "| Info | 1 |" in md


def test_untrusted_pipes_and_backticks_dont_break_table(tmp_path: Path) -> None:
    md, _ = _write(tmp_path, _result())
    row = next(ln for ln in md.splitlines() if ln.startswith("| `I1`"))
    assert len(re.findall(r"(?<!\\)\|", row)) == 5  # four columns, unbroken


def test_redaction_backstop(tmp_path: Path) -> None:
    """Evidence that bypassed construction-time redaction is still redacted on write."""
    r = _result()
    leaky = Evidence("body", "placeholder")
    object.__setattr__(leaky, "value", f"config: key={FAKE_KEY}")  # simulate a careless check
    object.__setattr__(leaky, "location", f"https://shop.test/?k={FAKE_KEY}")
    assert FAKE_KEY in leaky.value  # precondition: truly unredacted
    r.findings.append(
        Finding("LEAK", "Leak", Severity.MEDIUM, Confidence.HIGH, ("https://shop.test/",), (leaky,))
    )
    r.errors.append(f"boom {FAKE_KEY}")
    md, data = _write(tmp_path, r)
    raw_json = json.dumps(data)
    assert FAKE_KEY not in md and FAKE_KEY not in raw_json
    assert "[REDACTED-stripe_key]" in md and "[REDACTED-stripe_key]" in raw_json


def test_quick_mode_header_and_empty_findings(tmp_path: Path) -> None:
    r = ScanResult(Target("https://x.test/", "quick"))
    r.finish()
    md, data = _write(tmp_path, r)
    assert "none (quick mode" in md
    assert "No Low-or-higher findings." in md
    assert (data["summary"]["posture"]["score"], data["summary"]["posture"]["grade"]) == (100, "A")
    assert build_report_data(r)["target"]["mode"] == "quick"


# --- posture grading -------------------------------------------------------------------------

from albert.core.engine import run_family  # noqa: E402
from albert.core.report import posture  # noqa: E402

HEADERS = Path(__file__).parent / "fixtures" / "headers"


def _fixture_findings(name: str, url: str = "https://shop.test/account/login") -> list[Finding]:
    from albert.core.models import CollectedResponse

    lines = [
        ln
        for ln in (HEADERS / name).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    version, status = lines[0].split()[:2]
    pairs = tuple((k.strip(), v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:]))
    resp = CollectedResponse(url, int(status), pairs, version)
    return run_family("headers", [resp]) + run_family("cookies", [resp])


def _grade(findings: list[Finding]) -> str:
    return str(posture([f for f in findings if f.severity > Severity.INFO])["grade"])


def test_hardened_site_grades_a() -> None:
    assert _grade(_fixture_findings("hardened.txt", "https://secure.test/")) == "A"


def test_weak_sites_grade_poorly() -> None:
    bare = posture([f for f in _fixture_findings("bare_apache.txt") if f.severity > Severity.INFO])
    weak = posture(
        [
            f
            for f in _fixture_findings("weak.txt", "https://app.test/")
            if f.severity > Severity.INFO
        ]
    )
    assert bare["grade"] in ("C", "D") and weak["grade"] in ("C", "D")
    assert bare["score"] < 80 and weak["score"] < 80


def _graded(sev: Severity, conf: Confidence = Confidence.HIGH, n: int = 0) -> Finding:
    return Finding(f"X-{sev.label}-{n}", "t", sev, conf, ("https://x.test/",))


def test_severity_caps() -> None:
    one_high = posture([_graded(Severity.HIGH)])
    assert one_high["score"] == 75 and one_high["grade"] == "C"  # 75 alone would already be C
    assert posture([_graded(Severity.CRITICAL)])["grade"] == "D"  # score 60: D on its own
    medium_conf = posture([_graded(Severity.CRITICAL, Confidence.MEDIUM)])
    assert (medium_conf["score"], medium_conf["grade"], medium_conf["capped_by"]) == (
        70,
        "D",
        "critical",
    )
    low_conf_high = posture([_graded(Severity.HIGH, Confidence.LOW)])
    assert low_conf_high["capped_by"] is None and low_conf_high["grade"] == "B"  # 87.5


def test_diminishing_repeats_and_confidence() -> None:
    lows = posture([_graded(Severity.LOW, n=i) for i in range(20)])
    assert lows["score"] >= 94 and lows["grade"] == "A"  # 20 Lows cost < 6 points
    assert posture([_graded(Severity.MEDIUM)])["grade"] == "B"  # one Medium: 90
    assert posture([_graded(Severity.MEDIUM, Confidence.LOW)])["score"] == 95
    many_medium = posture([_graded(Severity.MEDIUM, n=i) for i in range(10)])["score"]
    assert many_medium > posture([_graded(Severity.HIGH)])["score"] - 10  # 10 Mediums ~ one High
