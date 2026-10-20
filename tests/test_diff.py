"""Scan diffing on two saved JSON reports with known additions, resolutions and changes."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from albert.cli import main
from albert.core.diff import DiffError, diff_reports, load_prior
from albert.core.models import Confidence, Evidence, Finding, ScanResult, Severity, Target
from albert.core.report import build_report_data, render_markdown

FIXTURES = Path(__file__).parent / "fixtures" / "diff"


def load(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def ids(entries: list[dict]) -> list[str]:  # type: ignore[type-arg]
    return [e["id"] for e in entries]


def test_categories() -> None:
    d = diff_reports(load("prior.json"), load("current.json"))
    assert ids(d["new"]) == ["JS-SECRET-AWS_ACCESS_KEY_ID", "RND-SCRIPT-NO-SRI"]
    assert ids(d["resolved"]) == ["HDR-HSTS-MISSING"]
    assert ids(d["unchanged"]) == ["HDR-CSP-MISSING"]
    assert ids(d["not_rechecked"]) == ["DNS-DMARC-MISSING"]  # dns_email didn't run this time
    assert d["not_rechecked"][0]["family"] == "dns_email"
    changed = {c["id"]: c for c in d["changed"]}
    assert set(changed) == {
        "COOKIE-NO-HTTPONLY-PHPSESSID",
        "HDR-REFERRER-UNSAFE",
        "VULN-CVE-2020-11022-jQuery",
        "HDR-CDN-WAF",
        "PRIV-THIRD-PARTY-ORIGINS",
    }
    assert changed["COOKIE-NO-HTTPONLY-PHPSESSID"]["urls_added"] == ["https://site.test/login"]
    assert changed["HDR-REFERRER-UNSAFE"]["severity"] == ["low", "medium"]
    assert changed["VULN-CVE-2020-11022-jQuery"]["confidence"] == ["high", "low"]
    assert changed["HDR-CDN-WAF"]["title"] == [
        "CDN/WAF detected: Cloudflare",
        "CDN/WAF detected: Fastly",
    ]
    assert d["counts"] == {
        "new": 2,
        "resolved": 1,
        "changed": 5,
        "unchanged": 1,
        "not_rechecked": 1,
    }


def test_repeated_ids_are_told_apart_by_title() -> None:
    prior = load("prior.json")
    current = load("current.json")
    prior["posture_notes"].append(dict(prior["posture_notes"][0], title="CDN/WAF detected: Akamai"))
    current["posture_notes"].append(
        dict(current["posture_notes"][0], title="CDN/WAF detected: Akamai")
    )
    d = diff_reports(prior, current)
    cdn = [e for k in ("new", "resolved", "unchanged") for e in d[k] if e["id"] == "HDR-CDN-WAF"]
    assert {(e["title"].split(": ")[1]) for e in cdn} == {"Akamai", "Cloudflare", "Fastly"}
    assert next(e for e in d["unchanged"] if e["id"] == "HDR-CDN-WAF")["title"].endswith("Akamai")


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("prior_other_host.json", "is for 'other.test', not 'site.test'"),
        ("prior_old_schema.json", "schema 0 is incompatible"),
        ("prior_quick.json", "is a 'quick' run, not 'scan'"),
    ],
)
def test_incompatible_prior_refused(name: str, message: str) -> None:
    with pytest.raises(DiffError, match=message):
        load_prior(FIXTURES / name, "site.test", "scan")


def test_unreadable_prior_refused(tmp_path: Path) -> None:
    bad = tmp_path / "x.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(DiffError, match="not a readable"):
        load_prior(bad, "site.test", "scan")
    with pytest.raises(DiffError, match="not a readable"):
        load_prior(tmp_path / "missing.json", "site.test", "scan")


def test_report_section_and_json() -> None:
    r = ScanResult(Target("https://site.test/", "scan", authorized_by="self"))
    r.checks_run = ["headers"]
    r.findings = [
        Finding(
            "HDR-CSP-MISSING",
            "Content-Security-Policy missing",
            Severity.MEDIUM,
            Confidence.HIGH,
            ("https://site.test/", "https://site.test/a"),
            (Evidence("header", "(absent)", "Content-Security-Policy"),),
        )
    ]
    r.finish()
    data = build_report_data(r, load_prior(FIXTURES / "prior.json", "site.test", "scan"))
    assert data["diff"]["counts"]["unchanged"] == 1
    assert "HDR-HSTS-MISSING" in ids(data["diff"]["resolved"])
    md = render_markdown(data)
    assert "## Changes since last scan" in md
    assert (
        md.index("## Executive summary")
        < md.index("## Changes since last scan")
        < md.index("## Findings")
    )
    assert data["diff"]["counts"] == {
        "new": 0,
        "resolved": 3,
        "changed": 0,
        "unchanged": 1,
        "not_rechecked": 4,
    }
    assert "| 0 | 3 | 0 | 1 | 4 |" in md  # new | resolved | changed | unchanged | not re-checked
    assert "Not re-checked this run" in md


@respx.mock
def test_cli_diff_end_to_end_and_refusal_before_scanning(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "site.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    home = respx.get("https://site.test/").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"}, text="<p>hi</p>")
    )
    respx.route().mock(return_value=httpx.Response(404))
    base = ["scan", "https://site.test/", "--scope", str(scope), "--rate", "0"]
    assert (
        main(
            [
                *base,
                "--out",
                str(tmp_path / "r1"),
                "--diff",
                str(FIXTURES / "prior_other_host.json"),
            ]
        )
        == 2
    )
    assert not home.called  # refused before any request
    assert main([*base, "--out", str(tmp_path / "r2"), "--diff", str(FIXTURES / "prior.json")]) == 0
    data = json.loads(next((tmp_path / "r2").glob("*.json")).read_text(encoding="utf-8"))
    assert "HDR-CSP-MISSING" in ids(data["diff"]["unchanged"]) + ids(data["diff"]["changed"])
    assert "HDR-HSTS-MISSING" in ids(data["diff"]["unchanged"]) + ids(data["diff"]["changed"])
    md = next((tmp_path / "r2").glob("*.md")).read_text(encoding="utf-8")
    assert "## Changes since last scan" in md


def test_a_report_diffs_cleanly_against_itself(tmp_path: Path) -> None:
    current = load("current.json")
    d = diff_reports(current, current)
    assert d["counts"]["unchanged"] == len(current["findings"]) + len(current["posture_notes"])
    assert sum(v for k, v in d["counts"].items() if k != "unchanged") == 0
