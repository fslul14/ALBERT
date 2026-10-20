"""Tests for the shared data model."""

import dataclasses
import json

import pytest

from albert.core.models import (
    Confidence,
    Evidence,
    Finding,
    ScanResult,
    Severity,
    Target,
    group_findings,
)

AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE"


def _f(fid: str, sev: Severity, conf: Confidence, url: str, ev: str = "v") -> Finding:
    return Finding(fid, f"title {fid}", sev, conf, urls=(url,), evidence=(Evidence("header", ev),))


def test_levels_ordered_and_labeled() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Confidence.LOW < Confidence.HIGH
    assert Severity.HIGH.label == "high"
    assert Severity.from_label("Medium") is Severity.MEDIUM


def test_evidence_redacts_at_construction() -> None:
    ev = Evidence("body", f"key={AWS_EXAMPLE}", location=f"https://x/?k={AWS_EXAMPLE}")
    assert AWS_EXAMPLE not in repr(ev)
    assert AWS_EXAMPLE not in json.dumps(ev.to_dict())
    replaced = dataclasses.replace(ev, value=AWS_EXAMPLE)
    assert AWS_EXAMPLE not in replaced.value


def test_frozen() -> None:
    f = _f("A", Severity.LOW, Confidence.HIGH, "https://x/")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.title = "changed"  # type: ignore[misc]
    assert isinstance(f.urls, tuple)


def test_group_findings_merges_and_sorts() -> None:
    findings = [
        _f("B-LOW", Severity.LOW, Confidence.HIGH, "https://x/1"),
        _f("A-MED", Severity.MEDIUM, Confidence.LOW, "https://x/1"),
        _f("A-MED", Severity.MEDIUM, Confidence.LOW, "https://x/2", ev="other"),
        _f("A-MED", Severity.MEDIUM, Confidence.LOW, "https://x/1"),
        _f("C-MED", Severity.MEDIUM, Confidence.HIGH, "https://x/3"),
        _f("A-HIGH", Severity.HIGH, Confidence.LOW, "https://x/1"),
    ]
    grouped = group_findings(findings)
    assert [g.id for g in grouped] == ["A-HIGH", "C-MED", "A-MED", "B-LOW"]
    med = grouped[2]
    assert med.urls == ("https://x/1", "https://x/2")
    assert [e.value for e in med.evidence] == ["v", "other"]


def test_same_id_different_severity_not_merged() -> None:
    grouped = group_findings(
        [
            _f("X", Severity.LOW, Confidence.HIGH, "https://x/1"),
            _f("X", Severity.HIGH, Confidence.HIGH, "https://x/2"),
        ]
    )
    assert len(grouped) == 2


@pytest.mark.parametrize("bad", ["ftp://x.com/", "example.com", "https:///path"])
def test_target_rejects_bad_url(bad: str) -> None:
    with pytest.raises(ValueError):
        Target(bad, "quick")


def test_scan_result_to_dict() -> None:
    t = Target("https://Example.com/", "scan", authorized_by="self (own domain)")
    assert t.host == "example.com"
    r = ScanResult(t)
    r.findings += [
        _f("A", Severity.MEDIUM, Confidence.HIGH, "https://example.com/1"),
        _f("A", Severity.MEDIUM, Confidence.HIGH, "https://example.com/2"),
    ]
    r.finish()
    d = json.loads(json.dumps(r.to_dict()))
    assert d["severity_counts"] == {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}
    assert d["findings"][0]["urls"] == ["https://example.com/1", "https://example.com/2"]
    assert d["target"]["authorized_by"] == "self (own domain)"
    assert d["finished_at"] is not None
