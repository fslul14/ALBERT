"""CORS-as-served and misc header checks on saved header fixtures. Nothing is ever sent."""

from pathlib import Path

import pytest

from albert.checks import headers
from albert.checks.cors import check_cors, run_cors_checks
from albert.core.models import CollectedResponse, Confidence, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "headers"
URL = "https://api.shop.test/v1/me"


def load(name: str, url: str = URL) -> CollectedResponse:
    lines = [
        ln
        for ln in (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    pairs = tuple((k.strip(), v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:]))
    return CollectedResponse(url, int(lines[0].split()[1]), pairs)


def resp(**headers: str) -> CollectedResponse:
    return CollectedResponse(URL, 200, tuple((k.replace("_", "-"), v) for k, v in headers.items()))


@pytest.mark.parametrize(
    ("fixture", "fid", "severity", "confidence"),
    [
        ("cors_wildcard.txt", "CORS-WILDCARD", Severity.LOW, Confidence.HIGH),
        (
            "cors_wildcard_credentials.txt",
            "CORS-WILDCARD-CREDENTIALS",
            Severity.MEDIUM,
            Confidence.HIGH,
        ),
        ("cors_null_credentials.txt", "CORS-NULL-CREDENTIALS", Severity.HIGH, Confidence.HIGH),
        ("cors_dynamic.txt", "CORS-DYNAMIC-CREDENTIALS", Severity.MEDIUM, Confidence.LOW),
        ("cors_list.txt", "CORS-INVALID", Severity.LOW, Confidence.HIGH),
    ],
)
def test_cors_fixtures(fixture: str, fid: str, severity: Severity, confidence: Confidence) -> None:
    (f,) = check_cors(load(fixture))
    assert (f.id, f.severity, f.confidence) == (fid, severity, confidence)


def test_reflection_is_low_confidence_and_says_unconfirmed() -> None:
    (f,) = check_cors(load("cors_dynamic.txt"))
    assert "Unconfirmed" in f.impact and "active test" in f.remediation


def test_specific_origins() -> None:
    assert check_cors(resp(Access_Control_Allow_Origin="https://app.shop.test")) == []  # no creds
    same_site = resp(
        Access_Control_Allow_Origin="https://app.shop.test", Access_Control_Allow_Credentials="true"
    )
    assert check_cors(same_site) == []  # same registrable domain, static: ordinary
    (third,) = check_cors(
        resp(
            Access_Control_Allow_Origin="https://partner.other.test",
            Access_Control_Allow_Credentials="true",
        )
    )
    assert third.id == "CORS-CREDENTIALS-THIRD-PARTY" and third.severity is Severity.LOW
    (http,) = check_cors(
        resp(
            Access_Control_Allow_Origin="http://app.shop.test",
            Access_Control_Allow_Credentials="true",
        )
    )
    assert http.id == "CORS-CREDENTIALS-INSECURE-ORIGIN" and http.severity is Severity.MEDIUM
    (pattern,) = check_cors(resp(Access_Control_Allow_Origin="https://*.shop.test"))
    assert pattern.id == "CORS-INVALID"


def test_null_without_credentials_is_low_and_groups() -> None:
    found = run_cors_checks(
        [
            CollectedResponse(u, 200, (("Access-Control-Allow-Origin", "null"),))
            for u in ("https://shop.test/a", "https://shop.test/b")
        ]
    )
    (f,) = found
    assert f.id == "CORS-NULL" and f.severity is Severity.LOW and len(f.urls) == 2


def test_misc_headers() -> None:
    findings = headers.check_misc(load("misc_conflicts.txt"))
    found = {f.id: f for f in findings}
    conflicts = {
        e.location for f in findings if f.id == "HDR-CONFLICTING-HEADERS" for e in f.evidence
    }
    assert conflicts == {"x-frame-options", "strict-transport-security"}
    assert found["HDR-TIMING-ALLOW-ORIGIN"].severity is Severity.INFO
    no_type = CollectedResponse(URL, 200, (("Content-Length", "120"),))
    assert [f.id for f in headers.check_misc(no_type)] == ["HDR-NO-CONTENT-TYPE"]
    empty = CollectedResponse(URL, 200, (("Content-Length", "0"),))
    assert headers.check_misc(empty) == []
    same_twice = CollectedResponse(
        URL,
        200,
        (("Content-Type", "text/html"), ("X-Frame-Options", "DENY"), ("x-frame-options", "deny")),
    )
    assert headers.check_misc(same_twice) == []  # duplicates that agree are harmless
