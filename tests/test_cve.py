"""CVE matching, fully offline: OSV/NVD responses are respx-mocked fixtures. The live APIs
are never contacted (the conftest DNS guard would fail any real lookup).
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from albert.checks.cve import cvss3_base_score, match_cves, nvd_certainty
from albert.cli import main
from albert.core.intel import IntelPolicy
from albert.core.models import Confidence, Severity, TechDetection
from albert.core.scope import OutOfScopeError
from albert.core.vulndb import lookup_all

FIXTURES = Path(__file__).parent / "fixtures" / "vulndb"
OSV = "https://api.osv.dev/v1/query"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
C, S = Confidence, Severity


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def det(name: str, version: str | None, conf: Confidence = C.HIGH, **ids: str) -> TechDetection:
    return TechDetection(
        name, "x", version, conf, (f"seen {name}",), ("https://shop.test/",), **ids
    )


def osv_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    pkg, version = body["package"]["name"], body["version"]
    if (pkg, version) == ("jquery", "3.4.1"):
        return httpx.Response(200, json=fixture("osv_jquery_3.4.1.json"))
    if pkg == "synthetic-lib":
        return httpx.Response(200, json=fixture("osv_synthetic_critical.json"))
    return httpx.Response(200, json={})


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", None),  # CVSS v2: not computed
    ],
)
def test_cvss3(vector: str, score: float | None) -> None:
    assert cvss3_base_score(vector) == score


@respx.mock
async def test_vulnerable_version_matches_patched_does_not(tmp_path: Path) -> None:
    route = respx.post(OSV).mock(side_effect=osv_handler)
    detections = [det("jQuery", "3.4.1", npm="jquery"), det("jQuery", "3.5.0", npm="jquery")]
    report = await lookup_all(detections, "online", tmp_path, target_hosts=("shop.test",))
    found = {f.id: f for f in match_cves(report.lookups)}
    assert set(found) == {"VULN-CVE-2020-11022-jQuery", "VULN-CVE-2020-11023-jQuery"}
    f = found["VULN-CVE-2020-11022-jQuery"]
    assert f.title == "jQuery 3.4.1 affected by CVE-2020-11022"
    assert (f.severity, f.confidence) == (S.MEDIUM, C.HIGH)  # CVSS 6.1; OSV match, High detection
    assert "3.5.0" in f.remediation and "CWE-79" in f.refs
    sent = [json.loads(c.request.content) for c in route.calls]
    assert all(set(b) == {"package", "version"} for b in sent)  # names + versions only
    assert "shop.test" not in json.dumps(sent)


@respx.mock
async def test_low_confidence_detection_caps_critical_cve(tmp_path: Path) -> None:
    respx.post(OSV).mock(side_effect=osv_handler)
    path_only = det("SyntheticLib", "1.0.0", C.LOW, npm="synthetic-lib")  # version from a URL
    report = await lookup_all([path_only], "online", tmp_path)
    (f,) = match_cves(report.lookups)
    assert f.severity is S.CRITICAL  # CVSS 9.8...
    assert f.confidence is C.LOW  # ...but never more certain than the detection


@respx.mock
async def test_nvd_ranges_and_platform_certainty(tmp_path: Path) -> None:
    respx.get(NVD).mock(return_value=httpx.Response(200, json=fixture("nvd_nginx.json")))
    old, new = det("nginx", "1.18.0", cpe="f5:nginx"), det("nginx", "1.25.3", cpe="f5:nginx")
    report = await lookup_all([old, new], "online", tmp_path)
    assert respx.calls.call_count == 1  # one product query, ranges evaluated locally
    found = {f.id: f for f in match_cves(report.lookups)}
    cve = found["VULN-CVE-2021-23017-nginx"]
    assert cve.title.startswith("nginx 1.18.0")
    assert (cve.severity, cve.confidence) == (S.HIGH, C.MEDIUM)  # 7.7; CPE match is Medium
    assert found["VULN-CVE-0000-00002-nginx"].confidence is C.LOW  # needs a specific OS
    assert not any("1.25.3" in f.title for f in found.values())


def test_nvd_range_edges() -> None:
    adv = {
        "matches": [
            {
                "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "0.6.18",
                "versionEndExcluding": "1.20.1",
            }
        ]
    }
    assert nvd_certainty("1.20.0", adv) is C.MEDIUM
    assert nvd_certainty("1.20.1", adv) is None
    assert nvd_certainty("0.6.17", adv) is None
    assert nvd_certainty("1.9.15", adv) is C.MEDIUM  # numeric, not string, comparison
    bare = {"matches": [{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]}
    assert nvd_certainty("1.0.0", bare) is None  # "every version" is too vague to claim


@respx.mock
async def test_unreachable_db_degrades_gracefully(tmp_path: Path) -> None:
    respx.post(OSV).mock(side_effect=httpx.ConnectError("no route"))
    report = await lookup_all([det("jQuery", "3.4.1", npm="jquery")], "online", tmp_path)
    (f,) = match_cves(report.lookups)
    assert f.id == "CVE-LOOKUP-UNAVAILABLE" and f.severity is S.INFO
    assert "jQuery 3.4.1" in f.evidence[0].value and "ConnectError" in f.evidence[0].value


@respx.mock
async def test_cache_then_offline(tmp_path: Path) -> None:
    respx.post(OSV).mock(side_effect=osv_handler)
    online = await lookup_all([det("jQuery", "3.4.1", npm="jquery")], "online", tmp_path)
    respx.reset()
    blocked = respx.post(OSV).mock(side_effect=AssertionError("network used in cache mode"))
    cached = await lookup_all([det("jQuery", "3.4.1", npm="jquery")], "cache", tmp_path)
    assert not blocked.called
    assert [f.id for f in match_cves(cached.lookups)] == [f.id for f in match_cves(online.lookups)]
    miss = await lookup_all([det("jQuery", "1.0.0", npm="jquery")], "cache", tmp_path)
    (f,) = match_cves(miss.lookups)
    assert f.id == "CVE-LOOKUP-UNAVAILABLE" and "--cve online" in f.evidence[0].value


async def test_presence_only_and_unidentified_never_looked_up(tmp_path: Path) -> None:
    detections = [det("jQuery", None, npm="jquery"), det("Mystery", "1.2.3")]
    report = await lookup_all(detections, "online", tmp_path)
    assert report.lookups == [] and match_cves(report.lookups) == []
    assert any("no CVE identifier" in n for n in report.notes)


def test_intel_policy() -> None:
    p = IntelPolicy(["shop.test"])
    assert p.check("POST", OSV) == "api.osv.dev"
    assert p.check("GET", NVD + "?x=1") == "services.nvd.nist.gov"
    for method, url in [
        ("GET", OSV),  # wrong method for OSV
        ("POST", "https://api.osv.dev/v1/vulns/x"),  # path not allowed
        ("GET", "http://services.nvd.nist.gov/rest/json/cves/2.0"),  # not https
        ("GET", "https://shop.test/"),  # the target
        ("GET", "https://evil.test/rest/json/cves/2.0"),
    ]:
        with pytest.raises(OutOfScopeError):
            p.check(method, url)


@respx.mock
def test_scan_default_is_local_and_degrades(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "shop.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    osv = respx.post(OSV).mock(return_value=httpx.Response(200, json={}))
    respx.get("https://shop.test/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "text/html", "Server": "nginx/1.18.0"}, text="<p>hi</p>"
        )
    )
    respx.route(host="shop.test").mock(return_value=httpx.Response(404))
    out = tmp_path / "reports"
    assert (
        main(
            ["scan", "https://shop.test/", "--scope", str(scope), "--out", str(out), "--rate", "0"]
        )
        == 0
    )
    data = json.loads(next(out.glob("shop.test_*.json")).read_text(encoding="utf-8"))
    note = next(f for f in data["posture_notes"] if f["id"] == "CVE-LOOKUP-UNAVAILABLE")
    assert "nginx 1.18.0" in note["evidence"][0]["value"]
    assert any("local cache only (no network)" in n for n in data["notes"])
    assert not osv.called  # default --cve cache never touches the network
