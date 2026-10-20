"""External intelligence, fully offline: crt.sh / Wayback / Safe Browsing are respx-mocked and
DNS blocklists use a fake resolver. Live APIs are never contacted.
"""

import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from albert.checks.intel_lookups import intel_findings
from albert.cli import main
from albert.core.intel import INTEL_ENDPOINTS, IntelDns, IntelDnsPolicy, IntelPolicy
from albert.core.intel_sources import CRT_SH, SAFE_BROWSING, WAYBACK_CDX, collect_intel
from albert.core.models import DnsAnswer, Finding, Severity
from albert.core.scope import OutOfScopeError

FIXTURES = Path(__file__).parent / "fixtures" / "intel"
D = "shop.test"
S = Severity
FAKE_KEY = "AIza" + "Sy" + "K" * 33  # built at runtime


def fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeDnsbl:
    def __init__(self, answers: dict[str, tuple[str, ...]] | None = None) -> None:
        self.answers, self.asked = answers or {}, []  # type: ignore[var-annotated]

    async def __call__(self, name: str, rtype: str) -> DnsAnswer:
        self.asked.append(name)
        if name in self.answers:
            return DnsAnswer(name, rtype, "ok", self.answers[name])
        return DnsAnswer(name, rtype, "nxdomain")


def mock_services(sb: bool = False) -> None:
    respx.get(url__startswith=CRT_SH).mock(
        return_value=httpx.Response(200, json=fixture("crtsh.json"))
    )
    respx.get(url__startswith=WAYBACK_CDX).mock(
        return_value=httpx.Response(200, json=fixture("wayback.json"))
    )
    if sb:
        respx.post(url__startswith=SAFE_BROWSING).mock(
            return_value=httpx.Response(200, json=fixture("safebrowsing_match.json"))
        )


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


async def run(
    tmp_path: Path,
    *,
    key: str | None = "",
    dnsbl: FakeDnsbl | None = None,
    mx_ips: list[str] | None = None,
) -> list[Finding]:
    report = await collect_intel(
        D, (D,), tmp_path, mx_ips=mx_ips, dns=IntelDns(dnsbl or FakeDnsbl()), safe_browsing_key=key
    )
    return intel_findings(report, lambda h: h in {D, "www.shop.test"})


@respx.mock
async def test_ct_subdomains_reported_with_scope_status(tmp_path: Path) -> None:
    mock_services()
    f = by_id(await run(tmp_path))["INTEL-CT-SUBDOMAINS"]
    assert f.severity is S.INFO
    status = {e.value: e.location for e in f.evidence}
    assert status == {
        "old-admin.shop.test": "not in scope: not contacted",
        "staging.shop.test": "not in scope: not contacted",
        "vpn.shop.test": "not in scope: not contacted",
        "www.shop.test": "in scope",
    }  # wildcard stripped, other domains (shop.test.other.example, notshop.test) dropped


@respx.mock
async def test_wayback_highlights_sensitive_paths(tmp_path: Path) -> None:
    mock_services()
    f = by_id(await run(tmp_path))["INTEL-WAYBACK-URLS"]
    values = [e.value for e in f.evidence]
    assert any("backup.zip" in v for v in values) and any("/admin/login" in v for v in values)
    assert not any("/blog/hello" in v for v in values)
    assert values[-1] == "6 archived URL(s) that returned HTTP 200"
    assert not any("$pkgver" in v for v in values)  # template junk (seen live) is not "sensitive"
    assert all(len(v) < 300 for v in values)  # multi-KB archived URLs are clipped
    wayback = next(c for c in respx.calls if c.request.url.host == "web.archive.org")
    assert parse_qs(wayback.request.url.query.decode())["filter"] == ["statuscode:200"]


@respx.mock
async def test_target_is_never_a_destination(tmp_path: Path) -> None:
    mock_services(sb=True)
    dnsbl = FakeDnsbl()
    await run(tmp_path, key=FAKE_KEY, dnsbl=dnsbl, mx_ips=["8.8.8.8"])
    hosts = {c.request.url.host for c in respx.calls}
    assert hosts == {"crt.sh", "web.archive.org", "safebrowsing.googleapis.com"}
    assert D not in hosts and not any(h.endswith("." + D) for h in hosts)
    for call in respx.calls:  # the domain appears only as the documented query subject
        url = call.request.url
        params = parse_qs(urlsplit(str(url)).query)
        if url.host == "crt.sh":
            assert params["q"] == [f"%.{D}"]
        elif url.host == "web.archive.org":
            assert params["url"] == [f"{D}/*"]
        else:
            body = json.loads(call.request.content)
            assert {e["url"] for e in body["threatInfo"]["threatEntries"]} == {
                f"https://{D}/",
                f"http://{D}/",
            }
            assert D not in json.dumps({k: v for k, v in body.items() if k != "threatInfo"})
    assert all(
        n.endswith((".dbl.spamhaus.org", ".multi.surbl.org", ".zen.spamhaus.org"))
        for n in dnsbl.asked
    )
    assert "8.8.8.8.zen.spamhaus.org" in dnsbl.asked


@respx.mock
async def test_missing_safe_browsing_key_is_a_skip_note(tmp_path: Path) -> None:
    mock_services()
    sb = respx.post(url__startswith=SAFE_BROWSING).mock(return_value=httpx.Response(200, json={}))
    found = by_id(await run(tmp_path, key=""))
    assert not sb.called
    note = found["INTEL-NOT-ASSESSED"]
    assert note.severity is S.INFO
    assert any(
        e.location == "safe_browsing" and "ALBERT_SAFE_BROWSING_KEY" in e.value
        for e in note.evidence
    )


@respx.mock
async def test_safe_browsing_match_is_high_and_key_never_reported(tmp_path: Path) -> None:
    mock_services(sb=True)
    found = await run(tmp_path, key=FAKE_KEY)
    f = by_id(found)["INTEL-SAFE-BROWSING"]
    assert f.severity is S.HIGH and "SOCIAL_ENGINEERING" in f.evidence[0].value
    assert FAKE_KEY not in json.dumps([x.to_dict() for x in found])


@respx.mock
async def test_blocklists(tmp_path: Path) -> None:
    mock_services()
    dnsbl = FakeDnsbl(
        {
            f"{D}.dbl.spamhaus.org": ("127.0.1.4",),
            f"{D}.multi.surbl.org": ("127.0.0.8",),
            "8.8.8.8.zen.spamhaus.org": ("127.0.0.10",),
        }
    )
    found = await run(tmp_path, dnsbl=dnsbl, mx_ips=["8.8.8.8", "10.0.0.5"])
    domain = [f for f in found if f.id == "INTEL-BLOCKLISTED-DOMAIN"]
    assert {f.title for f in domain} == {
        "Domain listed on dbl.spamhaus.org",
        "Domain listed on multi.surbl.org",
    }
    assert all(f.severity is S.MEDIUM for f in domain)
    assert "phishing" in domain[0].evidence[0].value
    mx = by_id(found)["INTEL-BLOCKLISTED-MX"]
    assert mx.severity is S.LOW  # PBL: policy listing only
    assert not any("10.0.0.5" in n or "5.0.0.10" in n for n in dnsbl.asked)  # private IP skipped


@respx.mock
async def test_refused_blocklist_and_unreachable_service_degrade(tmp_path: Path) -> None:
    respx.get(url__startswith=CRT_SH).mock(side_effect=httpx.ConnectError("timeout"))
    respx.get(url__startswith=WAYBACK_CDX).mock(
        return_value=httpx.Response(200, json=fixture("wayback.json"))
    )
    dnsbl = FakeDnsbl({f"{D}.dbl.spamhaus.org": ("127.255.255.254",)})
    found = by_id(await run(tmp_path, dnsbl=dnsbl))
    assert "INTEL-BLOCKLISTED-DOMAIN" not in found  # a refusal is not a listing
    assert "INTEL-WAYBACK-URLS" in found  # other sources still work
    sources = {e.location for e in found["INTEL-NOT-ASSESSED"].evidence}
    assert {"crt.sh", "blocklists", "safe_browsing"} <= sources


@respx.mock
async def test_results_cached(tmp_path: Path) -> None:
    mock_services()
    await run(tmp_path)
    first = len(respx.calls)
    await run(tmp_path)
    assert len(respx.calls) == first == 2  # second run: crt.sh + Wayback from cache


def test_intel_policies() -> None:
    p = IntelPolicy([D])
    assert p.check("GET", f"{CRT_SH}?q=%25.{D}&output=json") == "crt.sh"
    assert p.check("GET", f"{WAYBACK_CDX}?url={D}/*") == "web.archive.org"
    assert p.check("POST", f"{SAFE_BROWSING}?key=x") == "safebrowsing.googleapis.com"
    for method, url in [
        ("GET", "https://crt.sh/atom"),
        ("GET", "https://web.archive.org/web/2020/x"),
        ("GET", SAFE_BROWSING),
        ("POST", "https://api.osv.dev/v1/querybatch"),
        ("GET", f"https://{D}/"),
    ]:
        with pytest.raises(OutOfScopeError):
            p.check(method, url)
    assert all(paths for methods in INTEL_ENDPOINTS.values() for paths in methods.values())
    dns = IntelDnsPolicy()
    assert dns.check(f"{D}.dbl.spamhaus.org", "A")
    for name, rtype in [
        (D, "A"),
        ("dbl.spamhaus.org", "A"),
        (f"{D}.dbl.spamhaus.org", "TXT"),
        ("x.evil.example", "A"),
    ]:
        with pytest.raises(OutOfScopeError):
            dns.check(name, rtype)


@pytest.mark.real_intel
@respx.mock
def test_scan_full_reports_but_never_scans_discovered_subdomains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class OfflineIntelDns(IntelDns):
        def __init__(self, resolve: object = None) -> None:
            super().__init__(FakeDnsbl())

    monkeypatch.setattr("albert.core.intel_sources.IntelDns", OfflineIntelDns)
    scope = tmp_path / "scope.toml"
    scope.write_text(
        f'[[target]]\nhost = "{D}"\nauthorized_by = "self"\ndate = "2026-10-20"\n', encoding="utf-8"
    )
    mock_services()
    discovered = [
        respx.route(host=h).mock(return_value=httpx.Response(200))
        for h in ("staging.shop.test", "old-admin.shop.test", "vpn.shop.test", "www.shop.test")
    ]
    respx.get(f"https://{D}/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "text/html"}, text="<a href='/'>home</a>"
        )
    )
    respx.route(host=D).mock(return_value=httpx.Response(404))
    out = tmp_path / "reports"
    assert (
        main(
            [
                "scan",
                f"https://{D}/",
                "--scope",
                str(scope),
                "--out",
                str(out),
                "--rate",
                "0",
                "--full",
            ]
        )
        == 0
    )
    data = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
    assert "intel" in data["checks_run"]
    ct = next(f for f in data["posture_notes"] if f["id"] == "INTEL-CT-SUBDOMAINS")
    assert {e["value"] for e in ct["evidence"]} >= {"staging.shop.test", "vpn.shop.test"}
    assert not any(r.called for r in discovered)  # reported, never contacted
    assert not any(urlsplit(p).hostname != D for p in data["appendix"]["pages"])


@respx.mock
def test_plain_scan_has_no_intel(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        f'[[target]]\nhost = "{D}"\nauthorized_by = "self"\ndate = "2026-10-20"\n', encoding="utf-8"
    )
    crt = respx.get(url__startswith=CRT_SH).mock(return_value=httpx.Response(200, json=[]))
    respx.route().mock(return_value=httpx.Response(404))
    main(["scan", f"https://{D}/", "--scope", str(scope), "--out", str(tmp_path), "--rate", "0"])
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert "intel" not in data["checks_run"] and not crt.called
