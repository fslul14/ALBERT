"""DNS/email checks with mocked DNS (a fake resolver over a dict zone). Never live resolution:
the conftest guard makes any real dnspython query fail the test.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from albert.checks.dns_email import run_dns_email_checks
from albert.cli import main
from albert.core import dns_client
from albert.core.dns_client import DnsClient, DnsPolicy, collect_dns, system_resolve
from albert.core.models import (
    CollectedResponse,
    Confidence,
    DnsAnswer,
    DnsSnapshot,
    Finding,
    Severity,
)
from albert.core.scope import OutOfScopeError, ScopePolicy

D = "shop.test"
S, C = Severity, Confidence

GOOD_ZONE: dict[tuple[str, str], tuple[str, ...]] = {
    (D, "TXT"): (
        "v=spf1 include:_spf.shop.test include:_spf.google.com -all",
        "google-site-verification=x",
    ),
    ("_spf.shop.test", "TXT"): ("v=spf1 ip4:192.0.2.0/24 -all",),
    (f"_dmarc.{D}", "TXT"): ("v=DMARC1; p=reject; rua=mailto:dmarc@shop.test",),
    (D, "MX"): ("10 mx1.shop.test.", "20 aspmx.l.google.com."),
    (D, "DS"): ("12345 13 2 ABCDEF",),
    (D, "DNSKEY"): ("257 3 13 AwEAAa==",),
    (D, "CAA"): ('0 issue "letsencrypt.org"',),
    (f"_mta-sts.{D}", "TXT"): ("v=STSv1; id=20261020",),
    (f"_smtp._tls.{D}", "TXT"): ("v=TLSRPTv1; rua=mailto:tls@shop.test",),
    (f"default._bimi.{D}", "TXT"): ("v=BIMI1; l=https://shop.test/logo.svg",),
    ("_25._tcp.mx1.shop.test", "TLSA"): ("3 1 1 ABCD",),
}
GOOD_POLICY = (
    "version: STSv1\nmode: enforce\nmx: mx1.shop.test\nmx: *.l.google.com\nmax_age: 604800\n"
)


class FakeResolver:
    def __init__(
        self,
        zone: dict[tuple[str, str], tuple[str, ...]],
        nxdomain: set[tuple[str, str]] | None = None,
        errors: set[tuple[str, str]] | None = None,
    ) -> None:
        self.zone, self.nx, self.errors = zone, nxdomain or set(), errors or set()
        self.asked: list[tuple[str, str]] = []

    async def __call__(self, name: str, rtype: str) -> DnsAnswer:
        self.asked.append((name, rtype))
        if (name, rtype) in self.errors:
            return DnsAnswer(name, rtype, "error", error="LifetimeTimeout")
        if (name, rtype) in self.nx:
            return DnsAnswer(name, rtype, "nxdomain")
        values = self.zone.get((name, rtype))
        return (
            DnsAnswer(name, rtype, "ok", values) if values else DnsAnswer(name, rtype, "noanswer")
        )


def policy_resp(text: str, status: int = 200) -> CollectedResponse:
    return CollectedResponse(
        f"https://mta-sts.{D}/.well-known/mta-sts.txt",
        status,
        (("Content-Type", "text/plain"),),
        text=text,
    )


async def snapshot(
    zone: dict[tuple[str, str], tuple[str, ...]],
    policy: str | None = GOOD_POLICY,
    host: str = f"www.{D}",
    **kw: set[tuple[str, str]],
) -> tuple[DnsSnapshot, FakeResolver]:
    resolver = FakeResolver(zone, **kw)

    async def fetch(domain: str) -> CollectedResponse | None:
        return policy_resp(policy) if policy is not None else policy_resp("", 404)

    return await collect_dns(D, host, resolve=resolver, fetch_policy=fetch), resolver


def ids(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def zone_with(**changes: tuple[str, ...] | None) -> dict[tuple[str, str], tuple[str, ...]]:
    z = dict(GOOD_ZONE)
    for key, value in changes.items():
        name, rtype = key.rsplit("__", 1)
        name = name.replace("_dot_", ".").replace("APEX", D)
        if value is None:
            z.pop((name, rtype), None)
        else:
            z[(name, rtype)] = value
    return z


# --- scope ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", [D, f"_dmarc.{D}", "_25._tcp.mx1.shop.test", "MX1.Shop.Test."])
def test_policy_allows_own_names(name: str) -> None:
    assert DnsPolicy(D).check(name, "TXT")


@pytest.mark.parametrize(
    ("name", "rtype"),
    [
        ("_spf.google.com", "TXT"),
        ("shop.test.evil.test", "TXT"),
        ("evilshop.test", "A"),
        (D, "AXFR"),
        (D, "ANY"),
    ],
)
def test_policy_refuses(name: str, rtype: str) -> None:
    with pytest.raises(OutOfScopeError):
        DnsPolicy(D).check(name, rtype)


async def test_scope_checked_before_resolver() -> None:
    resolver = FakeResolver({})
    with pytest.raises(OutOfScopeError):
        await DnsClient(DnsPolicy(D), resolver).query("_spf.google.com", "TXT")
    assert resolver.asked == []


async def test_third_party_names_never_queried() -> None:
    snap, resolver = await snapshot(GOOD_ZONE)
    asked = {n for n, _ in resolver.asked}
    assert "_spf.shop.test" in asked  # in-domain include is expanded
    assert all(n == D or n.endswith("." + D) for n in asked)  # google include / MX never asked
    assert ("_25._tcp.mx1.shop.test", "TLSA") in resolver.asked
    assert any("aspmx.l.google.com" in n for n in snap.notes)  # off-domain MX: DANE skipped


@pytest.mark.dns_guard_test
async def test_real_dnspython_is_blocked_in_tests() -> None:
    """The guard intercepts the send itself (dnspython then reports all nameservers failed)."""
    from conftest import DNS_SEND_ATTEMPTS

    answer = await system_resolve("example.com", "TXT")
    assert DNS_SEND_ATTEMPTS and "example.com" in DNS_SEND_ATTEMPTS[0]
    assert answer.status == "error" and answer.values == ()


def test_mta_sts_policy_is_one_exact_file() -> None:
    p = ScopePolicy.for_mta_sts(D)
    assert p.check_request("GET", f"https://mta-sts.{D}/.well-known/mta-sts.txt")
    for url in (
        f"https://mta-sts.{D}/",
        f"http://mta-sts.{D}/.well-known/mta-sts.txt",
        f"https://mta-sts.{D}/.well-known/mta-sts.txt?x=1",
        f"https://www.{D}/.well-known/mta-sts.txt",
    ):
        with pytest.raises(OutOfScopeError):
            p.check_request("GET", url)


@respx.mock
async def test_mta_sts_fetch_does_not_follow_redirects() -> None:
    url = f"https://mta-sts.{D}/.well-known/mta-sts.txt"
    respx.get(url).mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.test/p"})
    )
    evil = respx.route(host="evil.test").mock(return_value=httpx.Response(200))
    resp = await dns_client.fetch_mta_sts_policy(D)
    assert resp is not None and resp.status == 302 and not evil.called


# --- checks ---------------------------------------------------------------------------------


async def test_well_configured_domain_is_quiet() -> None:
    snap, _ = await snapshot(GOOD_ZONE)
    found = run_dns_email_checks([snap])
    assert [f.id for f in found] == ["DNS-DKIM-NOT-ASSESSED"]  # can't be checked, never guessed
    assert found[0].severity is S.INFO


@pytest.mark.parametrize(
    ("changes", "fid", "severity"),
    [
        ({"APEX__TXT": ("v=spf1 +all",)}, "DNS-SPF-PLUS-ALL", S.MEDIUM),
        ({"APEX__TXT": ("v=spf1 mx ?all",)}, "DNS-SPF-NEUTRAL", S.LOW),
        ({"APEX__TXT": ("v=spf1 mx -all", "v=spf1 a -all")}, "DNS-SPF-MULTIPLE", S.LOW),
        ({"APEX__TXT": ("v=spf1 mx bogus -all",)}, "DNS-SPF-INVALID", S.LOW),
        ({"APEX__TXT": ("v=spf1 ptr -all",)}, "DNS-SPF-PTR", S.INFO),
        ({"APEX__TXT": None}, "DNS-SPF-MISSING", S.LOW),
        ({"_dmarc_dot_APEX__TXT": None}, "DNS-DMARC-MISSING", S.MEDIUM),
        (
            {"_dmarc_dot_APEX__TXT": ("v=DMARC1; p=none; rua=mailto:a@shop.test",)},
            "DNS-DMARC-NOT-ENFORCED",
            S.MEDIUM,
        ),
        (
            {"_dmarc_dot_APEX__TXT": ("v=DMARC1; p=reject; pct=25; rua=mailto:a@shop.test",)},
            "DNS-DMARC-PARTIAL",
            S.LOW,
        ),
        (
            {"_dmarc_dot_APEX__TXT": ("v=DMARC1; p=reject; sp=none; rua=mailto:a@shop.test",)},
            "DNS-DMARC-SUBDOMAINS-NONE",
            S.LOW,
        ),
        ({"_dmarc_dot_APEX__TXT": ("v=DMARC1; p=reject",)}, "DNS-DMARC-NO-REPORTS", S.INFO),
        ({"_dmarc_dot_APEX__TXT": ("v=DMARC1; p=bogus",)}, "DNS-DMARC-INVALID", S.MEDIUM),
        ({"APEX__CAA": None}, "DNS-CAA-MISSING", S.LOW),
        ({"APEX__DS": None}, "DNS-DNSSEC-MISSING", S.LOW),
        ({"_mta-sts_dot_APEX__TXT": None}, "DNS-MTA-STS-MISSING", S.LOW),
        ({"_smtp._tls_dot_APEX__TXT": None}, "DNS-TLSRPT-MISSING", S.INFO),
        ({"default._bimi_dot_APEX__TXT": None}, "DNS-BIMI-MISSING", S.INFO),
        ({"_25._tcp.mx1_dot_APEX__TLSA": None}, "DNS-DANE-MISSING", S.INFO),
    ],
)
async def test_each_gap(
    changes: dict[str, tuple[str, ...] | None], fid: str, severity: Severity
) -> None:
    snap, _ = await snapshot(zone_with(**changes))
    found = ids(run_dns_email_checks([snap]))
    assert fid in found, list(found)
    assert found[fid].severity is severity


async def test_spf_lookup_limit_counts_third_party_as_lower_bound() -> None:
    many = " ".join(f"include:_spf{i}.vendor.example" for i in range(11))
    snap, resolver = await snapshot(zone_with(APEX__TXT=(f"v=spf1 {many} -all",)))
    f = ids(run_dns_email_checks([snap]))["DNS-SPF-TOO-MANY-LOOKUPS"]
    assert "at least" in f.evidence[1].value
    assert not any("vendor.example" in n for n, _ in resolver.asked)


@pytest.mark.parametrize(
    ("policy", "fid"),
    [
        (GOOD_POLICY.replace("mode: enforce", "mode: testing"), "DNS-MTA-STS-NOT-ENFORCED"),
        (GOOD_POLICY.replace("mx: *.l.google.com\n", ""), "DNS-MTA-STS-MX-MISMATCH"),
        ("version: STSv1\nmode: enforce\n", "DNS-MTA-STS-POLICY-ERROR"),
        (None, "DNS-MTA-STS-POLICY-ERROR"),  # 404
    ],
)
async def test_mta_sts_policy_problems(policy: str | None, fid: str) -> None:
    snap, _ = await snapshot(GOOD_ZONE, policy)
    assert fid in ids(run_dns_email_checks([snap]))


async def test_dangling_cname_takeover() -> None:
    zone = zone_with(**{"www_dot_APEX__CNAME": ("old-shop.herokuapp.com.",)})
    snap, _ = await snapshot(zone, nxdomain={(f"www.{D}", "A")})
    f = ids(run_dns_email_checks([snap]))["DNS-DANGLING-CNAME"]
    assert (f.severity, f.confidence) == (S.HIGH, C.MEDIUM)
    assert f.urls == (f"dns:www.{D}",) and "Heroku" in f.evidence[1].value
    other = zone_with(**{"www_dot_APEX__CNAME": ("gone.example.net.",)})
    snap2, _ = await snapshot(other, nxdomain={(f"www.{D}", "A")})
    assert ids(run_dns_email_checks([snap2]))["DNS-CNAME-UNRESOLVABLE"].severity is S.LOW
    alive, _ = await snapshot(zone)  # same CNAME, but it resolves: not dangling
    assert "DNS-DANGLING-CNAME" not in ids(run_dns_email_checks([alive]))


async def test_lookup_failures_are_not_reported_as_missing() -> None:
    snap, _ = await snapshot(GOOD_ZONE, errors={(D, "TXT"), (f"_dmarc.{D}", "TXT")})
    found = ids(run_dns_email_checks([snap]))
    assert "DNS-SPF-MISSING" not in found and "DNS-DMARC-MISSING" not in found
    assert found["DNS-NOT-ASSESSED"].severity is S.INFO


async def test_null_mx_skips_mail_transport_checks() -> None:
    snap, _ = await snapshot(zone_with(APEX__MX=("0 .",), APEX__TXT=None))
    found = ids(run_dns_email_checks([snap]))
    assert not {"DNS-MTA-STS-MISSING", "DNS-TLSRPT-MISSING", "DNS-DKIM-NOT-ASSESSED"} & set(found)
    assert "no MX" in found["DNS-SPF-MISSING"].evidence[0].value


# --- wiring ----------------------------------------------------------------------------------


@pytest.mark.real_dns
@respx.mock
def test_quick_runs_dns_with_mocked_resolver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone = zone_with(**{"_dmarc_dot_APEX__TXT": ("v=DMARC1; p=none",)})
    monkeypatch.setattr(dns_client, "system_resolve", FakeResolver(zone))
    respx.get(f"https://mta-sts.{D}/.well-known/mta-sts.txt").mock(
        return_value=httpx.Response(200, text=GOOD_POLICY)
    )
    respx.get(f"https://www.{D}/").mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"})
    )
    respx.route().mock(return_value=httpx.Response(404))
    assert main(["quick", f"https://www.{D}/", "--out", str(tmp_path)]) == 0
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert "dns_email" in data["checks_run"]
    assert "DNS-DMARC-NOT-ENFORCED" in {f["id"] for f in data["findings"]}
    assert f"https://mta-sts.{D}/.well-known/mta-sts.txt" in data["appendix"]["pages"]


@respx.mock
def test_scan_needs_full_for_dns(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        f'[[target]]\nhost = "{D}"\nauthorized_by = "self"\ndate = "2026-10-20"\n', encoding="utf-8"
    )
    respx.route().mock(return_value=httpx.Response(404))
    base = ["scan", f"https://{D}/", "--scope", str(scope), "--rate", "0"]
    assert main([*base, "--out", str(tmp_path / "a")]) in (0, 1)
    assert main([*base, "--out", str(tmp_path / "b"), "--full"]) in (0, 1)
    plain = json.loads(next((tmp_path / "a").glob("*.json")).read_text(encoding="utf-8"))
    full = json.loads(next((tmp_path / "b").glob("*.json")).read_text(encoding="utf-8"))
    assert "dns_email" not in plain["checks_run"] and "dns_email" in full["checks_run"]
