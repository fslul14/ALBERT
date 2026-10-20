"""Scope-checked DNS for the target's own domain, plus the MTA-STS policy file.

``DnsPolicy`` is the checkpoint: only names equal to or under the target's registrable
domain, only the listed record types. ``DnsClient.query`` checks it first, before any packet
(AST-tested). Third-party names (e.g. an SPF ``include:_spf.google.com``, an MX at a mail
provider) are never queried. DKIM selectors are never guessed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import dns.asyncresolver
import dns.exception
import dns.resolver

from albert.core.http_client import ClientLimits, FetchError, HttpClient
from albert.core.models import CollectedResponse, DnsAnswer, DnsSnapshot
from albert.core.scope import OutOfScopeError, ScopePolicy

ALLOWED_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "CAA", "DS", "DNSKEY", "TLSA", "NS"})
MAX_QUERIES = 60
MAX_SPF_DEPTH = 10

RawResolve = Callable[[str, str], Awaitable[DnsAnswer]]


def dns_name(name: str) -> str:
    """Lowercased, no trailing dot; DNS labels may contain underscores (_dmarc, _mta-sts)."""
    return name.strip().lower().rstrip(".")


class DnsPolicy:
    """Which names may be looked up: the target's registrable domain and names under it."""

    def __init__(self, domain: str) -> None:
        self.domain = dns_name(domain)

    def check(self, name: str, rtype: str) -> str:
        """Return the normalized name if allowed; raise OutOfScopeError otherwise."""
        n = dns_name(name)
        if rtype.upper() not in ALLOWED_TYPES:
            raise OutOfScopeError(f"DNS type {rtype} refused")
        if not n or not (n == self.domain or n.endswith("." + self.domain)):
            raise OutOfScopeError(f"DNS name {n!r} is outside {self.domain!r}")
        return n


async def system_resolve(name: str, rtype: str) -> DnsAnswer:
    """Query the system's configured recursive resolver (dnspython)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 8.0
    try:
        answer = await resolver.resolve(name, rtype, raise_on_no_answer=False, search=False)
    except dns.resolver.NXDOMAIN:
        return DnsAnswer(name, rtype, "nxdomain")
    except dns.exception.DNSException as e:
        return DnsAnswer(name, rtype, "error", error=f"{type(e).__name__}: {e}"[:200])
    if answer.rrset is None:
        return DnsAnswer(name, rtype, "noanswer")
    values = []
    for rdata in answer.rrset:
        if rtype == "TXT":
            values.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        else:
            values.append(rdata.to_text())
    return DnsAnswer(name, rtype, "ok", tuple(values))


class DnsClient:
    """Every lookup passes the policy first; a query budget caps the run."""

    def __init__(self, policy: DnsPolicy, resolve: RawResolve | None = None) -> None:
        self.policy = policy
        self._resolve = resolve or system_resolve
        self.answers: dict[tuple[str, str], DnsAnswer] = {}

    async def query(self, name: str, rtype: str) -> DnsAnswer:
        n = self.policy.check(name, rtype)
        key = (n, rtype.upper())
        if key in self.answers:
            return self.answers[key]
        if len(self.answers) >= MAX_QUERIES:
            return DnsAnswer(n, key[1], "error", error="DNS query budget spent")
        answer = await self._resolve(n, key[1])
        self.answers[key] = DnsAnswer(n, key[1], answer.status, answer.values, answer.error)
        return self.answers[key]


def _spf_targets(record: str) -> list[str]:
    """Domains named by include:/redirect= in an SPF record."""
    out = []
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            out.append(t.split(":", 1)[1])
        elif t.startswith("redirect="):
            out.append(t.split("=", 1)[1])
    return out


async def collect_dns(
    domain: str,
    host: str,
    *,
    resolve: RawResolve | None = None,
    fetch_policy: Callable[[str], Awaitable[CollectedResponse | None]] | None = None,
) -> DnsSnapshot:
    """Every record the email/DNS checks need, for the target's own domain only."""
    client = DnsClient(DnsPolicy(domain), resolve)
    d = client.policy.domain
    notes: list[str] = []
    for name, rtype in (
        (d, "TXT"),
        (f"_dmarc.{d}", "TXT"),
        (d, "MX"),
        (d, "DS"),
        (d, "DNSKEY"),
        (f"_mta-sts.{d}", "TXT"),
        (f"_smtp._tls.{d}", "TXT"),
        (f"default._bimi.{d}", "TXT"),
    ):
        await client.query(name, rtype)
    # CAA: closest record walking up from the host to the registrable domain (RFC 8659).
    labels = dns_name(host).split(".")
    for i in range(len(labels)):
        name = ".".join(labels[i:])
        if name == d or name.endswith("." + d):
            if (await client.query(name, "CAA")).values:
                break
    # Dangling-CNAME indicators for names already known: the host and the apex.
    for name in dict.fromkeys([dns_name(host), d]):
        if name == d or name.endswith("." + d):
            if (await client.query(name, "CNAME")).values:
                await client.query(name, "A")  # resolver follows the chain; NXDOMAIN = dangling
    # SPF includes inside the domain (third-party includes are counted, not expanded).
    pending = [
        t
        for v in client.answers[(d, "TXT")].values
        if v.lower().startswith("v=spf1")
        for t in _spf_targets(v)
    ]
    seen: set[str] = set()
    while pending and len(seen) < MAX_SPF_DEPTH:
        target = dns_name(pending.pop(0))
        if target in seen or not (target == d or target.endswith("." + d)):
            continue
        seen.add(target)
        for v in (await client.query(target, "TXT")).values:
            if v.lower().startswith("v=spf1"):
                pending += _spf_targets(v)
    # DANE: TLSA for MX hosts inside the domain only.
    off_domain = []
    for mx in client.answers[(d, "MX")].values:
        mx_host = dns_name(mx.split()[-1])
        if mx_host in ("", "."):
            continue  # null MX
        if mx_host == d or mx_host.endswith("." + d):
            await client.query(f"_25._tcp.{mx_host}", "TLSA")
        else:
            off_domain.append(mx_host)
    if off_domain:
        notes.append(f"DANE not checked for MX hosts outside {d}: {', '.join(off_domain)}")
    # MTA-STS policy file, only if the domain advertises MTA-STS.
    policy_resp = None
    sts = [v for v in client.answers[(f"_mta-sts.{d}", "TXT")].values if v.startswith("v=STSv1")]
    if sts and fetch_policy is not None:
        policy_resp = await fetch_policy(d)
    return DnsSnapshot(d, dns_name(host), tuple(client.answers.values()), policy_resp, tuple(notes))


async def fetch_mta_sts_policy(
    domain: str, limits: ClientLimits | None = None
) -> CollectedResponse | None:
    """GET exactly https://mta-sts.<domain>/.well-known/mta-sts.txt; no redirects (RFC 8461)."""
    policy = ScopePolicy.for_mta_sts(domain)
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    async with HttpClient(policy, limits or ClientLimits(max_requests=1)) as client:
        try:
            raw = await client.fetch_one(url)
        except (FetchError, OutOfScopeError) as e:
            return CollectedResponse(url, 0, (), text=f"(unreachable: {e})")
    text = raw.body[:65536].decode("utf-8", "replace")
    return CollectedResponse(raw.url, raw.status, raw.headers, text=text)
