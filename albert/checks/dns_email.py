"""DNS and email-security checks. Pure over a DnsSnapshot (the target's own published records).

Severity: missing/unenforced DMARC and SPF +all are Medium; a CNAME to a takeover-prone service
that no longer resolves is High; most other gaps are Low or Info. Records whose lookup
failed are reported as "not assessed", never as missing.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from albert.core.models import Confidence, DnsSnapshot, Evidence, Finding, Severity

S, C = Severity, Confidence
LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")
_SPF_TERM = re.compile(
    r"^[+\-~?]?(?:all|include:\S+|a(?::\S+)?(?:/\d+)?|mx(?::\S+)?(?:/\d+)?|ptr(?::\S+)?|"
    r"ip4:[\d./]+|ip6:[0-9a-f:./]+|exists:\S+)$|^(?:redirect|exp)=\S+$|^[a-z][a-z0-9_.-]*=\S*$",
    re.I,
)
# CNAME targets on services where a deleted resource can be re-claimed by anyone.
TAKEOVER_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("AWS S3", ".s3.amazonaws.com"),
    ("AWS S3", ".s3-website"),
    ("AWS Elastic Beanstalk", ".elasticbeanstalk.com"),
    ("Heroku", ".herokuapp.com"),
    ("Heroku", ".herokudns.com"),
    ("GitHub Pages", ".github.io"),
    ("Azure", ".azurewebsites.net"),
    ("Azure", ".cloudapp.net"),
    ("Azure", ".cloudapp.azure.com"),
    ("Azure", ".trafficmanager.net"),
    ("Azure", ".blob.core.windows.net"),
    ("Azure", ".azureedge.net"),
    ("Shopify", ".myshopify.com"),
    ("Ghost", ".ghost.io"),
    ("Pantheon", ".pantheonsite.io"),
    ("Surge", ".surge.sh"),
    ("Bitbucket", ".bitbucket.io"),
    ("Zendesk", ".zendesk.com"),
    ("Readme", ".readme.io"),
    ("Unbounce", ".unbouncepages.com"),
    ("Tumblr", ".domains.tumblr.com"),
    ("WordPress.com", ".wordpress.com"),
    ("Fly.io", ".fly.dev"),
)

_SPECS: dict[str, tuple[str, Severity, str, str, tuple[str, ...]]] = {
    "DNS-NOT-ASSESSED": (
        "Some DNS records could not be looked up",
        S.INFO,
        "These checks did not run; nothing is assumed missing.",
        "Re-run when DNS is reachable.",
        (),
    ),
    "DNS-SPF-MISSING": (
        "No SPF record",
        S.LOW,
        "Receivers can't tell which servers may send mail for the domain.",
        "Publish v=spf1 listing your senders, ending in -all ('v=spf1 -all' if you send no mail).",
        ("RFC 7208",),
    ),
    "DNS-SPF-MULTIPLE": (
        "More than one SPF record",
        S.LOW,
        "Multiple v=spf1 records are a permanent error: receivers ignore SPF entirely.",
        "Merge them into a single v=spf1 record.",
        ("RFC 7208",),
    ),
    "DNS-SPF-INVALID": (
        "SPF record has invalid terms",
        S.LOW,
        "Unknown terms make the record a permanent error at receivers.",
        "Fix the syntax (check with an SPF validator).",
        ("RFC 7208",),
    ),
    "DNS-SPF-PLUS-ALL": (
        "SPF allows every server (+all)",
        S.MEDIUM,
        "Anyone, anywhere, passes SPF for this domain; spoofed mail looks authorised.",
        "End the record with -all (or ~all while testing).",
        ("RFC 7208", "CWE-290"),
    ),
    "DNS-SPF-NEUTRAL": (
        "SPF ends neutrally (?all or no all)",
        S.LOW,
        "Unlisted senders get a neutral result, which gives no spoofing protection.",
        "End the record with -all (or ~all).",
        ("RFC 7208",),
    ),
    "DNS-SPF-TOO-MANY-LOOKUPS": (
        "SPF needs more than 10 DNS lookups",
        S.LOW,
        "Receivers stop at 10 lookups and treat SPF as a permanent error.",
        "Flatten includes or remove unused ones.",
        ("RFC 7208",),
    ),
    "DNS-SPF-PTR": (
        "SPF uses the deprecated ptr mechanism",
        S.INFO,
        "ptr is slow and unreliable; receivers may skip it.",
        "Replace ptr with ip4/ip6/a.",
        ("RFC 7208",),
    ),
    "DNS-DMARC-MISSING": (
        "No DMARC record",
        S.MEDIUM,
        "Nothing tells receivers to reject mail failing SPF/DKIM, so the domain is easy to spoof.",
        "Publish _dmarc with p=quarantine or p=reject (start at p=none with rua= to monitor).",
        ("RFC 7489",),
    ),
    "DNS-DMARC-INVALID": (
        "DMARC record is invalid",
        S.MEDIUM,
        "Receivers ignore an invalid (or duplicated) DMARC record, as if none existed.",
        "Publish exactly one record starting v=DMARC1; p=...",
        ("RFC 7489",),
    ),
    "DNS-DMARC-NOT-ENFORCED": (
        "DMARC policy is p=none (monitor only)",
        S.MEDIUM,
        "Failing mail is still delivered; DMARC isn't protecting against spoofing yet.",
        "Move to p=quarantine, then p=reject, once reports look clean.",
        ("RFC 7489",),
    ),
    "DNS-DMARC-PARTIAL": (
        "DMARC applies to only part of the mail (pct < 100)",
        S.LOW,
        "The rest of failing mail is not quarantined/rejected.",
        "Raise pct to 100.",
        ("RFC 7489",),
    ),
    "DNS-DMARC-SUBDOMAINS-NONE": (
        "DMARC leaves subdomains unenforced (sp=none)",
        S.LOW,
        "Attackers can spoof mail from any subdomain.",
        "Set sp=quarantine or sp=reject.",
        ("RFC 7489",),
    ),
    "DNS-DMARC-NO-REPORTS": (
        "DMARC has no aggregate report address (rua)",
        S.INFO,
        "You won't see who is sending as your domain.",
        "Add rua=mailto:...",
        ("RFC 7489",),
    ),
    "DNS-DKIM-NOT-ASSESSED": (
        "DKIM not assessed (selectors not discoverable)",
        S.INFO,
        "DKIM keys live under selectors that can't be found passively without guessing.",
        "Check DKIM signing in a received message's DKIM-Signature header.",
        ("RFC 6376",),
    ),
    "DNS-CAA-MISSING": (
        "No CAA record",
        S.LOW,
        "Any certificate authority may issue certificates for the domain.",
        'Publish CAA records naming the CAs you use (e.g. 0 issue "letsencrypt.org").',
        ("RFC 8659",),
    ),
    "DNS-DNSSEC-MISSING": (
        "DNSSEC not enabled (no DS record)",
        S.LOW,
        "DNS answers for the domain can't be authenticated (spoofing/cache poisoning).",
        "Enable DNSSEC at the DNS host and publish the DS record at the registrar.",
        ("RFC 4033",),
    ),
    "DNS-MTA-STS-MISSING": (
        "No MTA-STS policy",
        S.LOW,
        "Mail to this domain can be downgraded to unencrypted SMTP by an attacker on the path.",
        "Publish _mta-sts TXT and https://mta-sts.<domain>/.well-known/mta-sts.txt.",
        ("RFC 8461",),
    ),
    "DNS-MTA-STS-POLICY-ERROR": (
        "MTA-STS advertised but its policy is unusable",
        S.LOW,
        "Senders ignore MTA-STS when the policy file is missing, unreachable or invalid.",
        "Serve a valid policy (version: STSv1, mode, mx, max_age) over HTTPS without redirects.",
        ("RFC 8461",),
    ),
    "DNS-MTA-STS-NOT-ENFORCED": (
        "MTA-STS is not enforcing",
        S.INFO,
        "mode testing/none only reports; TLS is not required for delivery yet.",
        "Move to mode: enforce once TLS-RPT reports are clean.",
        ("RFC 8461",),
    ),
    "DNS-MTA-STS-MX-MISMATCH": (
        "MTA-STS policy doesn't cover every MX",
        S.LOW,
        "Mail to an uncovered MX fails (enforce) or isn't protected.",
        "List every MX host (or a matching *. pattern) in the policy's mx lines.",
        ("RFC 8461",),
    ),
    "DNS-TLSRPT-MISSING": (
        "No SMTP TLS reporting (TLS-RPT)",
        S.INFO,
        "You won't hear about failed or downgraded TLS deliveries.",
        "Publish _smtp._tls TXT: v=TLSRPTv1; rua=mailto:...",
        ("RFC 8460",),
    ),
    "DNS-BIMI-MISSING": (
        "No BIMI record",
        S.INFO,
        "Optional: a brand logo next to authenticated mail in supporting clients.",
        "Publish default._bimi TXT with an SVG logo (needs enforced DMARC).",
        (),
    ),
    "DNS-DANE-MISSING": (
        "No DANE/TLSA record for the MX",
        S.INFO,
        "Optional alongside MTA-STS: pins the MX certificate via DNSSEC.",
        "Publish _25._tcp.<mx> TLSA (requires DNSSEC).",
        ("RFC 7672",),
    ),
    "DNS-DANGLING-CNAME": (
        "CNAME points to an unclaimed resource on a takeover-prone service",
        S.HIGH,
        "Anyone can create that resource and serve content on this hostname (subdomain "
        "takeover): phishing, cookie theft, CSP bypass.",
        "Remove the CNAME or re-create the resource it points to.",
        ("CWE-350", "OWASP A05:2021"),
    ),
    "DNS-CNAME-UNRESOLVABLE": (
        "CNAME target does not resolve",
        S.LOW,
        "A dangling CNAME; if its target's domain can be registered, the name can be taken over.",
        "Remove the stale CNAME.",
        ("CWE-350",),
    ),
}


def _hit(
    snap: DnsSnapshot,
    fid: str,
    *evidence: Evidence,
    conf: Confidence = C.HIGH,
    name: str | None = None,
) -> Finding:
    title, sev, impact, fix, refs = _SPECS[fid]
    return Finding(
        fid, title, sev, conf, (f"dns:{name or snap.domain}",), evidence, impact, fix, refs
    )


def _ev(name: str, rtype: str, value: str) -> Evidence:
    return Evidence("dns", value if len(value) <= 300 else value[:300] + "...", f"{rtype} {name}")


def _tags(record: str) -> dict[str, str]:
    out = {}
    for part in record.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k.strip().lower()] = v.strip()
    return out


def _mail_domain(snap: DnsSnapshot) -> tuple[bool, list[str]]:
    """(accepts mail?, MX hosts). A null MX ('0 .') means it explicitly doesn't."""
    hosts = [mx.split()[-1].rstrip(".").lower() for mx in snap.values(snap.domain, "MX")]
    real = [h for h in hosts if h]
    return bool(real), real


def _spf_lookups(snap: DnsSnapshot, record: str, depth: int = 0) -> tuple[int, int]:
    """(DNS lookups counted, third-party includes left unexpanded)."""
    count = unexpanded = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if not t.startswith(LOOKUP_MECHANISMS) or t.startswith(("ip4", "ip6", "all")):
            continue
        count += 1
        if t.startswith(("include:", "redirect=")) and depth < 10:
            target = re.split(r"[:=]", t, maxsplit=1)[1]
            child = [v for v in snap.values(target, "TXT") if v.lower().startswith("v=spf1")]
            if child:
                c, u = _spf_lookups(snap, child[0], depth + 1)
                count, unexpanded = count + c, unexpanded + u
            elif snap.get(target, "TXT") is None:
                unexpanded += 1  # outside the domain: never queried
    return count, unexpanded


def check_spf(snap: DnsSnapshot) -> list[Finding]:
    """SPF presence, uniqueness, syntax, all-qualifier and the 10-lookup limit."""
    d = snap.domain
    records = [v for v in snap.values(d, "TXT") if v.lower().startswith("v=spf1")]
    if not records:
        accepts, _ = _mail_domain(snap)
        ev = _ev(d, "TXT", "(no v=spf1 record)" + ("" if accepts else "; domain has no MX"))
        return [_hit(snap, "DNS-SPF-MISSING", ev)]
    if len(records) > 1:
        return [_hit(snap, "DNS-SPF-MULTIPLE", *(_ev(d, "TXT", r) for r in records))]
    rec = records[0]
    ev = _ev(d, "TXT", rec)
    out = []
    terms = rec.split()[1:]
    if bad := [t for t in terms if not _SPF_TERM.match(t)]:
        out.append(
            _hit(snap, "DNS-SPF-INVALID", ev, Evidence("dns", ", ".join(bad), "unknown terms"))
        )
    alls = [t for t in terms if t.lstrip("+-~?").lower() == "all"]
    has_redirect = any(t.lower().startswith("redirect=") for t in terms)
    if any(t.lower() in ("all", "+all") for t in alls):
        out.append(_hit(snap, "DNS-SPF-PLUS-ALL", ev))
    elif any(t.lower() == "?all" for t in alls) or (not alls and not has_redirect):
        out.append(_hit(snap, "DNS-SPF-NEUTRAL", ev))
    count, unexpanded = _spf_lookups(snap, rec)
    if count > 10:
        detail = f"{count} lookups" + (
            f" (at least; {unexpanded} third-party include(s) not expanded)" if unexpanded else ""
        )
        out.append(_hit(snap, "DNS-SPF-TOO-MANY-LOOKUPS", ev, Evidence("dns", detail, "count")))
    if any(t.lstrip("+-~?").lower().startswith("ptr") for t in terms):
        out.append(_hit(snap, "DNS-SPF-PTR", ev))
    return out


def _dmarc_records(snap: DnsSnapshot) -> list[str]:
    name = f"_dmarc.{snap.domain}"
    return [
        v for v in snap.values(name, "TXT") if v.lower().replace(" ", "").startswith("v=dmarc1")
    ]


def dmarc_policy(snap: DnsSnapshot) -> str | None:
    """The DMARC p= value if exactly one record exists."""
    recs = _dmarc_records(snap)
    if len(recs) != 1:
        return None
    return _tags(recs[0]).get("p", "").lower() or None


def check_dmarc(snap: DnsSnapshot) -> list[Finding]:
    """DMARC presence, validity and enforcement."""
    name = f"_dmarc.{snap.domain}"
    recs = _dmarc_records(snap)
    if not recs:
        return [
            _hit(snap, "DNS-DMARC-MISSING", _ev(name, "TXT", "(no v=DMARC1 record)"), name=name)
        ]
    if len(recs) > 1:
        return [_hit(snap, "DNS-DMARC-INVALID", *(_ev(name, "TXT", r) for r in recs), name=name)]
    tags = _tags(recs[0])
    ev = _ev(name, "TXT", recs[0])
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        return [
            _hit(
                snap,
                "DNS-DMARC-INVALID",
                ev,
                Evidence("dns", f"p={p or '(missing)'}", "policy"),
                name=name,
            )
        ]
    out = []
    if p == "none":
        out.append(_hit(snap, "DNS-DMARC-NOT-ENFORCED", ev, name=name))
    else:
        if tags.get("pct", "100").isdigit() and int(tags.get("pct", "100")) < 100:
            out.append(_hit(snap, "DNS-DMARC-PARTIAL", ev, name=name))
        if tags.get("sp", "").lower() == "none":
            out.append(_hit(snap, "DNS-DMARC-SUBDOMAINS-NONE", ev, name=name))
    if "rua" not in tags:
        out.append(_hit(snap, "DNS-DMARC-NO-REPORTS", ev, name=name))
    return out


def check_infrastructure(snap: DnsSnapshot) -> list[Finding]:
    """CAA, DNSSEC, and dangling-CNAME indicators."""
    d = snap.domain
    out = []
    caa_names = [a.name for a in snap.answers if a.rtype == "CAA"]
    if caa_names and not any(snap.values(n, "CAA") for n in caa_names):
        out.append(_hit(snap, "DNS-CAA-MISSING", _ev(d, "CAA", f"none on {', '.join(caa_names)}")))
    if snap.get(d, "DS") and snap.get(d, "DS").status in ("noanswer", "nxdomain"):  # type: ignore[union-attr]
        out.append(_hit(snap, "DNS-DNSSEC-MISSING", _ev(d, "DS", "(no DS record)")))
    for a in snap.answers:
        if a.rtype != "CNAME" or not a.values:
            continue
        target = a.values[0].rstrip(".").lower()
        resolved = snap.get(a.name, "A")
        dead = resolved is not None and resolved.status == "nxdomain"
        service = next((svc for svc, sfx in TAKEOVER_SUFFIXES if sfx in "." + target), None)
        ev = _ev(a.name, "CNAME", f"{a.name} -> {target}" + (" (NXDOMAIN)" if dead else ""))
        if dead and service:
            out.append(
                _hit(
                    snap,
                    "DNS-DANGLING-CNAME",
                    ev,
                    Evidence("dns", service, "service"),
                    conf=C.MEDIUM,
                    name=a.name,
                )
            )
        elif dead:
            out.append(_hit(snap, "DNS-CNAME-UNRESOLVABLE", ev, conf=C.LOW, name=a.name))
    return out


def _mx_covered(mx: str, patterns: list[str]) -> bool:
    for p in patterns:
        p = p.lower().rstrip(".")
        if p == mx or (p.startswith("*.") and mx.endswith(p[1:]) and mx.count(".") == p.count(".")):
            return True
    return False


def check_mail_transport(snap: DnsSnapshot) -> list[Finding]:
    """MTA-STS, TLS-RPT, BIMI, DANE: only for domains that receive mail."""
    accepts, mx_hosts = _mail_domain(snap)
    if not accepts:
        return []
    d, out = snap.domain, []
    sts_name = f"_mta-sts.{d}"
    sts = [v for v in snap.values(sts_name, "TXT") if v.startswith("v=STSv1")]
    if not sts:
        out.append(
            _hit(
                snap,
                "DNS-MTA-STS-MISSING",
                _ev(sts_name, "TXT", "(no v=STSv1 record)"),
                name=sts_name,
            )
        )
    else:
        resp = snap.mta_sts_policy
        fields: dict[str, list[str]] = {}
        if resp is not None and resp.status == 200:
            for line in resp.text.splitlines():
                k, _, v = line.partition(":")
                if v:
                    fields.setdefault(k.strip().lower(), []).append(v.strip())
        url = resp.url if resp is not None else f"https://mta-sts.{d}/.well-known/mta-sts.txt"
        mode = (fields.get("mode") or [""])[0].lower()
        if (
            fields.get("version") != ["STSv1"]
            or mode not in ("enforce", "testing", "none")
            or not fields.get("max_age")
        ):
            why = (
                f"HTTP {resp.status}"
                if resp is not None and resp.status != 200
                else (
                    resp.text[:120]
                    if resp is not None and resp.status == 0
                    else "missing version/mode/max_age"
                )
            )
            out.append(
                _hit(
                    snap,
                    "DNS-MTA-STS-POLICY-ERROR",
                    Evidence("https", why, url),
                    name=f"mta-sts.{d}",
                )
            )
        else:
            if mode != "enforce":
                out.append(
                    _hit(
                        snap,
                        "DNS-MTA-STS-NOT-ENFORCED",
                        Evidence("https", f"mode: {mode}", url),
                        name=f"mta-sts.{d}",
                    )
                )
            if uncovered := [m for m in mx_hosts if not _mx_covered(m, fields.get("mx", []))]:
                out.append(
                    _hit(
                        snap,
                        "DNS-MTA-STS-MX-MISMATCH",
                        Evidence("https", ", ".join(uncovered), "MX not in policy"),
                        name=f"mta-sts.{d}",
                    )
                )
    rpt = f"_smtp._tls.{d}"
    if not any(v.startswith("v=TLSRPTv1") for v in snap.values(rpt, "TXT")):
        out.append(
            _hit(snap, "DNS-TLSRPT-MISSING", _ev(rpt, "TXT", "(no v=TLSRPTv1 record)"), name=rpt)
        )
    bimi = f"default._bimi.{d}"
    if dmarc_policy(snap) in ("quarantine", "reject") and not any(
        v.startswith("v=BIMI1") for v in snap.values(bimi, "TXT")
    ):
        out.append(
            _hit(snap, "DNS-BIMI-MISSING", _ev(bimi, "TXT", "(no v=BIMI1 record)"), name=bimi)
        )
    for mx in mx_hosts:
        tlsa = snap.get(f"_25._tcp.{mx}", "TLSA")
        if tlsa is not None and not tlsa.values and tlsa.status != "error":
            out.append(
                _hit(
                    snap,
                    "DNS-DANE-MISSING",
                    _ev(f"_25._tcp.{mx}", "TLSA", "(no TLSA record)"),
                    name=mx,
                )
            )
    return out


def check_dkim(snap: DnsSnapshot) -> list[Finding]:
    """DKIM can't be assessed passively (selectors are never guessed)."""
    accepts, _ = _mail_domain(snap)
    if not accepts:
        return []
    return [
        _hit(
            snap,
            "DNS-DKIM-NOT-ASSESSED",
            Evidence("dns", "selectors unknown; none guessed", "DKIM"),
        )
    ]


def run_dns_email_checks(snapshots: Sequence[DnsSnapshot]) -> list[Finding]:
    """All DNS/email checks. A record that wasn't answered (lookup failed, or never queried)
    suppresses the checks that need it: "not assessed" is never reported as "missing"."""
    out: list[Finding] = []
    for snap in snapshots:
        failed = [a for a in snap.answers if a.status == "error"]
        failed_keys = {(a.name, a.rtype) for a in failed}
        d = snap.domain

        def answered(name: str, rtype: str, snap: DnsSnapshot = snap) -> bool:
            a = snap.get(name, rtype)
            return a is not None and a.status != "error"

        if answered(d, "TXT"):
            out += check_spf(snap)
        if answered(f"_dmarc.{d}", "TXT"):
            out += check_dmarc(snap)
        if answered(d, "MX"):
            out += check_mail_transport(snap) + check_dkim(snap)
        out += [
            f
            for f in check_infrastructure(snap)
            if not (f.id == "DNS-DNSSEC-MISSING" and (d, "DS") in failed_keys)
            and not (f.id == "DNS-CAA-MISSING" and any(k[1] == "CAA" for k in failed_keys))
        ]
        if failed:
            out.append(
                _hit(
                    snap,
                    "DNS-NOT-ASSESSED",
                    *(Evidence("dns", a.error or a.status, f"{a.rtype} {a.name}") for a in failed),
                )
            )
    return out
