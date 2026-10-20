"""TLS/certificate checks. Pure: TLSObservation (and HTTP hops) in, findings out.

Certificate validity comes from OpenSSL's verify result and maps to exactly ONE finding
(OpenSSL reports the first failure), so a bad cert yields its one obvious High.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from albert.core.models import (
    CertInfo,
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    Severity,
    TLSObservation,
)

S, C = Severity, Confidence
A02 = "OWASP A02:2021"
A05 = "OWASP A05:2021"

_SPECS: dict[str, tuple[str, Severity, str, str, tuple[str, ...]]] = {
    "TLS-UNAVAILABLE": (
        "HTTPS not available",
        S.MEDIUM,
        "No TLS handshake was possible, so traffic can only travel unencrypted.",
        "Serve the site over HTTPS (e.g. a free ACME certificate).",
        ("CWE-319", A02),
    ),
    "TLS-CERT-EXPIRED": (
        "Certificate has expired",
        S.HIGH,
        "Browsers block the site with a full-page warning; users who click through are exposed "
        "to interception.",
        "Renew the certificate and automate renewal.",
        ("CWE-298", A02),
    ),
    "TLS-CERT-NOT-YET-VALID": (
        "Certificate not yet valid",
        S.HIGH,
        "Browsers reject the certificate until its start date.",
        "Check the server clock and the certificate's validity period.",
        ("CWE-298", A02),
    ),
    "TLS-CERT-HOSTNAME-MISMATCH": (
        "Certificate does not match the hostname",
        S.HIGH,
        "Browsers block the site; the certificate was issued for other names.",
        "Install a certificate whose SAN list covers this hostname.",
        ("CWE-297", A02),
    ),
    "TLS-CERT-SELF-SIGNED": (
        "Self-signed certificate",
        S.HIGH,
        "No trusted CA vouches for the server; browsers block it and users can't tell an "
        "attacker's certificate from the real one.",
        "Use a certificate from a publicly trusted CA.",
        ("CWE-295", A02),
    ),
    "TLS-CERT-UNTRUSTED": (
        "Certificate chain not trusted",
        S.HIGH,
        "The chain doesn't lead to a trusted root; browsers block the site.",
        "Use a publicly trusted CA and serve the full chain.",
        ("CWE-295", A02),
    ),
    "TLS-CHAIN-INCOMPLETE": (
        "Certificate chain incomplete (intermediate missing)",
        S.MEDIUM,
        "Some clients (many mobile/API clients) fail; browsers may patch it via AIA/caches.",
        "Serve the leaf plus all intermediate certificates.",
        ("CWE-295",),
    ),
    "TLS-CERT-EXPIRING": (
        "Certificate expires soon",
        S.LOW,
        "The site will break for all visitors when it lapses.",
        "Renew now and automate renewal (ACME).",
        ("CWE-298",),
    ),
    "TLS-CERT-WEAK-SIGNATURE": (
        "Weak certificate signature algorithm",
        S.MEDIUM,
        "SHA-1/MD5 signatures are forgeable in practice and rejected by modern browsers.",
        "Reissue with a SHA-256 (or better) signature.",
        ("CWE-327", A02),
    ),
    "TLS-CERT-WEAK-KEY": (
        "Weak certificate key",
        S.MEDIUM,
        "Small keys can be factored/broken with feasible effort.",
        "Use RSA >= 2048 bits or ECDSA P-256+.",
        ("CWE-326", A02),
    ),
    "TLS-PROTO-SSL": (
        "Obsolete SSL protocol accepted (SSLv2/SSLv3)",
        S.MEDIUM,
        "SSLv3 is broken (POODLE) and SSLv2 worse; legacy clients can be downgraded to them.",
        "Disable SSLv2 and SSLv3.",
        ("CWE-327", A02),
    ),
    "TLS-PROTO-LEGACY": (
        "Deprecated TLS 1.0/1.1 accepted",
        S.LOW,
        "RFC 8996 deprecates TLS 1.0/1.1; they lack modern cipher modes.",
        "Allow only TLS 1.2 and 1.3.",
        ("CWE-327", A02),
    ),
    "TLS-PROTO-NO-MODERN": (
        "No TLS 1.2 or 1.3 support",
        S.MEDIUM,
        "Modern clients refuse to connect or fall back to weak protocols.",
        "Enable TLS 1.2 and TLS 1.3.",
        ("CWE-327", A02),
    ),
    "TLS-NO-TLS13": (
        "TLS 1.3 not supported",
        S.INFO,
        "Informational: TLS 1.3 is faster and removes legacy options.",
        "Enable TLS 1.3.",
        (),
    ),
    "TLS-CIPHER-WEAK": (
        "Insecure cipher suites accepted",
        S.MEDIUM,
        "NULL/EXPORT/anonymous/RC4/DES/3DES suites allow decryption or impersonation.",
        "Disable these suites; prefer AEAD (AES-GCM, ChaCha20-Poly1305) with ECDHE.",
        ("CWE-327", A02),
    ),
    "TLS-CIPHER-NO-FS": (
        "Cipher suites without forward secrecy accepted",
        S.LOW,
        "Recorded traffic can be decrypted later if the server key leaks.",
        "Prefer ECDHE/DHE suites; drop static-RSA key exchange.",
        ("CWE-327",),
    ),
    "TLS-NO-SCT": (
        "No embedded Certificate Transparency SCTs",
        S.INFO,
        "Informational: SCTs may still arrive via TLS extension or OCSP stapling.",
        "Normally handled by the CA; check if clients report CT errors.",
        (),
    ),
    "TLS-ENUM-NOT-TESTED": (
        "Protocol/cipher enumeration not completed",
        S.INFO,
        "Deprecated-protocol and weak-cipher checks did not run for this host.",
        "Re-run when the host is reachable.",
        (),
    ),
    "TLS-HTTP-NO-REDIRECT": (
        "HTTP does not redirect to HTTPS",
        S.MEDIUM,
        "Visitors who type the bare domain or follow http:// links stay on plain HTTP.",
        "Redirect all http:// requests to https:// (301) and add HSTS.",
        ("CWE-319", A02),
    ),
    "TLS-HTTPS-DOWNGRADE": (
        "HTTPS redirects to plain HTTP",
        S.MEDIUM,
        "A redirect chain drops from HTTPS to HTTP, exposing the request and cookies.",
        "Make every redirect target https://.",
        ("CWE-319", A02),
    ),
}

_INSECURE_CIPHER = re.compile(r"NULL|EXPORT|_anon_|RC4|_DES_|3DES|DES40|_RC2_|_MD5$|IDEA", re.I)
_EXPIRING_DAYS = 14


def _hit(url: str, fid: str, *evidence: Evidence, conf: Confidence = C.HIGH) -> Finding:
    title, sev, impact, fix, refs = _SPECS[fid]
    return Finding(fid, title, sev, conf, (url,), evidence, impact, fix, refs)


def _cert_ev(cert: CertInfo) -> Evidence:
    return Evidence(
        "cert",
        f"subject={cert.subject}; issuer={cert.issuer}; "
        f"valid {cert.not_before:%Y-%m-%d} to {cert.not_after:%Y-%m-%d}; "
        f"SANs={', '.join(cert.sans[:5])}",
        "leaf certificate",
    )


def _validity(obs: TLSObservation) -> list[Finding]:
    """Exactly one finding for a failed verification, mapped from the OpenSSL verify code."""
    if obs.verify_error is None:
        return []
    msg = obs.verify_error.lower()
    code = obs.verify_code
    ev = [Evidence("tls", obs.verify_error, "verification")]
    if obs.leaf:
        ev.append(_cert_ev(obs.leaf))
    if code == 10 or "expired" in msg:
        fid = "TLS-CERT-EXPIRED"
    elif code == 9 or "not yet valid" in msg:
        fid = "TLS-CERT-NOT-YET-VALID"
    elif code == 62 or "hostname mismatch" in msg or "doesn't match" in msg:
        fid = "TLS-CERT-HOSTNAME-MISMATCH"
    elif code in (18, 19) or "self-signed" in msg or "self signed" in msg:
        fid = "TLS-CERT-SELF-SIGNED"
    elif code in (2, 20, 21) and len(obs.chain) == 1 and not obs.chain[0].self_issued:
        fid = "TLS-CHAIN-INCOMPLETE"  # sslyze saw only the leaf: intermediate not served
    elif msg.startswith("handshake failed"):
        return []  # couldn't verify, but the lax handshake worked; protocol checks cover it
    else:
        fid = "TLS-CERT-UNTRUSTED"
    return [_hit(obs.url, fid, *ev)]


def _cert_quality(obs: TLSObservation, now: datetime) -> list[Finding]:
    out: list[Finding] = []
    leaf = obs.leaf
    if leaf is None:
        return out
    if obs.verify_error is None and leaf.not_after - now < timedelta(days=_EXPIRING_DAYS):
        out.append(_hit(obs.url, "TLS-CERT-EXPIRING", _cert_ev(leaf)))
    chain = obs.chain or (leaf,)
    weak_sig = [c for c in chain if not c.self_issued and c.signature_hash in {"sha1", "md5"}]
    if weak_sig:
        out.append(
            _hit(
                obs.url,
                "TLS-CERT-WEAK-SIGNATURE",
                *(
                    Evidence("cert", f"{c.subject}: {c.signature_hash}", "signature")
                    for c in weak_sig
                ),
            )
        )
    weak_key = (
        (leaf.key_type == "RSA" and leaf.key_bits < 2048)
        or (leaf.key_type == "EC" and leaf.key_bits < 256)
        or leaf.key_type == "DSA"
    )
    if weak_key:
        out.append(
            _hit(
                obs.url,
                "TLS-CERT-WEAK-KEY",
                Evidence("cert", f"{leaf.key_type} {leaf.key_bits} bits", "key"),
            )
        )
    if leaf.embedded_scts == 0 and not leaf.self_issued and obs.verify_error is None:
        out.append(_hit(obs.url, "TLS-NO-SCT", Evidence("cert", "0 embedded SCTs", "CT")))
    return out


def _protocols_and_ciphers(obs: TLSObservation) -> list[Finding]:
    if not obs.enumerated:
        why = obs.enum_error or "enumeration disabled"
        return [_hit(obs.url, "TLS-ENUM-NOT-TESTED", Evidence("tls", why, "sslyze"))]
    accepted = {proto for proto, ok in obs.protocols if ok}
    out = []
    if old_ssl := sorted(accepted & {"SSLv2", "SSLv3"}):
        out.append(_hit(obs.url, "TLS-PROTO-SSL", Evidence("tls", ", ".join(old_ssl), "accepted")))
    if legacy := sorted(accepted & {"TLSv1.0", "TLSv1.1"}):
        out.append(
            _hit(obs.url, "TLS-PROTO-LEGACY", Evidence("tls", ", ".join(legacy), "accepted"))
        )
    if not accepted & {"TLSv1.2", "TLSv1.3"}:
        out.append(
            _hit(
                obs.url,
                "TLS-PROTO-NO-MODERN",
                Evidence("tls", ", ".join(sorted(accepted)) or "none", "accepted"),
            )
        )
    elif "TLSv1.3" not in accepted:
        out.append(_hit(obs.url, "TLS-NO-TLS13", Evidence("tls", "TLSv1.3 rejected", "accepted")))
    weak = sorted({f"{p} {n}" for p, n, _ in obs.accepted_ciphers if _INSECURE_CIPHER.search(n)})
    if weak:
        out.append(
            _hit(
                obs.url, "TLS-CIPHER-WEAK", *(Evidence("cipher", w, "accepted") for w in weak[:20])
            )
        )
    no_fs = sorted(
        {
            f"{p} {n}"
            for p, n, fs in obs.accepted_ciphers
            if not fs and not _INSECURE_CIPHER.search(n)
        }
    )
    if no_fs:
        out.append(
            _hit(
                obs.url,
                "TLS-CIPHER-NO-FS",
                *(Evidence("cipher", c, "accepted") for c in no_fs[:20]),
            )
        )
    return out


def check_tls(obs: TLSObservation, now: datetime | None = None) -> list[Finding]:
    """All certificate/protocol/cipher checks for one host."""
    now = now or datetime.now(UTC)
    if obs.error:
        return [_hit(obs.url, "TLS-UNAVAILABLE", Evidence("tls", obs.error, "handshake"))]
    return _validity(obs) + _cert_quality(obs, now) + _protocols_and_ciphers(obs)


def check_http_redirect(http_hops: Sequence[CollectedResponse]) -> list[Finding]:
    """The plain-HTTP start page should redirect to HTTPS."""
    if not http_hops or urlsplit(http_hops[0].url).scheme != "http":
        return []
    final = http_hops[-1]
    if urlsplit(final.url).scheme == "https" or final.status >= 400:
        return []
    chain = " -> ".join(f"{h.url} ({h.status})" for h in http_hops)
    return [
        _hit(http_hops[0].url, "TLS-HTTP-NO-REDIRECT", Evidence("http", chain, "redirect chain"))
    ]


def check_downgrade(hops: Sequence[CollectedResponse]) -> list[Finding]:
    """Any https -> http step in a redirect chain."""
    out = []
    for a, b in zip(hops, hops[1:], strict=False):
        if urlsplit(a.url).scheme == "https" and urlsplit(b.url).scheme == "http":
            out.append(
                _hit(
                    a.url,
                    "TLS-HTTPS-DOWNGRADE",
                    Evidence("http", f"{a.url} -> {b.url}", "redirect"),
                )
            )
    return out
