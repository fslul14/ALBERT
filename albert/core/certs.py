"""X.509 certificate parsing with `cryptography`. Pure: DER bytes in, CertInfo out."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from albert.core.models import CertInfo


def _key(cert: x509.Certificate) -> tuple[str, int]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448
    return type(key).__name__, 0


def _sans(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    return tuple(ext.value.get_values_for_type(x509.DNSName))


def _scts(cert: x509.Certificate) -> int:
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
    except x509.ExtensionNotFound:
        return 0
    return len(ext.value)


def cert_info(cert: x509.Certificate) -> CertInfo:
    """Facts the TLS checks need from one certificate."""
    key_type, key_bits = _key(cert)
    sig = cert.signature_hash_algorithm
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        sans=_sans(cert),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        signature_hash=sig.name if sig else None,
        key_type=key_type,
        key_bits=key_bits,
        self_issued=cert.subject == cert.issuer,
        embedded_scts=_scts(cert),
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
    )


def parse_der(der: bytes) -> CertInfo:
    """Parse a DER-encoded certificate."""
    return cert_info(x509.load_der_x509_certificate(der))
