"""TLS module tests: pure checks on generated certificates, the scope-first guarantee, the
sslyze allowlist, and a real handshake against a local 127.0.0.1 server. No live hosts.
"""

import ast
import asyncio
import socket
import ssl
import threading
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from sslyze import ScanCommand

from albert.checks.tls import check_downgrade, check_http_redirect, check_tls
from albert.core import tls_client
from albert.core.certs import cert_info
from albert.core.models import CertInfo, CollectedResponse, Severity, TLSObservation
from albert.core.scope import OutOfScopeError, ScopePolicy
from albert.core.tls_client import SSLYZE_COMMANDS, TLSLimits, collect_tls, sslyze_probe

NOW = datetime(2026, 10, 20, tzinfo=UTC)
FORBIDDEN = {
    ScanCommand.HEARTBLEED,
    ScanCommand.OPENSSL_CCS_INJECTION,
    ScanCommand.SESSION_RENEGOTIATION,
    ScanCommand.ROBOT,
    ScanCommand.TLS_COMPRESSION,
    ScanCommand.TLS_FALLBACK_SCSV,
    ScanCommand.TLS_1_3_EARLY_DATA,
    ScanCommand.SESSION_RESUMPTION,
    ScanCommand.HTTP_HEADERS,
    ScanCommand.TLS_EXTENDED_MASTER_SECRET,
    ScanCommand.ELLIPTIC_CURVES,
}


def make_cert(
    *,
    cn: str = "shop.test",
    days: tuple[int, int] = (-30, 60),
    key: Any = None,
    sig: Any = None,
    issuer_cn: str | None = None,
) -> tuple[x509.Certificate, Any]:
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days[0]))
        .not_valid_after(now + timedelta(days=days[1]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, sig or hashes.SHA256())
    )
    return cert, key


def info(**kw: Any) -> CertInfo:
    return cert_info(make_cert(**kw)[0])


def obs(**kw: Any) -> TLSObservation:
    base: dict[str, Any] = {
        "host": "shop.test",
        "protocol": "TLSv1.3",
        "leaf": info(issuer_cn="Test CA"),
        "enumerated": True,
        "protocols": (("TLSv1.2", True), ("TLSv1.3", True)),
    }
    base.update(kw)
    return TLSObservation(**base)


def ids(findings: list[Any]) -> list[str]:
    return sorted(f.id for f in findings)


# --- cert parsing + pure checks -----------------------------------------------------------


def test_cert_info_parsing() -> None:
    c = info(cn="a.test", key=rsa.generate_private_key(65537, 1024))  # noqa: S505 weak on purpose
    assert c.sans == ("a.test",) and c.key_type == "RSA" and c.key_bits == 1024
    assert c.signature_hash == "sha256" and c.self_issued and c.embedded_scts == 0


def test_healthy_host_has_no_findings_above_info() -> None:
    found = check_tls(obs(), NOW)
    assert all(f.severity is Severity.INFO for f in found)  # only "no embedded SCT"


@pytest.mark.parametrize(
    ("code", "message", "expected"),
    [
        (10, "certificate has expired", "TLS-CERT-EXPIRED"),
        (9, "certificate is not yet valid", "TLS-CERT-NOT-YET-VALID"),
        (
            62,
            "Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'.",
            "TLS-CERT-HOSTNAME-MISMATCH",
        ),
        (18, "self-signed certificate", "TLS-CERT-SELF-SIGNED"),
        (19, "self-signed certificate in certificate chain", "TLS-CERT-SELF-SIGNED"),
        (20, "unable to get local issuer certificate", "TLS-CERT-UNTRUSTED"),
    ],
)
def test_each_verify_error_is_exactly_one_high(code: int, message: str, expected: str) -> None:
    found = check_tls(obs(verify_code=code, verify_error=message), NOW)
    highs = [f for f in found if f.severity is Severity.HIGH]
    assert [f.id for f in highs] == [expected]


def test_incomplete_chain_is_medium() -> None:
    leaf = info(issuer_cn="Intermediate CA")
    found = check_tls(
        obs(
            verify_code=20,
            verify_error="unable to get local issuer certificate",
            leaf=leaf,
            chain=(leaf,),
        ),
        NOW,
    )
    assert "TLS-CHAIN-INCOMPLETE" in ids(found)
    assert not any(f.severity is Severity.HIGH for f in found)


def test_cert_quality() -> None:
    # cryptography >= 46 refuses to create SHA-1 signatures, so set the parsed field instead.
    weak = replace(
        info(key=rsa.generate_private_key(65537, 1024), issuer_cn="CA", days=(-300, 5)),  # noqa: S505
        signature_hash="sha1",
    )
    found = ids(check_tls(obs(leaf=weak), datetime.now(UTC)))
    assert {"TLS-CERT-WEAK-KEY", "TLS-CERT-WEAK-SIGNATURE", "TLS-CERT-EXPIRING"} <= set(found)


def test_protocols_and_ciphers() -> None:
    o = obs(
        protocols=(
            ("SSLv3", True),
            ("TLSv1.0", True),
            ("TLSv1.1", False),
            ("TLSv1.2", True),
            ("TLSv1.3", False),
        ),
        accepted_ciphers=(
            ("TLSv1.2", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", False),
            ("TLSv1.2", "TLS_RSA_WITH_AES_128_GCM_SHA256", False),
            ("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", True),
        ),
    )
    found = {f.id: f for f in check_tls(o, NOW)}
    assert found["TLS-PROTO-SSL"].severity is Severity.MEDIUM
    assert [e.value for e in found["TLS-PROTO-LEGACY"].evidence] == ["TLSv1.0"]
    assert "TLS-NO-TLS13" in found
    assert [e.value for e in found["TLS-CIPHER-WEAK"].evidence] == [
        "TLSv1.2 TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    ]
    assert [e.value for e in found["TLS-CIPHER-NO-FS"].evidence] == [
        "TLSv1.2 TLS_RSA_WITH_AES_128_GCM_SHA256"
    ]
    only_old = check_tls(
        obs(protocols=(("TLSv1.0", True), ("TLSv1.2", False), ("TLSv1.3", False))), NOW
    )
    assert "TLS-PROTO-NO-MODERN" in ids(only_old)


def test_unavailable_and_not_enumerated() -> None:
    assert ids(check_tls(TLSObservation("x.test", error="ConnectionRefusedError"), NOW)) == [
        "TLS-UNAVAILABLE"
    ]
    assert "TLS-ENUM-NOT-TESTED" in ids(check_tls(obs(enumerated=False, enum_error="timeout"), NOW))


def _hop(url: str, status: int, location: str | None = None) -> CollectedResponse:
    headers = (("Location", location),) if location else ()
    return CollectedResponse(url, status, headers)


def test_http_redirect_and_downgrade() -> None:
    good = [_hop("http://shop.test/", 301), _hop("https://shop.test/", 200)]
    assert check_http_redirect(good) == []
    plain = [_hop("http://shop.test/", 200)]
    assert ids(check_http_redirect(plain)) == ["TLS-HTTP-NO-REDIRECT"]
    down = [_hop("https://shop.test/", 302), _hop("http://shop.test/login", 200)]
    assert ids(check_downgrade(down)) == ["TLS-HTTPS-DOWNGRADE"]


# --- scope first, before any socket -------------------------------------------------------


class SocketOpenedError(Exception):
    pass


@pytest.fixture
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise SocketOpenedError

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


POLICY = ScopePolicy(frozenset({"shop.test"}))


@pytest.mark.real_tls
@pytest.mark.usefixtures("no_sockets")
async def test_off_scope_raises_before_any_socket() -> None:
    for host, port in (("evil.test", 443), ("shop.test", 8443)):
        with pytest.raises(OutOfScopeError):
            await collect_tls(POLICY, host, port)
    with pytest.raises(OutOfScopeError):
        sslyze_probe(POLICY, "evil.test", 443, TLSLimits())  # before sslyze resolves DNS


@pytest.mark.real_tls
@pytest.mark.usefixtures("no_sockets")
async def test_socket_guard_control() -> None:
    """Control: an in-scope host does reach the socket layer."""
    with pytest.raises(SocketOpenedError):
        await collect_tls(POLICY, "shop.test", 443, TLSLimits(enumerate=False))


def test_every_network_function_checks_scope_first() -> None:
    tree = ast.parse(Path(tls_client.__file__).read_text(encoding="utf-8"))
    network = {
        "create_connection",
        "wrap_socket",
        "_handshake",
        "Scanner",
        "ServerNetworkLocation",
        "to_thread",
    }
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    checked: set[str] = set()
    for fn in funcs:
        names = {getattr(n, "attr", None) or getattr(n, "id", None) for n in ast.walk(fn)}
        if names & network:
            first = (
                fn.body[1]
                if isinstance(fn.body[0], ast.Expr) and isinstance(fn.body[0].value, ast.Constant)
                else fn.body[0]
            )
            calls = [c for c in ast.walk(first) if isinstance(c, ast.Call)]
            assert any(getattr(c.func, "attr", "") == "check_host" for c in calls), fn.name
            checked.add(fn.name)
    assert {"_handshake", "stdlib_probe", "sslyze_probe", "collect_tls"} <= checked


def test_sslyze_allowlist_is_non_intrusive() -> None:
    assert not SSLYZE_COMMANDS & FORBIDDEN
    src = Path(tls_client.__file__).read_text(encoding="utf-8")
    referenced = {
        ScanCommand[n] for n in set(__import__("re").findall(r"ScanCommand\.([A-Z0-9_]+)", src))
    }
    assert referenced == SSLYZE_COMMANDS  # nothing else is even mentioned


# --- real handshake against a local server ------------------------------------------------


@pytest.fixture
def local_tls_server(tmp_path: Path) -> Iterator[int]:
    cert, key = make_cert(cn="localhost")
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    server = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def handle(conn: socket.socket) -> None:
        try:
            with ctx.wrap_socket(conn, server_side=True):
                pass
        except (OSError, ssl.SSLError):
            pass

    def serve() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    server.close()
    thread.join(2)


@pytest.mark.real_tls
async def test_local_self_signed_server(local_tls_server: int) -> None:
    port = local_tls_server
    policy = ScopePolicy(frozenset({"localhost"}), frozenset({("localhost", port)}))
    result = await collect_tls(policy, "localhost", port, TLSLimits(timeout=5))
    assert result.verify_code == 18 and result.leaf is not None
    assert result.leaf.sans == ("localhost",)
    assert result.enumerated, result.enum_error
    accepted = {p for p, ok in result.protocols if ok}
    assert "TLSv1.2" in accepted and not accepted & {"SSLv2", "SSLv3"}
    highs = [f.id for f in check_tls(result) if f.severity is Severity.HIGH]
    assert highs == ["TLS-CERT-SELF-SIGNED"]
    await asyncio.sleep(0)
