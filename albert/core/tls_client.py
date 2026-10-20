"""TLS collector: handshakes and certificate inspection only. Opens its own sockets, so every
function that touches the network calls ``policy.check_host`` as its FIRST statement (a test
enforces this), the same checkpoint HttpClient uses.

Backends:
- stdlib ``ssl``: one verified handshake (system trust store) to capture OpenSSL's verify
  error, and an unverified one to read the leaf certificate + negotiated protocol/cipher.
- sslyze: non-intrusive commands only (``SSLYZE_COMMANDS``): certificate info (received
  chain) and per-protocol cipher-suite enumeration. Never Heartbleed, CCS injection,
  renegotiation, ROBOT, compression, fallback SCSV, early data, resumption, or HTTP headers.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import warnings
from dataclasses import dataclass, replace

from sslyze import (
    ScanCommand,
    Scanner,
    ServerNetworkConfiguration,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

from albert.core.certs import cert_info, parse_der
from albert.core.models import TLSObservation
from albert.core.scope import ScopePolicy

# sslyze's bundled trust store has a root with a non-positive serial; cryptography warns on
# every load. Harmless for path validation, so silence exactly that message.
warnings.filterwarnings("ignore", message="Parsed a serial number which wasn't positive")

# The complete allowlist. Anything not listed here is never queued.
SSLYZE_PROTOCOL_COMMANDS: dict[ScanCommand, str] = {
    ScanCommand.SSL_2_0_CIPHER_SUITES: "SSLv2",
    ScanCommand.SSL_3_0_CIPHER_SUITES: "SSLv3",
    ScanCommand.TLS_1_0_CIPHER_SUITES: "TLSv1.0",
    ScanCommand.TLS_1_1_CIPHER_SUITES: "TLSv1.1",
    ScanCommand.TLS_1_2_CIPHER_SUITES: "TLSv1.2",
    ScanCommand.TLS_1_3_CIPHER_SUITES: "TLSv1.3",
}
SSLYZE_COMMANDS: frozenset[ScanCommand] = frozenset(
    {ScanCommand.CERTIFICATE_INFO, *SSLYZE_PROTOCOL_COMMANDS}
)


@dataclass(frozen=True)
class TLSLimits:
    """Politeness for TLS inspection."""

    timeout: float = 10.0
    enumerate: bool = True  # run the sslyze backend
    sslyze_connections: int = 2  # concurrent handshakes per server during enumeration


def _handshake(
    policy: ScopePolicy, host: str, port: int, ctx: ssl.SSLContext, timeout: float
) -> tuple[bytes | None, str | None, str | None]:
    policy.check_host(host, port)
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        cipher = tls.cipher()
        return tls.getpeercert(binary_form=True), tls.version(), cipher[0] if cipher else None


def stdlib_probe(policy: ScopePolicy, host: str, port: int, timeout: float) -> TLSObservation:
    """Verified then (if needed) unverified handshake with Python's ssl."""
    policy.check_host(host, port)
    obs = TLSObservation(host, port)
    der = proto = cipher = None
    try:
        der, proto, cipher = _handshake(policy, host, port, ssl.create_default_context(), timeout)
    except ssl.SSLCertVerificationError as e:
        obs = replace(obs, verify_error=str(e.verify_message), verify_code=e.verify_code)
    except (OSError, ssl.SSLError) as e:
        obs = replace(obs, verify_error=f"handshake failed: {e}")
    if der is None:
        lax = ssl.create_default_context()
        lax.check_hostname = False
        lax.verify_mode = ssl.CERT_NONE
        try:
            der, proto, cipher = _handshake(policy, host, port, lax, timeout)
        except (OSError, ssl.SSLError) as e:
            return replace(obs, error=f"{type(e).__name__}: {e}", verify_error=None)
    leaf = parse_der(der) if der else None
    return replace(obs, protocol=proto, cipher=cipher, leaf=leaf)


def _forward_secret(name: str, ephemeral: object, protocol: str) -> bool:
    return protocol == "TLSv1.3" or ephemeral is not None or "_DHE_" in name or "ECDHE" in name


def sslyze_probe(policy: ScopePolicy, host: str, port: int, limits: TLSLimits) -> dict[str, object]:
    """Non-intrusive sslyze scan: received chain + accepted protocols/ciphers."""
    policy.check_host(host, port)
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(host, port),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=host,
            network_timeout=int(limits.timeout),
            network_max_retries=1,
        ),
        scan_commands=set(SSLYZE_COMMANDS),
    )
    scanner = Scanner(per_server_concurrent_connections_limit=limits.sslyze_connections)
    scanner.queue_scans([request])
    out: dict[str, object] = {}
    for result in scanner.get_results():
        if result.scan_status != ServerScanStatusEnum.COMPLETED or result.scan_result is None:
            out["enum_error"] = (
                f"connectivity: {result.connectivity_error_trace or result.scan_status}"
            )
            continue
        attempts = result.scan_result
        cert_attempt = attempts.certificate_info
        if cert_attempt.result is not None and cert_attempt.result.certificate_deployments:
            deployment = cert_attempt.result.certificate_deployments[0]
            out["chain"] = tuple(cert_info(c) for c in deployment.received_certificate_chain)
        protocols, ciphers = [], []
        for command, label in SSLYZE_PROTOCOL_COMMANDS.items():
            attempt = getattr(attempts, command.value)
            if attempt.result is None:
                continue
            accepted = attempt.result.accepted_cipher_suites
            protocols.append((label, bool(accepted)))
            ciphers += [
                (
                    label,
                    a.cipher_suite.name,
                    _forward_secret(a.cipher_suite.name, a.ephemeral_key, label),
                )
                for a in accepted
            ]
        out["protocols"] = tuple(protocols)
        out["accepted_ciphers"] = tuple(ciphers)
        out["enumerated"] = bool(protocols)
    return out


async def collect_tls(
    policy: ScopePolicy, host: str, port: int = 443, limits: TLSLimits | None = None
) -> TLSObservation:
    """Inspect one host's TLS. Raises OutOfScopeError before any socket if not allowed."""
    host = policy.check_host(host, port)
    limits = limits or TLSLimits()
    obs = await asyncio.to_thread(stdlib_probe, policy, host, port, limits.timeout)
    if obs.error or not limits.enumerate:
        return obs
    try:
        extra = await asyncio.to_thread(sslyze_probe, policy, host, port, limits)
    except Exception as e:  # sslyze failure must not sink the stdlib results
        return replace(obs, enum_error=f"{type(e).__name__}: {e}")
    return replace(obs, **extra)  # type: ignore[arg-type]
