"""Secret-detection patterns and redaction. Pure: no I/O.

Shared by the report writer's redaction backstop (step 5) and JS bundle analysis (step 14).
``redact`` is idempotent: its markers never re-match any pattern.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    """A named regex for one kind of secret.

    ``group`` selects the part of the match that is the secret (0 = whole match).
    ``keep`` is how many leading characters survive redaction, to aid identification.
    """

    name: str
    regex: re.Pattern[str]
    group: int = 0
    keep: int = 4


def _p(name: str, pattern: str, *, group: int = 0, keep: int = 4, flags: int = 0) -> SecretPattern:
    return SecretPattern(name, re.compile(pattern, flags), group, keep)


_KEY_NAME = r"(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|credential|auth[_-]?key)"

# Order matters: specific patterns run before generic/bearer ones.
PATTERNS: tuple[SecretPattern, ...] = (
    _p(
        "private_key",
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|(?:\r?\n[A-Za-z0-9+/=]+)*)",
        keep=0,
        flags=re.DOTALL,
    ),
    _p("url_credentials", r"(?<=://)[^\s/:@]+:[^\s/@]+(?=@)", keep=0),
    _p("aws_access_key_id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _p("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    _p("github_fine_grained_pat", r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b", keep=11),
    _p("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}", keep=6),
    _p("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", keep=5),
    _p("slack_webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}", keep=33),
    _p("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}", keep=8),
    _p("google_api_key", r"\bAIza[0-9A-Za-z_-]{35}"),
    _p("google_oauth_secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}", keep=7),
    _p("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", keep=7),
    _p("openai_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}", keep=3),
    _p("sendgrid_key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", keep=3),
    _p("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _p("azure_storage_key", r"(?i)AccountKey=([A-Za-z0-9+/]{86,88}={0,2})", group=1, keep=0),
    _p("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", keep=0),
    _p("bearer_token", r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", group=1),
    _p(
        "generic_secret",
        rf"""(?i){_KEY_NAME}\w*["']?\s*[:=]\s*["']([^"'\s\[\]]{{8,}})["']""",
        group=1,
    ),
)

# High-entropy candidates: base64/url-safe runs. Pure hex is excluded on purpose:
# asset hashes and commit SHAs are everywhere and benign.
_ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}(?![A-Za-z0-9+/_=-])")
ENTROPY_MIN_LEN = 32
ENTROPY_THRESHOLD = 4.3


def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy of ``s`` in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def is_high_entropy(s: str) -> bool:
    """Heuristic: long, mixed-case alphanumeric, and entropy above threshold."""
    return (
        len(s) >= ENTROPY_MIN_LEN
        and any(c.isupper() for c in s)
        and any(c.islower() for c in s)
        and any(c.isdigit() for c in s)
        and shannon_entropy(s) >= ENTROPY_THRESHOLD
    )


def marker(secret: str, name: str, keep: int = 0) -> str:
    """Build the redaction marker for ``secret``; keeps a short prefix only if it's long."""
    tag = f"[REDACTED-{name}]"
    if keep and len(secret) > 2 * keep:
        return f"{secret[:keep]}...{tag}"
    return tag


def _substitute(m: re.Match[str], pat: SecretPattern) -> str:
    whole, base = m.group(0), m.start()
    start, end = m.span(pat.group)
    secret = m.group(pat.group)
    return whole[: start - base] + marker(secret, pat.name, pat.keep) + whole[end - base :]


def redact(text: str, *, entropy: bool = True) -> str:
    """Replace every detected secret in ``text`` with a marker. Idempotent."""
    for pat in PATTERNS:
        text = pat.regex.sub(lambda m, p=pat: _substitute(m, p), text)  # type: ignore[misc]
    if entropy:
        text = _ENTROPY_CANDIDATE.sub(_entropy_substitute, text)
    return text


def _entropy_substitute(m: re.Match[str]) -> str:
    s = m.group()
    return marker(s, "high_entropy") if is_high_entropy(s) else s
