"""Tests for secret patterns and redaction.

Fake tokens are built by concatenation so no literal token-shaped string lives in the repo
(keeps GitHub push protection quiet). AKIAIOSFODNN7EXAMPLE is AWS's documented example.
"""

import pytest

from albert.core.secrets import is_high_entropy, redact, shannon_entropy

HIGH_ENTROPY = "Zx9Qm2Lp7Rt4Vw8Ky3Nb6Hc1Jd5Fg0SaEuXiOoPq"

SAMPLES = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp" + "_" + "a1B2c3D4e5" * 4,
    "gitlab_token": "glpat" + "-" + "x" * 20,
    "slack_token": "xoxb" + "-" + "1234567890-abcdef",
    "stripe_key": "sk" + "_live_" + "0" * 24,
    "google_api_key": "AIza" + "B" * 35,
    "anthropic_key": "sk" + "-ant-" + "q" * 30,
    "openai_key": "sk" + "-proj-" + "r" * 30,
    "npm_token": "npm" + "_" + "n" * 36,
    "jwt": "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + "." + "s" * 20,
}


@pytest.mark.parametrize(("name", "secret"), SAMPLES.items())
def test_known_patterns_redacted(name: str, secret: str) -> None:
    out = redact(f"leak: {secret} end")
    assert secret not in out
    assert f"[REDACTED-{name}]" in out
    assert out.startswith("leak: ") and out.endswith(" end")


def test_private_key_block() -> None:
    key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabc123==\n-----END RSA PRIVATE KEY-----"
    )
    out = redact(f"x {key} y")
    assert out == "x [REDACTED-private_key] y"


def test_truncated_private_key() -> None:
    out = redact("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n")
    assert "MIIEvQ" not in out


def test_url_credentials_keep_host() -> None:
    out = redact("https://admin:hunter22@db.internal/x")
    assert out == "https://[REDACTED-url_credentials]@db.internal/x"


def test_generic_assignment_keeps_key_name() -> None:
    out = redact('const apiKey = "s3cr3tValue99";')
    assert "s3cr3tValue99" not in out
    assert out.startswith('const apiKey = "')


def test_bearer() -> None:
    assert "abcdefghijklmnop1234" not in redact("Authorization: Bearer abcdefghijklmnop1234")


def test_high_entropy() -> None:
    assert shannon_entropy(HIGH_ENTROPY) > 5
    assert is_high_entropy(HIGH_ENTROPY)
    assert HIGH_ENTROPY not in redact(f"x={HIGH_ENTROPY}")
    assert HIGH_ENTROPY in redact(f"x={HIGH_ENTROPY}", entropy=False)


@pytest.mark.parametrize(
    "benign",
    [
        "Forgot your password? Reset it here.",
        "/static/js/main.4f3a2b1c.chunk.js",
        "commit 3f786850e387550fdab836ed7e6dc881de23001b",
        "getElementsByTagNameAndClassName2024Version",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "",
    ],
)
def test_benign_untouched(benign: str) -> None:
    assert redact(benign) == benign


def test_idempotent() -> None:
    text = " ".join(SAMPLES.values()) + f" {HIGH_ENTROPY} https://u:p4ssword@h/ token='abcdefgh12'"
    once = redact(text)
    assert redact(once) == once
