"""security.txt checks on fixture bodies. No network."""

from datetime import UTC, datetime

from albert.checks.security_txt import check_security_txt, parse_security_txt
from albert.core.models import CollectedResponse

URL = "https://x.test/.well-known/security.txt"
NOW = datetime(2026, 10, 20, tzinfo=UTC)


def _resp(
    text: str, ctype: str = "text/plain; charset=utf-8", status: int = 200
) -> CollectedResponse:
    return CollectedResponse(URL, status, (("Content-Type", ctype),), text=text)


def _ids(resp: CollectedResponse) -> set[str]:
    return {f.id for f in check_security_txt(resp, NOW)}


def test_valid_file() -> None:
    body = "# hi\nContact: mailto:sec@x.test\nExpires: 2027-06-01T00:00:00Z\n"
    assert _ids(_resp(body)) == {"SEC-TXT-PRESENT"}


def test_missing_and_soft_404() -> None:
    assert _ids(_resp("", status=404)) == {"SEC-TXT-MISSING"}
    assert _ids(_resp("<html>app</html>", ctype="text/html")) == {"SEC-TXT-MISSING"}


def test_problems() -> None:
    body = "Contact: http://x.test/report\nExpires: 2020-01-01T00:00:00Z\n"
    assert _ids(_resp(body, ctype="application/octet-stream")) == {
        "SEC-TXT-NOT-PLAIN",
        "SEC-TXT-INSECURE-CONTACT",
        "SEC-TXT-EXPIRED",
        "SEC-TXT-PRESENT",
    }
    assert _ids(_resp("Expires: soon\n")) == {
        "SEC-TXT-NO-CONTACT",
        "SEC-TXT-NO-EXPIRES",
        "SEC-TXT-PRESENT",
    }
    assert "SEC-TXT-EXPIRES-FAR" in _ids(
        _resp("Contact: mailto:a@b\nExpires: 2030-01-01T00:00:00Z")
    )


def test_signed_file_parsed() -> None:
    body = (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        "Contact: mailto:sec@x.test\n- Expires: 2027-01-01T00:00:00Z\n"
        "-----BEGIN PGP SIGNATURE-----\nContact: mailto:fake@x.test\n-----END PGP SIGNATURE-----\n"
    )
    fields = parse_security_txt(body)
    assert fields["contact"] == ["mailto:sec@x.test"]
    assert fields["expires"] == ["2027-01-01T00:00:00Z"]
