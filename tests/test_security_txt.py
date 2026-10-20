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


# --- RFC 9116 location/format rules (step 20) --------------------------------------------

from albert.checks.security_txt import run_security_txt_checks  # noqa: E402

GOOD = "Contact: mailto:sec@x.test\nExpires: 2027-06-01T00:00:00Z\n"


def _hop(url: str, status: int = 200, text: str = GOOD) -> CollectedResponse:
    ctype = "text/plain" if status == 200 else "text/html"
    return CollectedResponse(url, status, (("Content-Type", ctype),), text=text)


def _chain_ids(*chain: CollectedResponse) -> set[str]:
    return {f.id for f in run_security_txt_checks(list(chain))}


def test_https_required_on_every_hop() -> None:
    plain = _chain_ids(_hop("http://x.test/.well-known/security.txt"))
    assert "SEC-TXT-NOT-HTTPS" in plain
    redirected = _chain_ids(_hop("http://x.test/.well-known/security.txt", 301, ""), _hop(URL))
    assert "SEC-TXT-NOT-HTTPS" in redirected  # the http hop counts too
    assert "SEC-TXT-NOT-HTTPS" not in _chain_ids(_hop(URL))


def test_single_use_fields_and_canonical() -> None:
    twice = (
        GOOD + "Expires: 2027-07-01T00:00:00Z\nPreferred-Languages: en\nPreferred-Languages: de\n"
    )
    dup = [
        f
        for f in run_security_txt_checks([_hop(URL, text=twice)])
        if f.id == "SEC-TXT-DUPLICATE-FIELD"
    ]
    assert {e.location for e in dup[0].evidence} == {"Expires", "Preferred-Languages"}
    assert "SEC-TXT-CANONICAL-MISMATCH" in _chain_ids(
        _hop(URL, text=GOOD + "Canonical: https://other.test/.well-known/security.txt\n")
    )
    assert "SEC-TXT-CANONICAL-MISMATCH" not in _chain_ids(
        _hop(URL, text=GOOD + f"Canonical: {URL}\n")
    )


def test_missing_file_reported_once() -> None:
    assert _chain_ids(_hop(URL, 404, "")) == {"SEC-TXT-MISSING"}
