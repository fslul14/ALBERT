"""Proof that moving pattern checks into YAML rules changed no output.

``tests/fixtures/golden/rules_migration.json`` was produced by the pre-migration Python checks
(commit 20a6884: ``headers.run_header_checks`` / ``cookies.run_cookie_checks``) over the
representative responses below. The test runs the same responses through the rule-backed
families and requires the findings to be identical, field for field and in order.

Regenerate only on purpose: ``python tests/test_rules_migration.py``.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from albert.core.models import CollectedResponse, Finding

ROOT = Path(__file__).parent
GOLDEN = ROOT / "fixtures" / "golden" / "rules_migration.json"
URLS = ("https://shop.test/account/login", "http://shop.test/page")

COVERAGE: list[tuple[tuple[str, str], ...]] = [
    # Every deprecated header, all banner headers, mixed-case debug/backend headers, COOP
    # unsafe-none, and an X-XSS-Protection: 0 that must NOT fire.
    (
        ("Content-Type", "text/html"),
        ("X-XSS-Protection", "0"),
        ("Expect-CT", "max-age=0"),
        ("Public-Key-Pins", 'pin-sha256="x"'),
        ("Public-Key-Pins-Report-Only", 'pin-sha256="y"'),
        ("Feature-Policy", "camera 'none'"),
        ("P3P", 'CP="NOI"'),
        ("X-Content-Security-Policy", "default-src 'self'"),
        ("X-WebKit-CSP", "default-src 'self'"),
        ("Server", "Apache"),
        ("Server", "nginx/1.25.3"),
        ("X-AspNet-Version", "4.0.30319"),
        ("X-AspNetMvc-Version", "5.2"),
        ("X-Generator", "Drupal 9 (https://www.drupal.org)"),
        ("X-Powered-CMS", "Bitrix Site Manager"),
        ("X-Powered-By", "Express"),
        ("X-Debug-Token", "abc123"),
        ("X-ChromeLogger-Data", "eyJ2ZXJzaW9uIjo="),
        ("X-Backend-Server", "app01"),
        ("X-Real-Server", "web-2"),
        ("Cross-Origin-Opener-Policy", "unsafe-none"),
        ("Cross-Origin-Embedder-Policy", "require-corp"),
        ("X-Content-Type-Options", "NoSniff "),
    ),
    (
        ("Content-Type", "text/html"),
        ("X-XSS-Protection", "1; mode=block"),
        ("X-Content-Type-Options", "sniff"),
        ("Permissions-Policy", "camera=()"),
    ),
    (("Content-Type", "application/json"), ("X-Powered-By", "PHP/8.1.2")),
]
COOKIE_SETS: list[tuple[tuple[str, str], ...]] = [
    (
        ("Set-Cookie", "PHPSESSID=a; path=/"),
        ("Set-Cookie", "PHPSESSID=b; Secure; HttpOnly"),
        ("Set-Cookie", "csrftoken=x; Secure; SameSite=Strict"),
        ("Set-Cookie", "pref=dark"),
        ("Set-Cookie", "sso=1; Secure; HttpOnly; SameSite=None"),
        ("Set-Cookie", "legacy=1; HttpOnly; SameSite=None"),
        ("Set-Cookie", "broken"),
    ),
]


def _fixture(path: Path, url: str) -> CollectedResponse:
    lines = [
        ln
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    if path.parent.name == "cookies":
        headers = [("Content-Type", "text/html"), *(("Set-Cookie", ln) for ln in lines)]
        return CollectedResponse(url, 200, tuple(headers))
    version, status = lines[0].split()[:2]
    pairs = tuple((k.strip(), v.strip()) for k, _, v in (ln.partition(":") for ln in lines[1:]))
    return CollectedResponse(url, int(status), pairs, version)


def representative_responses() -> list[CollectedResponse]:
    files = sorted((ROOT / "fixtures" / "headers").glob("*.txt"))
    files += sorted((ROOT / "fixtures" / "cookies").glob("*.txt"))
    out = [_fixture(f, u) for f in files for u in URLS]
    for i, headers in enumerate(COVERAGE + COOKIE_SETS):
        for u in URLS:
            out.append(CollectedResponse(f"{u}?case={i}", 200, headers))
    out.append(CollectedResponse("https://shop.test/moved", 301, (("Location", "/"),)))
    out.append(
        CollectedResponse("https://shop.test/missing", 404, (("Content-Type", "text/html"),))
    )
    return out


def snapshot(
    headers: Callable[[Sequence[CollectedResponse]], list[Finding]],
    cookies: Callable[[Sequence[CollectedResponse]], list[Finding]],
) -> dict[str, Any]:
    responses = representative_responses()
    return {
        "headers": [f.to_dict() for f in headers(responses)],
        "cookies": [f.to_dict() for f in cookies(responses)],
    }


def test_rule_migration_changes_no_output() -> None:
    from albert.core.engine import run_family

    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    now = snapshot(lambda r: run_family("headers", r), lambda r: run_family("cookies", r))
    assert len(now["headers"]) == len(golden["headers"]) > 40
    assert len(now["cookies"]) == len(golden["cookies"]) > 20
    assert now == golden


if __name__ == "__main__":  # regenerate the golden file from the CURRENT code
    sys.path.insert(0, str(ROOT.parent))
    from albert.core.engine import run_family

    data = snapshot(lambda r: run_family("headers", r), lambda r: run_family("cookies", r))
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {GOLDEN}: {len(data['headers'])} header + {len(data['cookies'])} cookie findings")
