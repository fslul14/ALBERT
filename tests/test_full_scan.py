"""End-to-end: one `scan --full --render` runs every collector over one target, offline.

The site, crt.sh and Wayback are respx-mocked; TLS is the conftest fake; DNS and DNS
blocklists use fake resolvers; Chromium renders with no network of its own. Asserts the merged
report is coherent: every family once, no duplicates, each issue reported by one family only.
"""

import json
from collections import Counter
from pathlib import Path

import httpx
import pytest
import respx

from albert.cli import main
from albert.core import dns_client, intel_sources
from albert.core.intel import IntelDns
from albert.core.models import DnsAnswer

B = "https://shop.test"
AWS = "AKIAIOSFODNN7EXAMPLE"
HOME = f"""<!DOCTYPE html><html><head><title>Shop</title>
<meta name="generator" content="WordPress 6.4.2">
<script src="/static/app.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
<script>var cfg = {{aws: "{AWS}", api: "https://ci.corp.internal/build"}};</script>
</head><body><a href="/login">Login</a> <a href="/privacy">Privacy</a>
<!-- TODO remove debug --></body></html>"""
LOGIN = """<html><body><form action="http://shop.test/session" method="post">
<input name="u"><input type="password" name="p"></form></body></html>"""
APP = "/*! jQuery v3.4.1 | (c) OpenJS Foundation */ var x=1;\n//# sourceMappingURL=app.js.map\n"
ZONE = {
    ("shop.test", "TXT"): ("v=spf1 include:_spf.google.com ~all",),
    ("shop.test", "MX"): ("10 mx.shop.test.",),
    ("mx.shop.test", "A"): ("8.8.8.8",),
}
FAMILIES = {
    "headers",
    "cookies",
    "cors",
    "disclosure",
    "security_txt",
    "rendered",
    "fingerprint",
    "privacy",
    "cve",
    "js",
    "tls",
    "dns_email",
    "intel",
}


def _chromium() -> bool:
    import os
    import sys

    base = os.environ.get("LOCALAPPDATA", "") if sys.platform == "win32" else "~/.cache"
    return any((Path(base).expanduser() / "ms-playwright").glob("chromium*"))


@pytest.mark.real_dns
@pytest.mark.real_intel
@pytest.mark.skipif(not _chromium(), reason="Chromium not installed")
@respx.mock
def test_full_render_scan_is_one_coherent_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def zone(name: str, rtype: str) -> DnsAnswer:
        v = ZONE.get((name, rtype))
        return DnsAnswer(name, rtype, "ok", v) if v else DnsAnswer(name, rtype, "noanswer")

    class OfflineDnsbl(IntelDns):
        def __init__(self, resolve: object = None) -> None:
            async def nx(name: str, rtype: str) -> DnsAnswer:
                return DnsAnswer(name, rtype, "nxdomain")

            super().__init__(nx)

    monkeypatch.setattr(dns_client, "system_resolve", zone)
    monkeypatch.setattr(intel_sources, "IntelDns", OfflineDnsbl)
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "shop.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    html = {"Content-Type": "text/html", "Server": "nginx/1.18.0"}
    respx.get(f"{B}/").mock(
        return_value=httpx.Response(
            200, headers={**html, "Set-Cookie": "_ga=GA1.1; Path=/"}, text=HOME
        )
    )
    respx.get(f"{B}/login").mock(
        return_value=httpx.Response(
            200, headers={**html, "Set-Cookie": "PHPSESSID=x; Path=/"}, text=LOGIN
        )
    )
    respx.get(f"{B}/privacy").mock(
        return_value=httpx.Response(200, headers=html, text="<p>privacy</p>")
    )
    respx.get(f"{B}/static/app.js").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "application/javascript"}, text=APP
        )
    )
    respx.get(f"{B}/robots.txt").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "text/plain"}, text="User-agent: *\nDisallow: /admin/\n"
        )
    )
    respx.get(f"{B}/.well-known/security.txt").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="Contact: mailto:s@shop.test\nExpires: 2027-01-01T00:00:00Z\n",
        )
    )
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[{"name_value": "www.shop.test\nstaging.shop.test"}])
    )
    respx.get(url__startswith="https://web.archive.org/").mock(
        return_value=httpx.Response(
            200,
            json=[
                ["original", "timestamp", "statuscode"],
                ["https://shop.test/backup.zip", "20200101000000", "200"],
            ],
        )
    )
    respx.route().mock(return_value=httpx.Response(404))
    out = tmp_path / "reports"
    args = [
        "scan",
        f"{B}/",
        "--scope",
        str(scope),
        "--out",
        str(out),
        "--rate",
        "0",
        "--full",
        "--render",
    ]
    assert main(args) == 0

    assert len(list(out.glob("*.json"))) == len(list(out.glob("*.md"))) == 1  # one report
    raw = next(out.glob("*.json")).read_text(encoding="utf-8")
    md = next(out.glob("*.md")).read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["appendix"]["errors"] == []
    assert Counter(data["checks_run"]) == Counter(FAMILIES)  # every family, exactly once
    allf = data["findings"] + data["posture_notes"]
    assert [k for k, n in Counter((f["id"], f["title"]) for f in allf).items() if n > 1] == []
    pages = data["appendix"]["pages"]
    assert len(pages) == len(set(pages))
    # Each issue is reported by exactly one family (no cross-family double counting):
    assert [f["id"] for f in allf if "AWS" in f["id"]] == ["JS-SECRET-AWS_ACCESS_KEY_ID"]
    internal = [f["id"] for f in allf if "ci.corp.internal" in json.dumps(f["evidence"])]
    assert internal == ["JS-INTERNAL-URL"]
    assert "RND-FORM-HTTP-ACTION" in {f["id"] for f in allf}
    assert "RND-FORM-CROSS-ORIGIN" not in {f["id"] for f in allf}  # same site, scheme only
    # Boundaries held across all collectors:
    hosts = {c.request.url.host for c in respx.calls}
    assert hosts == {"shop.test", "crt.sh", "web.archive.org"}  # no tracker, no discovered host
    assert AWS not in raw and AWS not in md  # redaction backstop over the merged report
    assert data["summary"]["posture"]["grade"] in ("D", "F")  # 3 Highs: weak site grades poorly
    assert {t["name"] for t in data["appendix"]["tech"]} >= {"nginx", "WordPress", "jQuery"}
