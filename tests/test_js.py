"""JS analysis on saved fixtures with planted, string-assembled fake secrets. Nothing is
fetched by the checks; the crawl test shows only same-host scripts are fetched and .map
files never are. No raw secret may reach any finding or report.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from albert.checks.js import run_js_checks
from albert.cli import main
from albert.core.crawler import Crawler, CrawlLimits
from albert.core.http_client import ClientLimits
from albert.core.models import CollectedResponse, Finding, Severity, Target
from albert.core.scope import ScopePolicy

FIXTURES = Path(__file__).parent / "fixtures" / "js"
BASE = "https://shop.test"

# Built at runtime so no token-shaped literal is committed (GitHub push protection).
FAKES = {
    "AWS": "AKIA" + "Q3EXAMPLEZ7" + "KM2PQ",  # AKIA + 16
    "STRIPE": "sk" + "_live_" + "51Hx" + "9" * 20,
    "GITHUB": "ghp" + "_" + "Zz9" * 12,
    "GOOGLE": "AIza" + "Sy" + "B" * 33,
    "JWT": "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiI0MiJ9" + "." + "q" * 30,
    "GENERIC": "Pr0dSecretV4lue" + "-x9",
    "PRIVKEY": "-----BEGIN " + "RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\\n"
    "-----END " + "RSA PRIVATE KEY-----",
}


def planted(name: str) -> str:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    for key, value in FAKES.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def js(name: str, path: str, headers: tuple[tuple[str, str], ...] = ()) -> CollectedResponse:
    return CollectedResponse(
        f"{BASE}{path}",
        200,
        (("Content-Type", "application/javascript"), *headers),
        text=planted(name),
    )


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def assert_no_raw_secrets(blob: str) -> None:
    for key, value in FAKES.items():
        probe = value.split("\\n")[0] if key == "PRIVKEY" else value
        assert probe not in blob, key
    assert "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn" not in blob


def test_secrets_by_type_and_redacted() -> None:
    found = by_id(run_js_checks([], [js("app.min.js", "/static/app.min.js")]))
    expected = {
        "JS-SECRET-AWS_ACCESS_KEY_ID": Severity.HIGH,
        "JS-SECRET-STRIPE_KEY": Severity.HIGH,
        "JS-SECRET-GITHUB_TOKEN": Severity.HIGH,
        "JS-SECRET-PRIVATE_KEY": Severity.HIGH,
        "JS-SECRET-GOOGLE_API_KEY": Severity.LOW,
        "JS-SECRET-JWT": Severity.MEDIUM,
        "JS-SECRET-GENERIC_SECRET": Severity.LOW,
    }
    for fid, sev in expected.items():
        assert found[fid].severity is sev, fid
    # The "YOUR_API_KEY" placeholder is not reported: one generic match only.
    assert len(found["JS-SECRET-GENERIC_SECRET"].evidence) == 1
    assert "line 2" in found["JS-SECRET-AWS_ACCESS_KEY_ID"].evidence[0].value
    assert_no_raw_secrets(json.dumps([f.to_dict() for f in found.values()]))


def test_internal_staging_debug_and_source_map_reference() -> None:
    found = by_id(run_js_checks([], [js("app.min.js", "/static/app.min.js")]))
    assert {e.value for e in found["JS-INTERNAL-URL"].evidence} >= {
        "ci.corp.internal",
        "http://10.20.0.15:9090/push",
    }
    assert [e.value for e in found["JS-STAGING-HOST"].evidence] == ["api.staging.shop.test"]
    assert found["JS-DEBUG-FLAG"].severity is Severity.INFO
    ref = found["JS-SOURCEMAP-REFERENCED"]
    assert ref.severity is Severity.INFO
    assert [e.value for e in ref.evidence] == [
        f"{BASE}/static/app.min.js.map"
    ]  # resolved, not fetched


def test_dev_build_and_embedded_map() -> None:
    found = by_id(run_js_checks([], [js("vendor.dev.js", "/static/vendor.js")]))
    assert found["JS-DEV-BUILD"].severity is Severity.LOW
    assert found["JS-SOURCEMAP-EMBEDDED"].severity is Severity.LOW
    assert "JS-SOURCEMAP-REFERENCED" not in found


def test_sourcemap_header_and_served_map() -> None:
    script = CollectedResponse(
        f"{BASE}/a.js",
        200,
        (("Content-Type", "text/javascript"), ("SourceMap", "/maps/a.js.map")),
        text="var a=1;",
    )
    served = CollectedResponse(
        f"{BASE}/maps/old.js.map",
        200,
        (("Content-Type", "application/json"),),
        text='{"version":3,"sources":["x.ts"],"mappings":"AAAA"}',
    )
    found = by_id(run_js_checks([served], [script]))
    assert [e.value for e in found["JS-SOURCEMAP-REFERENCED"].evidence] == [f"{BASE}/maps/a.js.map"]
    assert found["JS-SOURCEMAP-SERVED"].severity is Severity.LOW


def test_clean_script_has_no_findings() -> None:
    assert run_js_checks([], [js("clean.js", "/static/clean.js")]) == []


def test_inline_scripts_and_json_blobs() -> None:
    page = CollectedResponse(
        f"{BASE}/", 200, (("Content-Type", "text/html"),), text=planted("page.html")
    )
    found = by_id(run_js_checks([page], []))
    aws = found["JS-SECRET-AWS_ACCESS_KEY_ID"]
    assert aws.urls == (f"{BASE}/",) and aws.evidence[0].location == "inline script #1"
    assert "debugMode" in found["JS-DEBUG-FLAG"].evidence[0].value
    assert_no_raw_secrets(json.dumps([f.to_dict() for f in found.values()]))


@respx.mock
async def test_crawler_fetches_same_host_scripts_only_and_never_maps() -> None:
    respx.get(f"{BASE}/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "text/html"}, text=planted("page.html")
        )
    )
    app = respx.get(f"{BASE}/static/app.min.js").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "application/javascript"}, text=planted("app.min.js")
        )
    )
    cdn = respx.route(host="cdn.other.test").mock(return_value=httpx.Response(200))
    smap = respx.get(f"{BASE}/static/app.min.js.map").mock(return_value=httpx.Response(200))
    respx.route(host="shop.test").mock(return_value=httpx.Response(404))
    policy = ScopePolicy.for_target(Target(f"{BASE}/", "scan", authorized_by="self"))
    crawl = await Crawler(policy, f"{BASE}/", ClientLimits(rate=0), CrawlLimits()).run()
    assert [s.url for s in crawl.scripts] == [f"{BASE}/static/app.min.js"]
    assert app.call_count == 1 and not cdn.called and not smap.called


@respx.mock
def test_scan_reports_js_findings_without_raw_secrets(tmp_path: Path) -> None:
    scope = tmp_path / "scope.toml"
    scope.write_text(
        '[[target]]\nhost = "shop.test"\nauthorized_by = "self"\ndate = "2026-10-20"\n',
        encoding="utf-8",
    )
    respx.get(f"{BASE}/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "text/html"}, text=planted("page.html")
        )
    )
    respx.get(f"{BASE}/static/app.min.js").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "application/javascript"}, text=planted("app.min.js")
        )
    )
    respx.route().mock(return_value=httpx.Response(404))
    out = tmp_path / "reports"
    assert main(["scan", f"{BASE}/", "--scope", str(scope), "--out", str(out), "--rate", "0"]) == 0
    md = next(out.glob("shop.test_*.md")).read_text(encoding="utf-8")
    raw = next(out.glob("shop.test_*.json")).read_text(encoding="utf-8")
    data = json.loads(raw)
    assert "js" in data["checks_run"]
    assert "JS-SECRET-AWS_ACCESS_KEY_ID" in {f["id"] for f in data["findings"]}
    assert_no_raw_secrets(md + raw)


@pytest.mark.parametrize("host", ["dev.to", "www.test.com", "developer.mozilla.org"])
def test_staging_detection_ignores_public_hosts(host: str) -> None:
    s = CollectedResponse(
        f"{BASE}/x.js",
        200,
        (("Content-Type", "text/javascript"),),
        text=f'fetch("https://{host}/a")',
    )
    assert "JS-STAGING-HOST" not in by_id(run_js_checks([], [s]))
