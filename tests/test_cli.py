"""CLI tests: version, and `quick` end to end against mocked hosts."""

import json
from pathlib import Path

import httpx
import pytest
import respx

import albert.quick
from albert.cli import main
from albert.core.models import TLSObservation
from albert.core.scope import ScopePolicy
from albert.core.tls_client import TLSLimits


def test_version_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


@respx.mock
def test_quick_writes_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    respx.get("http://site.test/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://site.test/"})
    )
    respx.get("https://site.test/").mock(
        return_value=httpx.Response(
            200, headers={"Content-Type": "text/html", "Server": "nginx/1.18.0"}, text="<html>"
        )
    )
    respx.route().mock(return_value=httpx.Response(404))
    assert main(["quick", "http://site.test/", "--out", str(tmp_path)]) == 0
    md = next(tmp_path.glob("site.test_*.md")).read_text(encoding="utf-8")
    data = json.loads(next(tmp_path.glob("site.test_*.json")).read_text(encoding="utf-8"))
    ids = {f["id"] for f in data["findings"]}
    assert {"HDR-CSP-MISSING", "HDR-HSTS-MISSING", "HDR-VERSION-BANNER"} <= ids
    assert data["appendix"]["pages"][:2] == ["http://site.test/", "https://site.test/"]
    assert "**Notes:**" in md and "redirect 301" in md
    assert "HDR-PROTOCOLS" in md and "not observed" in md
    assert "site.test:" in capsys.readouterr().out


@respx.mock
def test_quick_records_cross_domain_redirect(tmp_path: Path) -> None:
    respx.get("https://apex.test/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://other.test/"})
    )
    other = respx.route(host="other.test").mock(return_value=httpx.Response(200))
    respx.route().mock(return_value=httpx.Response(404))
    assert main(["quick", "apex.test", "--out", str(tmp_path)]) == 0
    data = json.loads(next(tmp_path.glob("apex.test_*.json")).read_text(encoding="utf-8"))
    assert "not followed" in data["appendix"]["skipped"][0]
    assert not other.called


def test_quick_prompts_for_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    asked: list[str] = []

    def fake_input(prompt: str) -> str:
        asked.append(prompt)
        return "ftp://nope"

    monkeypatch.setattr("builtins.input", fake_input)
    assert main(["quick", "--out", str(tmp_path)]) == 2  # invalid URL rejected cleanly
    assert asked == ["Which URL should I scan? "]


@respx.mock
@pytest.mark.parametrize("flag, enumerate", [([], True), (["--no-tls-enum"], False)])
def test_quick_no_tls_enum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: list[str], enumerate: bool
) -> None:
    seen: list[TLSLimits | None] = []
    canned = albert.quick.collect_tls  # type: ignore[attr-defined]  # conftest's fake

    async def fake(
        policy: ScopePolicy, host: str, port: int = 443, limits: TLSLimits | None = None
    ) -> TLSObservation:
        seen.append(limits)
        return await canned(policy, host, port, limits)

    monkeypatch.setattr("albert.quick.collect_tls", fake)
    respx.route().mock(return_value=httpx.Response(200, headers={"Content-Type": "text/html"}))
    assert main(["quick", "https://site.test/", "--out", str(tmp_path), *flag]) == 0
    assert [lim.enumerate for lim in seen if lim is not None] == [enumerate]
    data = json.loads(next(tmp_path.glob("site.test_*.json")).read_text(encoding="utf-8"))
    assert any("--no-tls-enum" in n for n in data["notes"]) is not enumerate
