"""CLI tests: version, and `quick` end to end against mocked hosts."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from albert.cli import main


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
    assert main(["quick", "http://site.test/", "--out", str(tmp_path)]) == 0
    md = next(tmp_path.glob("site.test_*.md")).read_text(encoding="utf-8")
    data = json.loads(next(tmp_path.glob("site.test_*.json")).read_text(encoding="utf-8"))
    ids = {f["id"] for f in data["findings"]}
    assert {"HDR-CSP-MISSING", "HDR-HSTS-MISSING", "HDR-VERSION-BANNER"} <= ids
    assert data["appendix"]["pages"] == ["http://site.test/", "https://site.test/"]
    assert "HDR-PROTOCOLS" in md and "not observed" in md
    assert "site.test:" in capsys.readouterr().out


@respx.mock
def test_quick_records_off_scope_redirect(tmp_path: Path) -> None:
    respx.get("https://apex.test/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.apex.test/"})
    )
    www = respx.get("https://www.apex.test/").mock(return_value=httpx.Response(200))
    assert main(["quick", "apex.test", "--out", str(tmp_path)]) == 0
    data = json.loads(next(tmp_path.glob("apex.test_*.json")).read_text(encoding="utf-8"))
    assert "not followed" in data["appendix"]["skipped"][0]
    assert not www.called


def test_quick_prompts_for_url(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    asked: list[str] = []

    def fake_input(prompt: str) -> str:
        asked.append(prompt)
        return "ftp://nope"

    monkeypatch.setattr("builtins.input", fake_input)
    assert main(["quick", "--out", str(tmp_path)]) == 2  # invalid URL rejected cleanly
    assert asked == ["Which URL should I scan? "]
