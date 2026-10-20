"""Static guard: network access exists only in allow-listed core modules, and only behind the
scope checkpoint. Fails the build if new code opens another path to the network.
"""

import ast
from pathlib import Path

PKG = Path(__file__).parent.parent / "albert"

NETWORK_MODULES = {
    "httpx",
    "socket",
    "ssl",
    "urllib.request",
    "http.client",
    "requests",
    "aiohttp",
    "httpcore",
    "dns",
    "playwright",
    "sslyze",
    "websockets",
}
NETWORK_CALLS = {"open_connection", "create_connection", "getaddrinfo", "sock_connect"}
# Grows as egress modules land (browser.py, dns_client.py, TLS); each must call scope first.
ALLOWED = {"core/http_client.py"}


def _modules() -> list[tuple[str, ast.Module]]:
    return [
        (p.relative_to(PKG).as_posix(), ast.parse(p.read_text(encoding="utf-8")))
        for p in PKG.rglob("*.py")
    ]


def _imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _is_network(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in NETWORK_MODULES)


def test_network_imports_only_in_allowed_modules() -> None:
    offenders = {
        rel: sorted(n for n in _imports(tree) if _is_network(n))
        for rel, tree in _modules()
        if rel not in ALLOWED
    }
    assert {k: v for k, v in offenders.items() if v} == {}


def test_no_raw_connection_calls() -> None:
    offenders = [
        f"{rel}:{node.lineno}"
        for rel, tree in _modules()
        if rel not in ALLOWED
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr in NETWORK_CALLS
    ]
    assert offenders == []


def test_every_httpx_client_uses_guarded_transport() -> None:
    tree = dict(_modules())["core/http_client.py"]
    clients = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in {"AsyncClient", "Client"}
    ]
    assert clients, "expected the httpx client construction"
    for call in clients:
        kw = {k.arg: k.value for k in call.keywords}
        assert isinstance(kw.get("transport"), ast.Attribute)
        assert kw["transport"].attr == "_transport"  # type: ignore[attr-defined]


def test_transport_checks_scope_first() -> None:
    tree = dict(_modules())["core/http_client.py"]
    handlers = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "handle_async_request"
    ]
    assert len(handlers) == 1
    first = handlers[0].body[0]
    calls = [n for n in ast.walk(first) if isinstance(n, ast.Call)]
    assert any(isinstance(c.func, ast.Attribute) and c.func.attr == "check_request" for c in calls)
