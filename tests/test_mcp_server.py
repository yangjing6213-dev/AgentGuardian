import importlib
import sys
from types import ModuleType

import pytest
from mcp import Client

from agentguardian import __version__
from agentguardian.mcp_server import server


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_server_exposes_exactly_two_tools() -> None:
    async with Client(server, raise_exceptions=True) as client:
        tools = await client.list_tools()
    assert [tool.name for tool in tools.tools] == [
        "prepare_audit",
        "run_prepared_audit",
    ]


@pytest.mark.anyio
async def test_prepare_returns_structured_content_without_qt() -> None:
    assert __version__ == "0.3.0a1"
    qt_modules_before = {
        name for name in sys.modules if name.startswith("PySide6")
    }
    async with Client(server, raise_exceptions=True) as client:
        result = await client.call_tool(
            "prepare_audit",
            {
                "operation": "clipboard",
                "classification": "personal_non_regulated",
            },
        )
    assert result.is_error is False
    assert result.structured_content["status"] == "prepared"
    assert {
        name for name in sys.modules if name.startswith("PySide6")
    } <= qt_modules_before


def test_source_dispatches_stdio_without_qt(monkeypatch: pytest.MonkeyPatch) -> None:
    import agentguardian.__main__ as entrypoint

    calls: list[str] = []
    qt_modules_before = {
        name for name in sys.modules if name.startswith("PySide6")
    }

    def fake_run_stdio() -> int:
        calls.append("stdio")
        return 7

    monkeypatch.setitem(
        sys.modules,
        "agentguardian.mcp_server",
        type("FakeMcpServer", (), {"run_stdio": staticmethod(fake_run_stdio)})(),
    )
    sys.modules.pop("agentguardian.app", None)
    sys.modules.pop("PySide6", None)

    assert entrypoint.main(["--stdio-mcp"]) == 7
    assert calls == ["stdio"]
    assert "agentguardian.app" not in sys.modules
    assert {
        name for name in sys.modules if name.startswith("PySide6")
    } <= qt_modules_before


def test_source_dispatch_rejects_mixed_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agentguardian.__main__ as entrypoint

    monkeypatch.setattr(
        entrypoint,
        "sys",
        type("FakeSys", (), {"argv": ["agentguardian", "--stdio-mcp", "extra"]})(),
    )
    assert entrypoint.main() == 64


def test_importing_entrypoint_does_not_execute_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    fake_app = ModuleType("agentguardian.app")
    fake_app.main = lambda: calls.append("gui") or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agentguardian.app", fake_app)
    sys.modules.pop("agentguardian.__main__", None)

    importlib.import_module("agentguardian.__main__")

    assert calls == []
