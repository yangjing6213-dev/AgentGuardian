from __future__ import annotations

from pathlib import Path
import sys


USAGE_ERROR = 64
_STDIO_ARGUMENTS = ("--stdio-mcp",)
_PURGE_ARGUMENT = "--purge-protected-state"
_INSTALL_ARGUMENTS = {
    "--install-codex-integration=skill": (True, False),
    "--install-codex-integration=mcp": (False, True),
    "--install-codex-integration=skill,mcp": (True, True),
}
_SUCCESS_CODES = {
    "INTEGRATION_INSTALLED",
    "INTEGRATION_REMOVED",
    "INTEGRATION_NOT_PRESENT",
}
_ROLLBACK_CODES = {
    "INTEGRATION_ROLLBACK_FAILED",
    "INTEGRATION_CLEANUP_REQUIRED",
    "INTEGRATION_INSTALL_FAILED",
    "INTEGRATION_TEMP_WRITE_FAILED",
    "INTEGRATION_DPAPI_FAILED",
    "INTEGRATION_DPAPI_UNAVAILABLE",
    "INTEGRATION_BACKUP_DISCARD_FAILED",
}


def _frozen_launcher() -> str | None:
    if not getattr(sys, "frozen", False):
        return None
    name = Path(sys.executable).name.casefold()
    if name == "agentguardian.exe":
        return "gui"
    if name == "agentguardianmcp.exe":
        return "mcp"
    return "unknown"


def _integration_exit_code(result: str) -> int:
    if result in _SUCCESS_CODES:
        return 0
    if result in _ROLLBACK_CODES or result.endswith("ROLLBACK_FAILED"):
        return 3
    return 2


def main(arguments: list[str] | None = None) -> int:
    selected = list(sys.argv[1:] if arguments is None else arguments)
    launcher = _frozen_launcher()
    if selected == list(_STDIO_ARGUMENTS):
        if launcher in {"gui", "unknown"}:
            return USAGE_ERROR
        from agentguardian.mcp_server import run_stdio

        return run_stdio()
    if "--stdio-mcp" in selected:
        return USAGE_ERROR
    if launcher in {"mcp", "unknown"}:
        return USAGE_ERROR
    if selected == [_PURGE_ARGUMENT]:
        from agentguardian.app import run_maintenance_command

        result = run_maintenance_command(selected)
        return USAGE_ERROR if result is None else result
    if _PURGE_ARGUMENT in selected:
        return USAGE_ERROR
    if len(selected) == 1 and selected[0] in _INSTALL_ARGUMENTS:
        from agentguardian.codex_integration import install_integration

        install_skill, enable_mcp = _INSTALL_ARGUMENTS[selected[0]]
        result = install_integration(
            install_skill=install_skill,
            enable_mcp=enable_mcp,
        )
        return _integration_exit_code(result)
    if selected == ["--remove-codex-integration"]:
        from agentguardian.codex_integration import uninstall_integration

        return _integration_exit_code(uninstall_integration())
    if any(
        argument.startswith("--install-codex-integration")
        or argument == "--remove-codex-integration"
        for argument in selected
    ):
        return USAGE_ERROR
    if selected:
        return USAGE_ERROR
    from agentguardian.app import main as run_gui

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
