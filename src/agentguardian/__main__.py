from __future__ import annotations

import sys


USAGE_ERROR = 64


def main(arguments: list[str] | None = None) -> int:
    selected = list(sys.argv[1:] if arguments is None else arguments)
    if selected == ["--stdio-mcp"]:
        from agentguardian.mcp_server import run_stdio

        return run_stdio()
    if "--stdio-mcp" in selected:
        return USAGE_ERROR
    from agentguardian.app import main as run_gui

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
