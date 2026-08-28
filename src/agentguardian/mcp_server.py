from __future__ import annotations

from mcp.server import MCPServer

from . import __version__
from .mcp_service import AuditMcpService


_INSTRUCTIONS = (
    "AgentGuardian supports personal, non-regulated data only. "
    "Call prepare_audit first, show consent_summary verbatim, then request "
    "run_prepared_audit. Never describe incomplete or truncated output as safe."
)
_service = AuditMcpService()
server = MCPServer("AgentGuardian", version=__version__, instructions=_INSTRUCTIONS)


@server.tool()
def prepare_audit(
    operation: str,
    classification: str,
    roots: list[str] | None = None,
    browser_kind: str | None = None,
    database_path: str | None = None,
    url: str | None = None,
) -> dict[str, object]:
    """Prepare one bounded local audit without reading content or using the network."""
    return _service.prepare_audit(
        operation=operation,
        classification=classification,
        roots=roots,
        browser_kind=browser_kind,
        database_path=database_path,
        url=url,
    )


@server.tool()
def run_prepared_audit(
    authorization_id: str,
    scope_digest: str,
    consent_summary: str,
) -> dict[str, object]:
    """Consume one prepared authorization and return a bounded redacted result."""
    return _service.run_prepared_audit(
        authorization_id=authorization_id,
        scope_digest=scope_digest,
        consent_summary=consent_summary,
    )


def run_stdio() -> int:
    server.run()
    return 0
