# AgentGuardian Codex Skill

This is the independently distributable AgentGuardian Codex Skill, version
0.2.0, licensed under Apache-2.0. It requires an AgentGuardian runtime in the
range `>=0.3.0a1,<0.4` and the local MCP tools `prepare_audit` and
`run_prepared_audit`.

## Two-layer installation

The Skill and the local runtime are separate products:

1. Copy this directory to `%USERPROFILE%\.agents\skills\agentguardian`.
2. Obtain a Windows installer or portable ZIP from the target repository's
   GitHub release page:
   `https://github.com/yangjing6213-dev/AgentGuardian/releases`.
3. Configure the host's local STDIO MCP server with
   `AgentGuardianMcp.exe --stdio-mcp`. The console helper is the MCP entry
   point; `AgentGuardian.exe` is the windowed launcher.
4. Start a new agent session. The Skill checks for both required MCP tools
   before offering any audit operation.

If no release asset and matching SHA-256 are published, the runtime is not
available for installation yet. This package does not include a binary,
downloader, or host-configuration writer, and it never guesses an executable
path. Codex Desktop, Codex CLI, and other agents must use their own local
STDIO configuration mechanism.

## Capability and data boundary

When both tools are visible, the Skill exposes four bounded operations:
`files`, `browser`, `clipboard`, and `public_share`. Each request requires
one operation, explicit `personal_non_regulated` classification, and a user
choice after the local consent summary is shown.

Do not use it for medical, financial, identity, biometric, legally
privileged, customer-dataset, national-secret, regulated, or other highly
sensitive real data. Redacted arguments and results may enter the Codex model context.
Incomplete or truncated coverage cannot establish safety.

The Skill does not call an OpenAI or other Provider API and does not provide
automatic remediation. This preview is not production-safe, is not a
certification, and must not be represented as proof that an agent, account,
MCP server, browser, share, or system is safe.
