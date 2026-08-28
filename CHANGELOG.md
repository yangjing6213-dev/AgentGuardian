# Changelog

## Unreleased

- Harden the standalone AgentGuardian Skill setup route and capability check.
- Keep the Skill independent from the Windows runtime and local STDIO MCP
  configuration.
- Keep the preview boundary at personal, non-regulated data with no default
  Provider API call.

## 0.3.0a1

- Added the shared local audit core, desktop GUI, standalone Skill, and opt-in
  local STDIO MCP entry point for the four bounded audit operations.
- Added the `prepare_audit` and `run_prepared_audit` consent contract.
