# AgentGuardian Codex Skill

This is the independently distributable AgentGuardian Codex Skill, version
0.1.0, licensed under Apache-2.0. It requires an AgentGuardian runtime in the
range `>=0.3.0a1,<0.4` and the local MCP tools `prepare_audit` and
`run_prepared_audit`.

## Installation

Copy this Skill to `%USERPROFILE%\.agents\skills\agentguardian`. The Skill is
separate from the AgentGuardian Python package and can be uploaded or sold as
an independent product. It does not install or modify a runtime by itself.

## Boundary

Use only for `personal_non_regulated` data and one bounded operation at a
time. Do not use it for medical, financial, identity, biometric, legally
privileged, customer-dataset, national-secret, regulated, or other highly
sensitive real data. A user must choose whether to continue after the local
consent summary is shown.

Redacted arguments and results may enter the Codex model context. Incomplete
or truncated coverage cannot establish safety. The Skill does not call an
OpenAI or other Provider API and does not provide automatic remediation.

This preview is not production-safe, is not a certification, and must not be
represented as proof that an agent, account, MCP server, browser, share, or
system is safe.
