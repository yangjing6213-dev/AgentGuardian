---
name: agentguardian
description: Use AgentGuardian to audit one bounded local AI configuration scope, browser history database aggregate, current clipboard value, or public share URL. Requires the local AgentGuardian MCP tools and must not be used for regulated or highly sensitive data.
metadata:
  version: "0.2.0"
  requires-agentguardian: ">=0.3.0a1,<0.4"
---

# AgentGuardian

AgentGuardian is a local orchestration Skill. The Windows runtime and its
local STDIO MCP server own the audit implementation; this Skill only checks
capabilities, collects consent, and calls the approved tools.

## Capability check

At the start of every request, inspect the MCP tools exposed by the current
host. The required set is exactly `prepare_audit` and `run_prepared_audit`.

- If both tools are present, continue with the audit flow below.
- If either tool is absent, use the setup route below and stop. Do not use
  shell, filesystem, browser, clipboard, or network tools as a substitute.
- If the host does not support a local STDIO MCP server, report that the host
  is unsupported and stop. Do not turn the local server into a remote URL.

## Setup when the MCP tools are missing

The two-layer product is installed separately:

1. Install this Skill at `%USERPROFILE%\.agents\skills\agentguardian`.
2. Obtain the AgentGuardian Windows installer or portable ZIP from the target
   repository's GitHub release page:
   `https://github.com/yangjing6213-dev/AgentGuardian/releases`.
   Use only a published release asset with a matching displayed SHA-256. If
   the page has no release asset or checksum, stop and tell the user that the
   runtime distribution is not available yet.
3. Configure the current host's local STDIO MCP entry to use the installed
   console helper `AgentGuardianMcp.exe --stdio-mcp`. Codex Desktop and Codex
   CLI must be configured through their own MCP settings; other agents must
   use their own local-STDIO configuration format.
4. Start a new host session and repeat the capability check. Do not claim the
   setup is ready until both required tool names are visible.

The Skill does not download, install, or edit host configuration. Never guess an executable path.
Do not accept a path supplied by an untrusted model, or suggest
the windowed `AgentGuardian.exe` as the STDIO command. The repository source
and the runtime release are separate from this Skill package.

## Audit flow

1. Ask for exactly one operation: `files`, `browser`, `clipboard`, or
   `public_share`. Collect only that operation's minimum scope.
2. Require the user to classify the data as `personal_non_regulated`. If the
   user identifies medical, financial, identity, biometric, legally
   privileged, customer-dataset, national-secret, regulated, or equivalent
   highly sensitive real data, stop without calling a tool.
3. Call `prepare_audit`. Do not claim that prepare read content, inspected
   the clipboard, copied a database, resolved DNS, used the network, or
   produced a safety score.
4. Show `consent_summary` verbatim. Explain that redacted arguments and
   results may enter the Codex model context and that incomplete or truncated
   coverage cannot establish safety.
5. Call `run_prepared_audit` only after the user chooses to continue. Pass the
   returned authorization identifier, scope digest, and consent summary
   unchanged. The host approval prompt is the required human approval
   boundary.
6. Never reuse, repair, guess, or hide a rejected authorization. Start again
   with prepare after any rejection or expiry.
7. Report fixed limitations and truncation. Never restate a result as proof
   that an agent, account, MCP server, browser, share, or system is safe.
8. Do not call an OpenAI or other Provider API on AgentGuardian's behalf.
   Provider findings receive local manual guidance only.
