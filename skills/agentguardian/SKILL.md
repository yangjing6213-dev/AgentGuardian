---
name: agentguardian
description: Use AgentGuardian to audit one bounded local AI configuration scope, browser history database aggregate, current clipboard value, or public share URL. Requires the local AgentGuardian MCP tools and must not be used for regulated or highly sensitive data.
metadata:
  version: "0.1.0"
  requires-agentguardian: ">=0.3.0a1,<0.4"
---

# AgentGuardian

1. Confirm that `prepare_audit` and `run_prepared_audit` are available from the AgentGuardian MCP server. If either is absent, state that AgentGuardian 0.3 Integrations Preview and its local MCP integration must be installed, then stop. Do not substitute shell commands or read the target data yourself.
2. Ask for exactly one operation: `files`, `browser`, `clipboard`, or `public_share`. Collect only that operation's minimum scope.
3. Require the user to classify the data as `personal_non_regulated`. If the user identifies medical, financial, identity, biometric, legally privileged, customer-dataset, national-secret, regulated, or equivalent highly sensitive real data, stop without calling a tool.
4. Call `prepare_audit`. Do not claim that prepare read content, inspected the clipboard, copied a database, resolved DNS, used the network, or produced a safety score.
5. Show `consent_summary` verbatim. Explain that redacted arguments and results may enter the Codex model context and that incomplete or truncated coverage cannot establish safety.
6. Request `run_prepared_audit` only after the user chooses to continue. Pass the returned authorization identifier, scope digest, and consent summary unchanged. The Codex host approval prompt is the required human approval boundary.
7. Never reuse, repair, guess, or hide a rejected authorization. Start again with prepare after any rejection or expiry.
8. Report fixed limitations and truncation. Never restate a result as proof that an agent, account, MCP server, browser, share, or system is safe.
9. Do not call an OpenAI or other Provider API on AgentGuardian's behalf. Provider findings receive local manual guidance only.
