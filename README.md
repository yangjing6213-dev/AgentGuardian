![AgentGuardian](assets/brand/agentguardian-cover.svg)

# AgentGuardian Integrations Preview

AgentGuardian 0.3 Integrations Preview is the active development track for a local-first static security auditor on Windows 11 x64. Its supported use boundary is **personal non-regulated configuration**. The active entry points are the desktop GUI, the standalone Codex Skill, and the local STDIO MCP helper; all three use one local audit core. The current status is `INTEGRATIONS-PREVIEW-NOT-READY` and formal release remains `NO-GO`.

The `0.2.0-beta.1` Personal v1 candidate at frozen exact SHA `8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6` is historical evidence only. It remains `PRIVATE-BETA-NOT-READY` because external license and Qt approval, two-machine acceptance, and the operations/security gate are pending; formal public release remains `NO-GO`. Historical 0.2 evidence does not establish current 0.3 CI, installer, lifecycle, or review status.

## Current implementation

- Static audit of directories explicitly selected by the user, with bounded read-only discovery.
- Redacted JSON and HTML reports with explainable scoring, findings, and disposition guidance.
- Read-only browser SQLite metadata audit through a temporary local copy that is cleaned up after use.
- One-time, explicitly triggered clipboard inspection in memory; clipboard source text is not retained.
- Explicit public URL share-reachability checks. AgentGuardian does not upload audit data through this action.
- One fixed, allowlisted `OPENAI_BASE_URL_OVERRIDE` replacement with preview, confirmation, target recheck, backup, and same-session rollback.
- Local state protected for the current Windows user with DPAPI.
- Static MCP configuration detection for dangerous capability combinations.
- OpenAI Provider local adaptation, detection, and manual guidance only. The runtime must not call OpenAI or another provider API by default.
- A standalone Apache-2.0 Codex Skill and an opt-in local STDIO MCP entry point with `prepare_audit` and `run_prepared_audit`.
- Four bounded operations: `files`, `browser`, `clipboard`, and `public_share`, with human approval before the operation that reads or verifies data.

`Personal v1 不支持高敏感现实数据`。`联网分享验证仅在用户显式输入公开 URL 后执行`。

## Permanently excluded

The frozen 0.2 Personal v1 permanently excludes MCP runtime integration. The active 0.3 preview adds only the reviewed local STDIO MCP helper described in `docs/security/integrations-preview.md`; enterprise features, a high-sensitivity mode, and dynamic MCP execution remain unsupported. The runtime has no telemetry, cloud console, automatic arbitrary remediation, or plugin execution.

The static MCP detector does not download, load, launch, broker, sandbox, package, or execute MCP software. Provider findings are local configuration observations and manual guidance, not endpoint classification or API verification.

## Unsupported real data

Do not use Personal v1 with medical, financial, identity or biometric, legally privileged, customer data, state-secret, other regulated, or other high-sensitivity real data. This boundary is a use restriction, not a guarantee that AgentGuardian can classify content correctly.

## Not yet passed

The active 0.3 preview has not passed its eight-gate ledger. GitHub CI, the
Windows integrations workflow, clean-machine lifecycle, Codex CLI/Desktop
STDIO acceptance, license/marketplace review, local verification, and
independent review remain separately pending. The unsigned traditional
installer route is a development route only and is not a production-safe
release.

The intended delivery route is a traditional unsigned offline EXE installer sent directly to known private testers. No installer candidate has passed the required gates. Because it is unsigned, Windows may show Unknown Publisher or SmartScreen warnings; testers must verify the supplied SHA-256 before running it.

An artifact uploaded by this public repository's GitHub Actions workflow is not an access-controlled private distribution channel. `Private beta` is a maturity label for the known-tester scope, not a claim that an artifact is confidential or access-restricted.

Local evidence is generated outside Git and is current only when its report and
every artifact name the same clean source SHA. Earlier reports for another SHA,
including reports made before the current release-hardening changes, are
historical context and must not be promoted to current verification. A new
clean candidate must be rebuilt and revalidated before its build, staging,
installer, or CI results can be called current. Local evidence does not replace
GitHub CI, clean-machine, Codex CLI/Desktop, license/marketplace, or
operations/security evidence. GitHub Issues is live for ordinary support.
GitHub Private Vulnerability Reporting is disabled, so no current private
vulnerability intake is claimed. These limits prohibit production-safety,
license, or clean-machine claims.

The canonical partial status ledger is [personal-exe-private-beta-status.json](docs/security/personal-exe-private-beta-status.json). Private beta remains `PRIVATE-BETA-NOT-READY` and formal release remains `NO-GO`; exact-SHA evidence must be generated outside the candidate commit.

## Try from source

Use Windows 11 x64 and Python 3.12 or later. Run with ordinary user privileges and only synthetic or supported personal non-regulated configuration data.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python -m agentguardian
```

Developer verification:

```powershell
.\.venv\Scripts\python -m pip install -r requirements-dev.lock --require-hashes
.\.venv\Scripts\python -m pytest -q -p no:cacheprovider
```

The self-audit reports the Python 版本 but does not expose the interpreter path.

## Windows Public Preview download

Primary download for the future public preview:

https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe

This link resolves only after a separately authorized GitHub Release has been
published as neither draft nor prerelease. The first channel is AgentGuardian
0.3.0 Public Preview (unsigned), an unsigned Public Preview. Windows may show
Unknown Publisher or SmartScreen warnings. The current status remains
`INTEGRATIONS-PREVIEW-NOT-READY` and `NO-GO`; this link is not current release
evidence until that authorized handoff has happened.

The main EXE installer is intended to contain the current GUI, the local
STDIO MCP executable `AgentGuardianMcp.exe`, and the independent Skill payload.
Codex and other hosts still require the user to explicitly select and configure
their integration. The installer does not silently download or enable a Provider API.

The exact Release asset allowlist is:

- `AgentGuardian-0.3.0-preview.1-windows-x64.zip`
- `AgentGuardian-Setup-0.3.0-preview.1-x64.exe`
- `AgentGuardian-Setup-Windows-x64.exe`
- `AgentGuardian-Skill-0.2.0.zip`
- `DOWNLOAD-METADATA.json`
- `LICENSE`
- `SHA256SUMS`
- `THIRD_PARTY_NOTICES.md`

After publication, verify every downloaded file against `SHA256SUMS` before
running the installer. This preview targets Windows 11 x64 and personal
non-regulated use only. High-sensitivity real data is prohibited. Do not make
a production-safety claim from this preview, and do not assume any
enterprise control-plane guarantee.

The historical 0.2 results and earlier CI reports remain historical evidence;
they are distinct from current revalidation of the 0.3 release candidate.

## Reference documents

The Personal v1 links below are historical compatibility and governance
references. The active 0.3 route is defined in the Integrations Preview section
and its status ledger.

- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/security/personal-v1-threat-model.md)
- [Privacy](docs/security/personal-v1-privacy.md)
- [Support and vulnerability handling](docs/security/personal-v1-support.md)
- [Release gate runbook](docs/security/personal-v1-release-runbook.md)
- [Independent-machine acceptance](docs/security/personal-v1-independent-machine-acceptance.md)

## Development governance

- [Active 0.3 Integrations Preview boundary](docs/security/integrations-preview.md)
- [Active 0.3 status ledger](docs/security/integrations-preview-status.json)
- [Active Integrations Preview implementation plan](docs/superpowers/plans/2026-08-24-agentguardian-integrations-preview.md)

- [Approved Personal v1 specification](docs/superpowers/specs/2026-08-16-agentguardian-personal-v1-design.md)
- [Active Personal EXE private-beta implementation plan](docs/superpowers/plans/2026-08-21-agentguardian-personal-exe-private-beta.md)

The approved specification and active implementation plan govern development; they are not product capability claims or release evidence. The Store/MSIX/WACK/Partner Center route and its artifacts are historical and non-governing. Retiring or deleting that route does not pass any private-beta gate. Other documents under `docs/superpowers` are historical planning snapshots; older Windows MVP reports are historical planning or evidence snapshots. `docs/security/windows-mvp-threat-model.md` and `docs/security/windows-release-evidence.md` are also historical snapshots. They are not active Personal v1 product promises or current release evidence.

## License

Source code is licensed under [Apache License 2.0](LICENSE). That repository license does not replace the pending external review of the exact candidate SBOM, Qt, and redistribution obligations.
