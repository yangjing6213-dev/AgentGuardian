# AgentGuardian Personal v1.0 Scope Convergence Design

Status: approved active product specification. The development branch is at
the Task 7 documentation-convergence checkpoint; Task 8 exact-SHA and external
acceptance remains incomplete. This is governance status, not release evidence.

## Goal

Deliver AgentGuardian 1.0 as a formal Windows product for individual users.
The product performs local AI configuration security auditing with redacted
evidence and bounded, user-initiated actions. It does not support highly
sensitive real-world content, enterprise administration, or dynamic MCP
execution.

The release claim is limited to the documented personal-use scope on a
supported, uncompromised Windows host. It is not a general production-safety,
compliance, regulated-data, or compromised-host claim.

## Product Decisions

The following decisions are permanent for the Personal 1.x product line:

1. Highly sensitive real-world data is unsupported. AgentGuardian does not
   claim suitability for medical records, financial records, identity or
   biometric data, legally privileged material, customer datasets, state
   secrets, or equivalent regulated or third-party content.
2. Enterprise features are abandoned. There is no tenant, organization,
   remote device, enterprise policy, administrator service, policy signing,
   enrollment, telemetry, or remote control product surface.
3. Dynamic MCP execution is abandoned. The product detects risky MCP
   configuration statically but never downloads, loads, launches, brokers, or
   sandboxes an MCP adapter or other user-selected executable.
4. OpenAI Provider behavior remains local adaptation, detection, and manual
   guidance first. The default product makes no OpenAI or third-party API call.
5. Microsoft Store MSIX is the primary binary distribution and update channel.
   Source publication remains separate from formal binary release evidence.

## Supported Personal Scope

Personal 1.0 supports the following user-initiated capabilities:

- Read-only discovery of approved local AI configuration roots and explicit
  user-selected local folders.
- Static detection of credential patterns, privacy-risk patterns, provider
  overrides, and risky MCP configuration combinations.
- Explainable scoring and redacted JSON/HTML reports that do not reproduce
  credential values, raw matches, full paths, chats, or page contents.
- Explicit, read-only browser SQLite metadata auditing with bounded temporary
  snapshots and cleanup.
- One-time clipboard auditing after an explicit confirmation, with no writeback
  and no raw clipboard retention.
- Explicit, bounded public HTTP(S) reachability verification that sends no scan
  data and makes no content, permission, or indexing claim.
- One allowlisted remediation for `OPENAI_BASE_URL_OVERRIDE`, including preview,
  confirmation, target hash recheck, same-directory backup, atomic replacement,
  rollback, and mandatory re-audit.
- Local protected state, report comparison, package-source self-audit, and
  user-initiated redacted diagnostic export.

Credential-pattern auditing remains in scope because it is the product's core
purpose. A credential value may be read transiently for local matching but must
never be reproduced in UI evidence, reports, logs, diagnostics, or retained
state.

## Unsupported Data Boundary

The application must not imply that it can reliably classify every regulated
or highly sensitive file. It enforces the boundary through all of the following:

1. First-run and scan-scope consent identifies the unsupported data classes in
   concise language and requires the user to confirm the selected scope is
   eligible.
2. Known unsupported roots, broad roots, UNC paths, device paths, reparse paths,
   and recognized regulated-data selectors fail closed before scanning.
3. The report records the supported-use boundary and scope coverage without
   recording full paths or user content.
4. Product copy, Store metadata, documentation, and support responses never
   market the product for regulated or highly sensitive real-world data.

This boundary reduces misuse but is not a content-classification guarantee.

## Runtime Convergence

### Remove Enterprise Runtime

The desktop enterprise page, enterprise imports, enterprise modules, enterprise
optional dependency lock, enterprise scripts, enterprise tests, and enterprise
source-policy entries are removed from the active product tree. Git history is
the only archive.

The removal includes at least:

- `enterprise_control_plane.py`
- `enterprise_policy.py`
- `enterprise_service.py`
- `enterprise_signing.py`
- `requirements-enterprise.lock`

No placeholder menu, disabled route, hidden service, or future-enterprise copy
remains in the Personal build.

### Remove Dynamic Execution

The MCP supervisor, AppContainer launcher, Job Object launcher, adapter download,
adapter acceptance, embedded adapter signing policy, adapter build inputs, and
adapter release-evidence fields are removed. Static MCP configuration detection
stays in the scanner and report model.

The removal includes at least:

- `mcp_sandbox.py`
- `windows_appcontainer.py`
- `windows_job_object.py`
- MCP-only executable signing helpers
- `download_trusted_mcp_adapter.py`
- `run_windows_mcp_adapter_acceptance.py`

No subprocess or dynamic module execution path may replace the removed feature.

### Remove High-Sensitivity Product Mode

The `SensitiveModePolicy`, the desktop high-sensitivity checkbox, enterprise
high-sensitivity confirmation fields, and high-sensitivity product claims are
removed. Local-only behavior, no default API access, redaction, raw-data
non-retention, explicit network actions, and export safeguards become permanent
personal-product invariants rather than an optional mode.

The synthetic acceptance gate is renamed and narrowed to personal privacy
acceptance. It continues to prove redaction, clipboard non-retention, browser
snapshot cleanup, temporary workspace cleanup, and absence of raw markers in
reports and diagnostics. It does not produce high-sensitivity readiness
evidence.

## Personal Release Profile

A machine-readable `personal_store_release` profile binds the build and final
gate to this design. The profile rejects enterprise modules, high-sensitivity
mode, dynamic execution modules, adapter artifacts, default API access,
telemetry, and undeclared network capability.

The package-source self-audit and packaging tests verify both absence and
behavior:

- Forbidden modules and files are absent from source manifests and payloads.
- No UI route, import, entry point, workflow input, environment variable, or
  documentation promise exposes removed capabilities.
- Static MCP detection remains covered by focused tests.
- Supported personal workflows remain behaviorally unchanged except for the
  new unsupported-data consent and permanent privacy invariants.

## Distribution Architecture

The existing PFX-and-adapter trusted workflow is replaced for Personal 1.0 by a
Store-candidate workflow that:

1. Checks out an exact commit and installs hash-locked dependencies.
2. Runs the full suite, personal privacy acceptance, brand validation,
   compilation, source self-audit, and forbidden-capability checks.
3. Builds the reproducible x64 portable payload and Store-identity MSIX upload
   candidate without enterprise or adapter inputs.
4. Generates CycloneDX SBOM, third-party notices, build provenance, checksums,
   and a bounded release manifest.
5. Runs Windows App Certification Kit and records its report as candidate
   evidence.
6. Uploads candidate artifacts for Partner Center submission without publishing
   a GitHub binary release.

The formal package is the Microsoft Store-certified package. A private Store
audience is used before public availability. Final acceptance verifies Store
origin, exact package identity and version, signature trust, install, launch,
upgrade, bounded workflow use, termination, uninstall, and application-data
residue on independently provisioned Windows machines.

## Supported Platform

Personal 1.0 targets Windows 11 x64. Windows 11 25H2 is the primary support
baseline. Windows 11 24H2 may be transitional only while it remains in Microsoft
support. Windows 10, ARM64, administrator/SYSTEM execution, Windows Server,
Wine, and modified Windows installations are unsupported.

The manifest minimum and tested versions must match the published support
matrix. `windows-latest` CI is supporting evidence, not the independent machine
matrix.

## Privacy, Legal, And Support

Formal release requires:

- A public privacy policy describing local access, temporary copies, protected
  state, explicit network actions, retention, deletion, and unsupported data.
- A support contact and a public security vulnerability reporting channel.
- An approved license-review record bound to the exact source commit and SBOM
  digest, with one reviewed record for every shipped component.
- A documented Qt/PySide distribution decision and all required notices or a
  commercial license, reviewed by an authorized human.
- Release notes, supported-version policy, update and rollback procedure,
  vulnerability triage procedure, and a security update policy.

These are product operations, not substitutes for technical tests.

## Failure Behavior

- Selecting an unsupported or ambiguous scope fails before file traversal.
- Consent cancellation performs no scan and no clipboard read.
- Browser snapshot, report, diagnostic, or remediation cleanup failure is
  visible and cannot be reported as success.
- Any removed-capability file or payload entry fails packaging and the final
  release gate.
- Missing or stale license, privacy, WACK, Store, clean-machine, or review
  evidence keeps the release decision at `NO-GO`.
- Network errors affect only the explicit share-verification action and never
  change local audit results.
- No failure path enables API access, telemetry, enterprise behavior, dynamic
  execution, or raw-data persistence.

## Acceptance Gates

Personal 1.0 is complete only when all gates pass for one exact candidate:

Before any gate runs, the intended formal version, Store identity, and every
package input are committed and frozen in a NO-GO `1.0.0` private candidate
before any gate. That private candidate package may carry version `1.0.0` for
WACK, Store, and independent-machine evidence, but it is not a formal or public
release while any gate remains incomplete.

1. **Scope gate:** removed capabilities are absent from source, payload, UI,
   workflows, documentation, and runtime imports.
2. **Local gate:** full tests, focused privacy/security tests, brand validation,
   compilation, self-audit, and `git diff --check` pass on a clean tree.
3. **Remote gate:** normal push and Draft PR CI plus Windows candidate workflows
   pass for the exact SHA.
4. **Supply-chain gate:** reproducible payload, SBOM, checksums, provenance,
   third-party notices, and approved exact-SHA license review pass.
5. **Store gate:** WACK passes and the private-audience Store package has trusted
   Store origin, identity, version, and signature evidence.
6. **Independent-machine gate:** at least two fresh Windows 11 x64 environments
   pass install, launch, supported workflows, upgrade, crash/restart, uninstall,
   and residue acceptance without development tools.
7. **Independent-review gate:** no unresolved Critical or Important security,
   privacy, packaging, or scope finding remains.
8. **Operations gate:** privacy, support, vulnerability disclosure, release
   notes, update, rollback, and security-update processes are live.

The package validated by all eight gates already carries version `1.0.0`.
After all eight gates pass, only external status evidence and formal-release
wording may change. Any source, version, Store identity, dependency, or package
input change creates a new candidate and requires all affected gates to rerun.
Passing gates do not establish production safety or expand the unsupported data
or host-compromise boundary.

## Migration Sequence

1. Remove enterprise runtime and package surface.
2. Remove high-sensitivity mode while preserving permanent privacy invariants.
3. Remove dynamic MCP execution and simplify build/release evidence.
4. Add the personal release profile and forbidden-capability tests.
5. Add unsupported-data consent and personal privacy acceptance.
6. Replace the signed-adapter workflow with Store-candidate packaging and WACK.
7. Complete licenses, privacy, support, private Store flight, independent
   machines, and final review.

Each sequence item is independently committed and revalidated. Deletion count,
test count, or a green CI run alone is not release evidence.

## Non-Goals

- No support for highly sensitive or regulated real-world data.
- No enterprise edition, remote service, tenant, device, policy, or telemetry.
- No dynamic MCP, plugin, helper, script, shell, or arbitrary executable launch.
- No default OpenAI or third-party API call.
- No cloud synchronization, automatic credential revocation, arbitrary repair,
  continuous clipboard monitoring, browser content extraction, or search-index
  claim.
- No direct-download production binary until a separately designed trusted
  direct-signing and update channel is approved.
- No production-safety, compliance-certification, or compromised-host claim.
