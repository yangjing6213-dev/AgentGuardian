# Packaged MCP Adapter Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require a real, organization-signed, certificate-pinned MCP adapter to be embedded in the trusted Windows package and successfully executed under the native AppContainer/Job Object boundary before a release candidate can pass.

**Architecture:** A trusted build downloads an operator-controlled adapter only after receiving an exact SHA-256 and signer identity, then `build_windows_portable.py` verifies and stages it at a fixed bundle path before payload manifests and the ZIP are created. After MSIX installation and upgrade, `verify_windows_msix.ps1` invokes a Python acceptance runner against the installed adapter. The final release verifier binds that evidence to the source commit and bundled adapter metadata. Unsigned CI remains unchanged; missing trusted adapter inputs fail closed.

**Tech Stack:** Python 3.12, pytest, PowerShell 7, Windows Authenticode/Crypt32, AppContainer, Job Object, GitHub Actions, MSIX.

---

### Task 1: Acceptance evidence and final release gate

**Files:**
- Create: `scripts/run_windows_mcp_adapter_acceptance.py`
- Modify: `scripts/verify_windows_release_candidate.py`
- Create: `tests/test_windows_mcp_adapter_acceptance.py`
- Modify: `tests/test_release_evidence.py`

- [ ] **Step 1: Write failing acceptance-runner tests**

Add tests that call `run_packaged_adapter_acceptance` with a real temporary executable and monkeypatched sandbox result. Require an absolute local non-reparse adapter, a new absolute evidence path, a full lowercase source SHA, an exact lowercase adapter SHA-256, a non-empty trimmed X.500 subject, and a lowercase certificate SHA-256. Assert successful evidence contains only schema, source commit, fixed adapter basename/hash/signer identity, bounded sandbox metadata, and `passed=true`; it must not contain the adapter path, request bytes, response bytes, environment values, or exception text. Add negative cases for path/hash/signer/certificate mismatch, sandbox denial/failure, missing network/process isolation limits, raw-output retention, and existing/relative/reparse evidence paths.

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```powershell
python -m pytest -q tests/test_windows_mcp_adapter_acceptance.py
```

Expected: collection fails because `scripts.run_windows_mcp_adapter_acceptance` does not exist.

- [ ] **Step 3: Implement the minimal acceptance runner**

Create a fixed one-shot request constant and the public function `run_packaged_adapter_acceptance(adapter_path, evidence_path, *, expected_source_commit, expected_adapter_sha256, expected_publisher_subject, expected_certificate_sha256)`. Its successful output must use this exact bounded structure:

```python
evidence = {
    "schema": 1,
    "source_commit": expected_source_commit,
    "adapter": {
        "name": adapter.name,
        "sha256": expected_adapter_sha256,
        "publisher_subject": expected_publisher_subject,
        "certificate_sha256": expected_certificate_sha256,
    },
    "sandbox": {
        "status": result.status.value,
        "reason": result.reason,
        "response_bytes": result.response_bytes,
        "raw_response_retained": result.raw_response_retained,
        "limits": list(result.limits),
    },
    "passed": True,
}
```

It must construct `McpSandboxPolicy.from_command` with no adapter arguments, call `run_mcp_sandbox` with the policy, fixed request, and `confirmed=True`, require `COMPLETED`, `reason == "completed"`, `response_bytes > 0`, `raw_response_retained is False`, and both native isolation limits. Write canonical ASCII JSON to a new evidence path only after validation. The CLI must expose matching required arguments and return nonzero on failure without printing raw request/response data.

- [ ] **Step 4: Verify the acceptance runner GREEN**

Run:

```powershell
python -m pytest -q tests/test_windows_mcp_adapter_acceptance.py
```

Expected: all tests pass.

- [ ] **Step 5: Write failing final-gate tests**

Extend `_write_candidate` in `tests/test_release_evidence.py` to create `MCP-ADAPTER.json` in the bundle and matching MCP acceptance evidence. Pass the new evidence path to every trusted release validation. Add failures for absent evidence, source mismatch, adapter metadata mismatch, non-completed sandbox state, raw retention, and missing isolation limits.

- [ ] **Step 6: Run final-gate tests and verify RED**

Run:

```powershell
python -m pytest -q tests/test_release_evidence.py
```

Expected: failures because the verifier does not accept or validate MCP evidence.

- [ ] **Step 7: Implement the final release binding**

Add required keyword `mcp_adapter_evidence_path` to `validate_release_candidate` and CLI option `--mcp-adapter-evidence`. Validate `MCP-ADAPTER.json` and the evidence with the existing bounded local-path JSON loader. Require exact source commit, adapter basename, SHA-256, publisher subject, certificate SHA-256, `passed=true`, completed bounded result, no raw retention, positive response bytes, and exact native isolation limits. Return only bounded release metadata.

- [ ] **Step 8: Run focused tests and commit**

Run:

```powershell
python -m pytest -q tests/test_windows_mcp_adapter_acceptance.py tests/test_release_evidence.py
python -m compileall -q scripts
git diff --check
```

Expected: all pass. Commit only the four Task 1 files.

### Task 2: Trusted bundle staging and installed-package execution

**Files:**
- Modify: `scripts/build_windows_portable.py`
- Modify: `scripts/verify_windows_msix.ps1`
- Modify: `.github/workflows/windows-mvp-signed.yml`
- Modify: `tests/test_windows_packaging.py`
- Modify: `tests/test_windows_msix.py`

- [ ] **Step 1: Write failing trusted-bundle staging tests**

Add tests for `stage_trusted_mcp_adapter` that use a temporary adapter and monkeypatch Authenticode identity verification. Require a fixed destination `adapters/AgentGuardianMcpAdapter.exe`, canonical `MCP-ADAPTER.json`, exact file hash, exact signer subject/certificate pin, no reparse/UNC input, and no staging for unsigned builds. Require `build_portable` with `artifact_status="trusted_release"` inputs to be complete; partial or absent adapter inputs fail closed.

- [ ] **Step 2: Run staging tests and verify RED**

Run:

```powershell
python -m pytest -q tests/test_windows_packaging.py -k trusted_mcp
```

Expected: failures because staging support does not exist.

- [ ] **Step 3: Implement trusted adapter staging before manifests**

Add `stage_trusted_mcp_adapter` to validate the absolute regular local input, exact SHA-256, trusted Authenticode signature, exact X.500 subject, and exact certificate SHA-256. Copy it only to the fixed bundle path and write canonical metadata before `write_portable_evidence`, so `PAYLOAD-MANIFEST.json`, `SHA256SUMS`, and deterministic ZIP bind the adapter. Extend the build CLI with required trusted-adapter options; reject them for unsigned builds and require all of them for trusted builds.

- [ ] **Step 4: Verify staging GREEN**

Run:

```powershell
python -m pytest -q tests/test_windows_packaging.py
```

Expected: all tests pass.

- [ ] **Step 5: Write failing installed-package/workflow tests**

Extend PowerShell contract tests to require a `RequireMcpAdapterAcceptance` mode that accepts the expected source commit, adapter relative path/hash/publisher/certificate pin, and a new absolute evidence path. It must resolve the adapter beneath the installed package location after upgrade, reject traversal/reparse/missing files, invoke `run_windows_mcp_adapter_acceptance.py`, and fail before uninstall when acceptance fails. Extend workflow tests to require non-secret repository variables `AGENTGUARDIAN_MCP_ADAPTER_URL`, `AGENTGUARDIAN_MCP_ADAPTER_SHA256`, `AGENTGUARDIAN_MCP_ADAPTER_PUBLISHER`, and `AGENTGUARDIAN_MCP_ADAPTER_CERTIFICATE_SHA256`; download to `RUNNER_TEMP`, verify hash before build, pass trusted staging parameters, request installed-package acceptance, and pass `--mcp-adapter-evidence` to the final gate.

- [ ] **Step 6: Run workflow tests and verify RED**

Run:

```powershell
python -m pytest -q tests/test_windows_msix.py
```

Expected: failures because the PowerShell and workflow contracts are absent.

- [ ] **Step 7: Implement installed-package acceptance and workflow wiring**

Add the strict PowerShell parameter set and validation. Resolve the installed adapter with `Join-Path` plus full-path containment and reparse checks, invoke the Python acceptance runner, and preserve uninstall cleanup in `finally`. In the trusted workflow, fail closed on any missing adapter variable, download only to a fixed `RUNNER_TEMP` path, compare SHA-256 before build, and never print certificate material or adapter response data.

- [ ] **Step 8: Verify Task 2 and commit**

Run:

```powershell
python -m pytest -q tests/test_windows_packaging.py tests/test_windows_msix.py tests/test_windows_mcp_adapter_acceptance.py tests/test_release_evidence.py
python -m compileall -q src scripts tests
git diff --check
```

Expected: all pass. Commit only the five Task 2 files plus any Task 1 CLI reference required by the workflow.

### Task 3: Full evidence and documentation synchronization

**Files:**
- Modify: `README.md`
- Modify: `docs/security/enterprise-and-mcp-control-core.md`
- Modify: `docs/reports/windows-mvp-release-candidate-report.md`
- Modify: `docs/superpowers/plans/2026-08-15-agentguardian-product-completion.md`
- Modify: `src/agentguardian/source_policy.json` only if reviewed package source changed

- [ ] **Step 1: Run current full local gates**

Run:

```powershell
python -m pytest -q
python scripts/run_windows_mvp_security_gate.py
python -m compileall -q src scripts tests
git diff --check
```

- [ ] **Step 2: Synchronize evidence boundaries**

Document that the trusted workflow now requires a real downloaded, exact-hash and exact-certificate-pinned adapter, embeds it before payload manifests, and executes it from the installed package under AppContainer/Job Object. State that the workflow has not passed until organization signing material, adapter variables, license approval, and independent clean-machine execution are present. Keep release decision `NO-GO`.

- [ ] **Step 3: Commit, push, and verify exact-SHA GitHub checks**

Stage explicit paths, commit, push `agent/founder-alpha`, and verify push/PR CI plus Windows workflow checks for the exact final SHA. Do not claim the manual trusted-signature workflow passed unless it was actually dispatched with the required external inputs and completed successfully.
