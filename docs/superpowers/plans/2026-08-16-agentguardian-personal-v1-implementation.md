# AgentGuardian Personal v1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Converge AgentGuardian into a formal-scope Windows personal product that statically audits approved local AI configuration, permanently excludes enterprise, high-sensitivity, and dynamic execution capabilities, and produces a Microsoft Store submission candidate with evidence-bound release gates.

**Architecture:** Keep the existing local PySide6 audit application, redacted reporting, explicit browser/clipboard/share actions, fixed remediation, protected state, and source self-audit. Remove abandoned runtime surfaces in three independently tested commits, then bind the remaining product to a machine-readable `personal_store_release` profile and a Store-candidate workflow. Store certification, legal approval, two independent machines, and final independent review remain fail-closed external gates rather than simulated test results.

**Tech Stack:** Python 3.12, PySide6, pytest, PyInstaller, MSIX/MakeAppx, PowerShell, GitHub Actions, CycloneDX JSON, Microsoft Windows App Certification Kit.

---

## File Structure

- `src/agentguardian/app.py`: personal desktop UI and user-initiated audit actions; enterprise and optional high-sensitivity mode surfaces are removed here.
- `src/agentguardian/workflow.py`: scope preview, eligibility boundary, and consent binding.
- `src/agentguardian/self_audit.py`: package-source capability scan; only capabilities retained by Personal v1 are audited.
- `src/agentguardian/source_policy.json`: exact canonical SHA-256 allowlist for shipped Python modules.
- `release_profiles/personal_store_release.json`: machine-readable source, payload, workflow, and active-document capability contract.
- `scripts/verify_personal_release_profile.py`: fail-closed verifier for the release profile.
- `scripts/run_personal_privacy_acceptance.py`: synthetic privacy invariant gate with no high-sensitivity readiness claim.
- `scripts/build_windows_portable.py`: reproducible personal payload, SBOM, notices, provenance, checksums, and release manifest.
- `scripts/build_windows_msix.py`: Store-identity MSIX staging without embedded adapter or enterprise input.
- `scripts/verify_windows_release_candidate.py`: exact-SHA personal candidate gate without adapter evidence.
- `scripts/verify_windows_msix.ps1`: install, launch, upgrade, termination, uninstall, and residue evidence without adapter execution.
- `.github/workflows/windows-mvp.yml`: ordinary Windows regression and development MSIX smoke.
- `.github/workflows/windows-store-candidate.yml`: manual Store submission candidate and WACK evidence workflow.
- `docs/security/personal-v1-*.md`: active threat model, privacy, support, release, and external acceptance instructions.

Historical design records under `docs/superpowers/` remain immutable context and are excluded from active product-copy scanning. The tasks stay in one plan because all three capability removals change the same UI, source manifest, packaging, release verifier, and workflow contracts.

### Task 1: Remove Enterprise Runtime And Package Surface

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/agentguardian/app.py`
- Modify: `src/agentguardian/self_audit.py`
- Modify: `src/agentguardian/source_policy.json`
- Modify: `tests/test_app_smoke.py`
- Modify: `tests/test_self_audit.py`
- Delete: `requirements-enterprise.lock`
- Delete: `src/agentguardian/enterprise_control_plane.py`
- Delete: `src/agentguardian/enterprise_policy.py`
- Delete: `src/agentguardian/enterprise_service.py`
- Delete: `src/agentguardian/enterprise_signing.py`
- Delete: `tests/test_enterprise_control_plane.py`
- Delete: `tests/test_enterprise_policy.py`
- Delete: `tests/test_enterprise_service.py`
- Delete: `tests/test_enterprise_signing.py`

- [ ] **Step 1: Replace the enterprise UI test with a personal-navigation contract**

```python
def test_window_navigation_contains_only_personal_pages(qapp):
    window = AgentGuardianWindow()
    assert [button.text() for button in window.navigation_buttons] == [
        "审计范围",
        "风险发现",
        "审计报告",
    ]
    assert window.stack.count() == 3
    assert not hasattr(window, "control_plane_status_label")
```

- [ ] **Step 2: Run the new contract and verify the old surface fails it**

Run: `rtk python -m pytest tests/test_app_smoke.py::test_window_navigation_contains_only_personal_pages -q -p no:cacheprovider`

Expected: `FAIL` because the current window exposes four pages and enterprise widgets.

- [ ] **Step 3: Remove the enterprise import, state, page, callbacks, and optional dependency**

In `app.py`, keep only these personal page registrations:

```python
for index, text in enumerate(("审计范围", "风险发现", "审计报告")):
    ...

self.stack.addWidget(self._scope_page())
self.stack.addWidget(self._findings_page())
self.stack.addWidget(self._report_page())
```

Remove `EnterpriseControlPlane`, `default_control_plane_path`, `self._control_plane`, `_enterprise_page`, and every control-plane callback. Remove the entire `[project.optional-dependencies].enterprise` table from `pyproject.toml`.

- [ ] **Step 4: Delete enterprise implementation, lock, and dedicated tests**

Use `apply_patch` to delete every file listed in this task. Git history is the recovery path; no archive or disabled route is added.

- [ ] **Step 5: Narrow self-audit and regenerate the canonical source policy**

Remove `enterprise_control_plane.py` and `enterprise_policy.py` from `_AUDITED_CAPABILITY_MODULES`. Remove all four enterprise paths from `source_policy.json`, recompute `app.py` and `self_audit.py`, and preserve sorted module names.

Run:

```powershell
$env:PYTHONPATH = "src"
python -c "import json; from pathlib import Path; from agentguardian.self_audit import _canonical_source_sha256; root=Path('src/agentguardian'); modules={p.relative_to(root).as_posix():_canonical_source_sha256(p.read_bytes()) for p in sorted(root.rglob('*.py'))}; Path('src/agentguardian/source_policy.json').write_text(json.dumps({'schema':1,'modules':modules},indent=2,ensure_ascii=True)+'\n',encoding='utf-8')"
```

Expected: the manifest contains exactly the remaining `src/agentguardian/**/*.py` files.

- [ ] **Step 6: Run focused and full regression**

Run: `rtk python -m pytest tests/test_app_smoke.py tests/test_self_audit.py tests/test_packaging.py -q -p no:cacheprovider`

Expected: `PASS`.

Run: `rtk python -m pytest -q -p no:cacheprovider`

Expected: `PASS`; the total test count is lower only because the deleted enterprise feature tests no longer describe the product.

- [ ] **Step 7: Commit the enterprise removal**

```powershell
rtk git add pyproject.toml src/agentguardian/app.py src/agentguardian/self_audit.py src/agentguardian/source_policy.json tests/test_app_smoke.py tests/test_self_audit.py requirements-enterprise.lock src/agentguardian/enterprise_control_plane.py src/agentguardian/enterprise_policy.py src/agentguardian/enterprise_service.py src/agentguardian/enterprise_signing.py tests/test_enterprise_control_plane.py tests/test_enterprise_policy.py tests/test_enterprise_service.py tests/test_enterprise_signing.py
rtk git commit -m "Remove abandoned enterprise runtime"
```

### Task 2: Make Privacy Invariants Permanent

**Files:**
- Modify: `src/agentguardian/app.py`
- Modify: `src/agentguardian/self_audit.py`
- Modify: `src/agentguardian/source_policy.json`
- Create: `scripts/run_personal_privacy_acceptance.py`
- Create: `tests/test_personal_privacy_acceptance.py`
- Modify: `tests/test_app_smoke.py`
- Modify: `tests/test_self_audit.py`
- Modify: `.github/workflows/windows-mvp.yml`
- Delete: `src/agentguardian/sensitive_mode.py`
- Delete: `scripts/run_sensitive_data_acceptance.py`
- Delete: `tests/test_sensitive_data_acceptance.py`
- Delete: `tests/test_sensitive_mode.py`

- [ ] **Step 1: Add failing permanent-privacy UI and export tests**

```python
def test_personal_window_has_no_high_sensitivity_mode(qapp):
    window = AgentGuardianWindow()
    assert not hasattr(window, "sensitive_mode_checkbox")
    assert not hasattr(window, "_sensitive_mode")
    assert window.share_button.isEnabled()


def test_personal_report_export_uses_redacted_report_without_mode(monkeypatch, qapp, tmp_path):
    window = AgentGuardianWindow()
    destination = tmp_path / "report.json"
    window.report_mode_combo.setCurrentText("JSON")
    window.report_json = '{"evidence":"masked"}'
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_args: (str(destination), "JSON"))
    window._export_report()
    assert destination.read_text(encoding="utf-8") == window.report_json
```

Run: `rtk python -m pytest tests/test_app_smoke.py -k "high_sensitivity_mode or export_uses_redacted" -q -p no:cacheprovider`

Expected: `FAIL` because mode state and conditional export still exist.

- [ ] **Step 2: Remove the optional mode while retaining fixed safeguards**

Delete the `SensitiveModePolicy` import, state, checkbox, callback, share short-circuit, and conditional export branches. Keep report redaction unchanged, keep share verification explicit and URL-only, and reduce export to:

```python
content = self.report_json if mode == "JSON" else self.report_html
try:
    export_new_report(path, content, self._report_roots)
except (OSError, PermissionError, TypeError, ValueError):
    QMessageBox.warning(self, "导出失败", "无法导出报告。")
    return
```

Change `export_new_report` to accept only `(destination, content, scanned_roots)` and retain exclusive creation, local-path validation, root separation, and cleanup-on-failure.

- [ ] **Step 3: Rename the synthetic acceptance without weakening it**

Move the acceptance implementation to `run_personal_privacy_acceptance.py`, remove `SensitiveModePolicy`, and emit this exact top-level contract:

```python
evidence = {
    "schema": 1,
    "profile": "personal_privacy_acceptance",
    "passed": True,
    "claims": {
        "redacted_reports": True,
        "clipboard_raw_retained": False,
        "browser_snapshot_cleaned": True,
        "temporary_workspace_cleaned": True,
        "raw_markers_absent": True,
        "default_api_call": False,
    },
}
```

The acceptance still scans only generated synthetic data or an explicitly supplied sanitized sample and rejects raw markers in JSON, HTML, diagnostics, and evidence.
The claim values are derived from the report, clipboard, browser, cleanup, and
package self-audit checks; they are not unconditional constants. The evidence
contains no high-sensitivity mode or readiness field.

- [ ] **Step 4: Add acceptance tests and update the workflow**

```python
def test_personal_privacy_acceptance_proves_only_personal_invariants(tmp_path):
    evidence_path = tmp_path / "personal-privacy-acceptance.json"
    result = run_acceptance(evidence_path=evidence_path)
    assert result["profile"] == "personal_privacy_acceptance"
    assert result["claims"]["raw_markers_absent"] is True
    assert result["claims"]["clipboard_raw_retained"] is False
    assert result["claims"]["default_api_call"] is False
    assert "high_sensitivity" not in result
    assert "sensitive_mode" not in evidence_path.read_text(encoding="utf-8")
```

Replace the workflow step with:

```yaml
- name: Run personal privacy acceptance gate
  shell: pwsh
  run: |
    New-Item -ItemType Directory -Path "$pwd\.analysis" -Force | Out-Null
    python scripts/run_personal_privacy_acceptance.py `
      --evidence-path "$pwd\.analysis\personal-privacy-acceptance.json"
    Get-Content -LiteralPath "$pwd\.analysis\personal-privacy-acceptance.json"
```

- [ ] **Step 5: Delete old mode files, regenerate source policy, and test**

Delete the four old files listed above, remove `sensitive_mode.py` from the source policy, regenerate all hashes using Task 1 Step 5, then run:

`rtk python -m pytest tests/test_app_smoke.py tests/test_personal_privacy_acceptance.py tests/test_clipboard_audit.py tests/test_browser_audit.py tests/test_reporting.py -q -p no:cacheprovider`

Expected: `PASS`.

Run: `rtk python -m pytest -q -p no:cacheprovider`

Expected: `PASS`.

- [ ] **Step 6: Commit permanent privacy invariants**

Stage only the files listed in Task 2 and commit with `rtk git commit -m "Make personal privacy safeguards permanent"`.

### Task 3: Remove Dynamic MCP And Adapter Execution

**Files:**
- Modify: `scripts/build_windows_portable.py`
- Modify: `scripts/verify_windows_release_candidate.py`
- Modify: `scripts/verify_windows_msix.ps1`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security/windows-mvp-threat-model.md`
- Delete: `docs/security/enterprise-and-mcp-control-core.md`
- Delete: `.github/workflows/windows-mvp-signed.yml`
- Modify: `src/agentguardian/self_audit.py`
- Modify: `src/agentguardian/source_policy.json`
- Modify: `tests/test_windows_packaging.py`
- Modify: `tests/test_release_evidence.py`
- Modify: `tests/test_windows_msix.py`
- Modify: `tests/test_self_audit.py`
- Delete: `src/agentguardian/mcp_sandbox.py`
- Delete: `src/agentguardian/windows_appcontainer.py`
- Delete: `src/agentguardian/windows_code_signing.py`
- Delete: `src/agentguardian/windows_job_object.py`
- Delete: `scripts/download_trusted_mcp_adapter.py`
- Delete: `scripts/run_windows_mcp_adapter_acceptance.py`
- Delete: `tests/test_mcp_sandbox.py`
- Delete: `tests/test_trusted_adapter_download.py`
- Delete: `tests/test_windows_appcontainer.py`
- Delete: `tests/test_windows_code_signing.py`
- Delete: `tests/test_windows_job_object.py`
- Delete: `tests/test_windows_mcp_adapter_acceptance.py`

- [ ] **Step 1: Add failing package and release tests for adapter absence**

```python
def test_personal_portable_builder_has_no_adapter_contract():
    source = Path("scripts/build_windows_portable.py").read_text(encoding="utf-8")
    for token in ("mcp_adapter", "trusted_mcp", "windows_code_signing"):
        assert token not in source.casefold()


def test_personal_release_gate_has_no_adapter_evidence_argument():
    signature = inspect.signature(validate_release_candidate)
    assert "mcp_adapter_evidence" not in signature.parameters
```

Run: `rtk python -m pytest tests/test_windows_packaging.py tests/test_release_evidence.py -k "no_adapter" -q -p no:cacheprovider`

Expected: `FAIL` against the current adapter-bound build and release contracts.

- [ ] **Step 2: Simplify the portable builder and release gate**

Remove `windows_code_signing`, `stage_trusted_mcp_adapter`, adapter constants, adapter CLI options, adapter metadata, adapter locks, and adapter validation helpers. `build_portable` retains these release inputs only:

```python
def build_portable(
    output_root: Path,
    *,
    project_root: Path,
    source_commit: str,
    built_at: str,
    artifact_status: str = "development_only",
) -> Path:
    ...
```

Change `validate_release_candidate` and its CLI to require bundle, MSIX smoke evidence, exact source commit, trusted Store identity evidence, fresh-user-state evidence, and license review only. Remove all adapter manifest and evidence checks.

- [ ] **Step 3: Remove adapter parameters from MSIX verification**

Delete `RequireMcpAdapterAcceptance`, `McpAdapterRelativePath`, all expected adapter pins, the adapter evidence path, the installed-adapter execution block, and adapter fields from emitted evidence. Preserve package identity, source commit, trusted signature/Store origin, upgrade, launch, termination, uninstall, and residue checks.

- [ ] **Step 4: Delete the old signed-adapter workflow**

Delete `.github/workflows/windows-mvp-signed.yml`. The existing
`windows-mvp.yml` remains the development package compatibility gate; Task 6
adds the distinct Store-candidate workflow. Add a test that the retired workflow
is absent and that no active workflow contains a PFX secret, adapter variable,
adapter download, executable launch, or trusted-release claim.

- [ ] **Step 5: Delete dynamic execution files and retain static MCP detection**

Delete every dynamic implementation, script, and test listed in this task. Remove their source-policy and `_AUDITED_CAPABILITY_MODULES` entries. Do not change `detectors.py`, scoring reason `mcp_dangerous_combination`, or the static MCP detector tests.

Add this focused retained-capability assertion to `tests/test_detectors.py`:

```python
def test_personal_profile_retains_static_mcp_risk_detection():
    findings = scan_text(
        Path("mcp.json"),
        '{"mcpServers":{"unsafe":{"command":"tool","permissions":["filesystem","network"]}}}',
    )
    assert any(finding.rule_id == "MCP_DANGEROUS_COMBINATION" for finding in findings)
```

Delete `docs/security/enterprise-and-mcp-control-core.md`, remove dynamic MCP
and signed-adapter claims from `README.md` and `docs/architecture.md`, and
replace the dynamic-MCP threat row with the retained static-configuration
detection boundary. Historical records under `docs/superpowers/` remain
unchanged.

- [ ] **Step 6: Regenerate policy and run regressions**

Regenerate `source_policy.json` using Task 1 Step 5.

Run: `rtk python -m pytest tests/test_detectors.py tests/test_self_audit.py tests/test_windows_packaging.py tests/test_windows_msix.py tests/test_release_evidence.py -q -p no:cacheprovider`

Expected: `PASS` with static MCP detection still covered and no executable path.

Run: `rtk python -m pytest -q -p no:cacheprovider`

Expected: `PASS`.

- [ ] **Step 7: Commit dynamic execution removal**

Stage only the files listed in Task 3 and commit with `rtk git commit -m "Remove dynamic MCP execution surface"`.

### Task 4: Add The Personal Store Release Profile

**Files:**
- Create: `release_profiles/personal_store_release.json`
- Create: `scripts/verify_personal_release_profile.py`
- Create: `tests/test_personal_release_profile.py`
- Modify: `scripts/build_windows_portable.py`
- Modify: `scripts/verify_windows_release_candidate.py`

- [ ] **Step 1: Write failing profile-verifier tests**

```python
def test_repository_matches_personal_store_release_profile():
    result = verify_profile(Path.cwd(), Path("release_profiles/personal_store_release.json"))
    assert result == {"profile": "personal_store_release", "status": "pass"}


@pytest.mark.parametrize("forbidden", [
    "src/agentguardian/enterprise_policy.py",
    "src/agentguardian/sensitive_mode.py",
    "src/agentguardian/mcp_sandbox.py",
    "scripts/download_trusted_mcp_adapter.py",
])
def test_profile_rejects_forbidden_source_path(tmp_path, forbidden):
    root = copy_profile_fixture(tmp_path)
    path = root / forbidden
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("forbidden", encoding="utf-8")
    with pytest.raises(ProfileViolation, match="FORBIDDEN_PATH"):
        verify_profile(root, root / "release_profiles/personal_store_release.json")
```

Run: `rtk python -m pytest tests/test_personal_release_profile.py -q -p no:cacheprovider`

Expected: `FAIL` because the profile and verifier do not exist.

- [ ] **Step 2: Create the exact machine-readable profile**

```json
{
  "schema": 1,
  "name": "personal_store_release",
  "forbidden_source_globs": [
    "requirements-enterprise.lock",
    "src/agentguardian/enterprise_*.py",
    "src/agentguardian/sensitive_mode.py",
    "src/agentguardian/mcp_sandbox.py",
    "src/agentguardian/windows_appcontainer.py",
    "src/agentguardian/windows_code_signing.py",
    "src/agentguardian/windows_job_object.py",
    "scripts/*mcp_adapter*.py"
  ],
  "forbidden_payload_globs": ["adapters/**", "**/*McpAdapter*.exe"],
  "forbidden_workflow_tokens": [
    "AGENTGUARDIAN_SIGNING_PFX",
    "AGENTGUARDIAN_MCP_ADAPTER",
    "McpAdapter",
    "mcp_adapter"
  ],
  "forbidden_runtime_imports": [
    "importlib",
    "openai",
    "runpy",
    "subprocess"
  ],
  "forbidden_runtime_calls": ["__import__", "compile", "eval", "exec"],
  "forbidden_runtime_symbols": [
    "EnterpriseControlPlane",
    "SensitiveModePolicy"
  ],
  "active_document_paths": [
    "README.md",
    "docs/architecture.md",
    "docs/security/*.md"
  ],
  "forbidden_document_promises": [
    "dynamic MCP execution is implemented",
    "high-sensitivity mode is supported",
    "enterprise control plane is implemented"
  ],
  "required_source_paths": [
    "src/agentguardian/detectors.py",
    "src/agentguardian/share_verification.py",
    "scripts/run_personal_privacy_acceptance.py"
  ],
  "declared_network_modules": ["src/agentguardian/share_verification.py"]
}
```

- [ ] **Step 3: Implement a fail-closed verifier**

Implement `ProfileViolation(code)` plus `load_profile`, `verify_profile`, and
`verify_payload`. Require exact schema keys, sorted unique arrays, relative
POSIX patterns, bounded JSON size, no symlink/reparse traversal, all required
paths present, and all forbidden paths absent. Parse runtime Python with `ast`:
reject actual forbidden imports/calls/symbol use, telemetry/LLM imports, and any
network import outside the exact declared module list while allowing
`self_audit.py` to contain detector literals. Scan workflow text only for the
workflow token list and active documents only for exact retired positive
promises. Return only
`{"profile": "personal_store_release", "status": "pass"}` on success.

- [ ] **Step 4: Bind packaging and final release verification**

Call `verify_profile(project_root, project_root / "release_profiles/personal_store_release.json")` before PyInstaller. Call `verify_payload(bundle_root, profile)` before writing portable evidence and again in `validate_release_candidate`.

- [ ] **Step 5: Test hostile profile and payload cases**

Add parameterized tests for duplicate keys, unknown keys, unsorted arrays, absolute/traversal globs, oversized profile, case-insensitive forbidden payload names, symlink/reparse entries, forbidden workflow variables, undeclared network imports, missing required files, and payload adapter residue.

Run: `rtk python -m pytest tests/test_personal_release_profile.py tests/test_windows_packaging.py tests/test_release_evidence.py -q -p no:cacheprovider`

Expected: `PASS`.

- [ ] **Step 6: Commit the release profile**

Stage the five files listed in Task 4 and commit with `rtk git commit -m "Bind builds to personal Store profile"`.

### Task 5: Enforce Unsupported-Data Scope Consent

**Files:**
- Modify: `src/agentguardian/workflow.py`
- Modify: `src/agentguardian/app.py`
- Modify: `src/agentguardian/reporting.py`
- Modify: `tests/test_workflow.py`
- Modify: `tests/test_app_smoke.py`
- Modify: `tests/test_reporting.py`
- Modify: `src/agentguardian/source_policy.json`

- [ ] **Step 1: Add failing eligibility and consent tests**

```python
@pytest.mark.parametrize("name", [
    "medical-records", "patient-data", "financial-records", "biometric-data",
    "privileged-legal", "customer-dataset", "state-secrets",
])
def test_scope_preview_rejects_recognized_unsupported_selector(name):
    with pytest.raises(ValueError, match="SCOPE_DATA_CLASS_UNSUPPORTED"):
        build_scope_preview((Path("C:/Users/Test") / name,))


def test_scan_requires_supported_data_confirmation(qapp, tmp_path):
    window = AgentGuardianWindow()
    window._roots = (tmp_path,)
    window._refresh_scope_preview()
    window.scope_consent_checkbox.setChecked(True)
    assert window.scan_button.isEnabled() is False
    window.supported_data_checkbox.setChecked(True)
    assert window.scan_button.isEnabled() is True
```

Run: `rtk python -m pytest tests/test_workflow.py tests/test_app_smoke.py -k "unsupported_selector or supported_data_confirmation" -q -p no:cacheprovider`

Expected: `FAIL` before traversal or scanning.

- [ ] **Step 2: Add a fixed eligibility contract to scope preview**

Add `SUPPORTED_USE_BOUNDARY = "personal_non_regulated_configuration"` and exact NFKC/case-folded lexical selector rejection. Keep existing drive-root, UNC, device, reparse, path-count, selector-count, and size limits. Add `supported_use_boundary` to `ScopePreview` and its consent digest so eligibility cannot change after confirmation. NFKC compatibility forms are covered; broader cross-script homoglyph classification remains outside this bounded rule.

- [ ] **Step 3: Add concise mandatory UI confirmation**

Add one unchecked `supported_data_checkbox` immediately before the existing scope-consent checkbox:

```python
self.supported_data_checkbox = QCheckBox(
    "我确认数据符合个人非受监管配置边界"
)
self.supported_data_checkbox.setToolTip(
    "仅支持个人非受监管配置；不含医疗、金融、身份/生物识别、法律特权、客户数据集、国家秘密或同等高敏感真实数据。"
)
self.supported_data_checkbox.toggled.connect(self._supported_data_changed)
```

Require both confirmations in one shared readiness predicate used by scan, clipboard, and browser callbacks and button state. Clear both whenever roots or preview change, and read no clipboard, browser database, or file before both are valid.

- [ ] **Step 4: Record the boundary without recording content or full paths**

Add this fixed report field to JSON and HTML metadata:

```json
"supported_use_boundary": "personal_non_regulated_configuration"
```

Do not add path names, rejected selector names, or user content to the report.

- [ ] **Step 5: Regenerate source policy and run tests**

Regenerate hashes using Task 1 Step 5.

Run: `rtk python -m pytest tests/test_workflow.py tests/test_app_smoke.py tests/test_reporting.py tests/test_clipboard_audit.py -q -p no:cacheprovider`

Expected: `PASS`.

Run: `rtk python -m pytest -q -p no:cacheprovider`

Expected: `PASS`.

- [ ] **Step 6: Commit the scope boundary**

Stage only Task 5 files and commit with `rtk git commit -m "Enforce personal supported-data consent"`.

### Task 6: Build A Microsoft Store Submission Candidate Workflow

**Files:**
- Create: `.github/workflows/windows-store-candidate.yml`
- Create: `scripts/verify_wack_report.py`
- Create: `tests/test_windows_store_candidate.py`
- Modify: `scripts/build_windows_msix.py`
- Modify: `scripts/build_windows_portable.py`
- Modify: `scripts/verify_windows_release_candidate.py`
- Modify: `docs/security/windows-license-review.json`

- [ ] **Step 1: Write failing workflow contract tests**

```python
def test_store_candidate_workflow_is_manual_exact_sha_and_non_publishing():
    workflow = Path(".github/workflows/windows-store-candidate.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "expected_source_commit" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "--require-hashes" in workflow
    assert "personal_store_release" in workflow
    assert "Windows App Certification Kit" in workflow
    assert "actions/upload-artifact" in workflow
    assert "release" not in workflow.casefold()
    assert "PFX" not in workflow
    assert "MCP_ADAPTER" not in workflow
```

Run: `rtk python -m pytest tests/test_windows_store_candidate.py -q -p no:cacheprovider`

Expected: `FAIL` because the Store workflow does not exist.

- [ ] **Step 2: Add Store identity inputs without secrets or local signing**

The manual workflow accepts required `expected_source_commit`, `store_identity_name`, `store_publisher`, `store_version`, and `wack_tool_path` inputs. It rejects non-lowercase 40-character SHA, checks exact `HEAD`, requires a clean tree, and never accepts a PFX, password, timestamp URL, adapter URL, or executable path from the repository.

- [ ] **Step 3: Run all internal candidate gates**

The workflow installs `requirements-dev.lock` and `requirements-build.lock` with `--require-hashes`, then runs full pytest, personal privacy acceptance, brand validation, `compileall`, package self-audit, personal profile verification, two reproducible x64 portable builds, byte-identical ZIP comparison, Store-identity MSIX staging, SBOM/notices/provenance/checksums generation, and release-manifest validation.

- [ ] **Step 4: Add bounded WACK report validation**

Implement `verify_wack_report.py` to accept one absolute non-reparse report path under the workflow evidence directory, cap it at 16 MiB, parse XML without external entities, require a recognized WACK report root, require overall `PASS`, reject failed tests, and emit canonical JSON containing only tool version, package identity, overall result, test counts, source commit, report SHA-256, and generated UTC time.

- [ ] **Step 5: Upload candidate evidence without publishing a binary release**

Use a commit-bound artifact name and upload only MSIX upload candidate, portable checksums, SBOM, notices, provenance, release manifest, profile result, privacy result, WACK summary, and workflow run metadata. Set artifact retention to 14 days. Do not call `gh release`, GitHub Releases APIs, Partner Center APIs, or public deployment.

- [ ] **Step 6: Keep license approval fail-closed**

Extend `windows-license-review.json` with exact `source_commit`, `sbom_sha256`, `reviewed_at`, `reviewer`, and one record per shipped runtime/build component. Preserve status `pending` until an authorized human records an actual decision; workflow and release verifier must fail while it is pending or stale.

- [ ] **Step 7: Run tests and commit Store candidate infrastructure**

Run: `rtk python -m pytest tests/test_windows_store_candidate.py tests/test_windows_msix.py tests/test_windows_packaging.py tests/test_release_evidence.py -q -p no:cacheprovider`

Expected: `PASS` for local workflow contracts; actual WACK and Store evidence remain unverified.

Stage only Task 6 files and commit with `rtk git commit -m "Add Store candidate evidence workflow"`.

### Task 7: Synchronize Active Product, Privacy, Support, And Acceptance Documents

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Create: `docs/security/personal-v1-threat-model.md`
- Create: `docs/security/personal-v1-privacy.md`
- Create: `docs/security/personal-v1-support.md`
- Create: `docs/security/personal-v1-release-runbook.md`
- Create: `docs/security/personal-v1-independent-machine-acceptance.md`
- Create: `docs/security/personal-v1-release-status.json`
- Modify: `tests/test_personal_release_profile.py`

- [ ] **Step 1: Add failing active-document and status tests**

```python
def test_active_docs_describe_only_personal_supported_scope():
    verify_profile(Path.cwd(), Path("release_profiles/personal_store_release.json"))
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "high-sensitive real-data readiness" not in readme
    assert "EnterpriseControlPlane" not in readme
    assert "personal non-regulated configuration" in readme


def test_release_status_stays_no_go_until_all_eight_gates_pass():
    status = json.loads(Path("docs/security/personal-v1-release-status.json").read_text(encoding="utf-8"))
    assert status["decision"] == "NO-GO"
    assert len(status["gates"]) == 8
    assert all(gate["status"] in {"pass", "pending", "blocked"} for gate in status["gates"])
    assert status["decision"] == ("GO" if all(g["status"] == "pass" for g in status["gates"]) else "NO-GO")
```

- [ ] **Step 2: Replace stale active product claims**

Describe only personal local auditing, permanent privacy safeguards, static MCP detection, explicit share reachability, fixed remediation, Store-first distribution, Windows 11 x64 support, and unsupported data/host boundaries. Historical specs and plans remain labeled historical and are not active product promises.

- [ ] **Step 3: Publish concrete privacy and support procedures**

Document local reads, temporary browser copies, clipboard one-time read, protected state, explicit URL-only network action, report/diagnostic retention, deletion, unsupported data, support contact `yangjing6213-dev` GitHub Issues, and vulnerability reporting through GitHub private vulnerability reporting. Do not claim these channels are live until their URLs are verified.

- [ ] **Step 4: Define exact external acceptance evidence**

The independent-machine runbook requires two newly provisioned Windows 11 x64 machines, one 25H2 and one supported 24H2 or second 25H2, no development tools, Store private-audience origin, exact identity/version/signature, install, first launch, eligible scan, browser metadata audit, clipboard audit, share reachability, remediation/rollback, report comparison, crash/restart, upgrade, uninstall, and application-data residue checks. Evidence records machine ID hashes and OS/build metadata, never usernames, full paths, or user content.

- [ ] **Step 5: Add the eight-gate status ledger**

Create canonical JSON with gates `scope`, `local`, `remote`, `supply_chain`, `store`, `independent_machine`, `independent_review`, and `operations`. Every gate contains `status`, `source_commit`, `evidence_sha256`, and `verified_at`; unavailable evidence uses `null` and status `pending`. Initial decision is `NO-GO`.

- [ ] **Step 6: Verify and commit documentation convergence**

Run: `rtk python -m pytest tests/test_personal_release_profile.py -q -p no:cacheprovider`

Expected: `PASS` with active docs free of removed product promises.

Stage only Task 7 files and commit with `rtk git commit -m "Synchronize personal v1 product boundaries"`.

### Task 8: Exact-SHA Verification And External Formal Acceptance

**Files:**
- Modify only when evidence exists: `docs/security/windows-license-review.json`
- Modify only when evidence exists: `docs/security/personal-v1-release-status.json`

- [ ] **Step 1: Run the local final candidate gate on a clean tree**

Run:

```powershell
rtk git diff --check
rtk python -m compileall -q src scripts tests
rtk python scripts/check_brand_assets.py
rtk python scripts/verify_personal_release_profile.py --project-root . --profile release_profiles/personal_store_release.json
rtk python -m pytest -q -p no:cacheprovider
rtk git status --short
```

Expected: every command passes and status is empty. Record the exact `rtk git rev-parse HEAD` SHA; do not use prior-session test results for this gate.

- [ ] **Step 2: Obtain independent code and security review**

Dispatch an independent review against the exact SHA. Resolve every Critical or Important finding with a new commit and repeat Step 1. Medium/Low findings require an explicit disposition in the review evidence; unresolved Critical or Important keeps `independent_review=pending` or `blocked`.

- [ ] **Step 3: Push and verify exact-SHA GitHub checks**

Push `agent/founder-alpha`, verify normal CI, Windows development MSIX, Draft PR checks, and the manual Store-candidate workflow all point to the exact local SHA. A historical green run or a run on another SHA does not pass this gate.

- [ ] **Step 4: Complete human and external gates without simulation**

An authorized human approves the exact-SHA license/Qt record; Partner Center accepts the private-audience package; WACK evidence passes; two independent machines pass the full runbook; privacy/support/security channels are live. Store secrets, credentials, PFX data, user data, and raw evidence are never committed.

- [ ] **Step 5: Recompute the final decision**

Set a gate to `pass` only after its exact evidence digest and timestamp exist. Keep `decision=NO-GO` while any gate is not `pass`. Only when all eight gates pass may a separately authorized commit change the product version to `1.0.0` and use the phrase `formal personal release`; this plan does not authorize merge, public Store rollout, GitHub binary release, deployment, or a production-safety claim.

---

## Plan Self-Review

- Spec coverage: all seven migration items and all eight acceptance gates map to Tasks 1-8.
- Scope boundary: enterprise, optional high-sensitivity mode, and dynamic MCP execution are deleted; static MCP detection and supported personal workflows remain.
- Evidence boundary: local tests, CI, WACK, Store certification, legal review, independent machines, and independent review are recorded as distinct facts.
- YAGNI check: no enterprise replacement, sandbox replacement, cloud service, updater, telemetry, direct-download channel, or API integration is introduced.
- Release claim: version stays `0.1.0` and status stays `NO-GO` until all external evidence exists.
