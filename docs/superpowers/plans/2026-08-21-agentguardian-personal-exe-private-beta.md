# AgentGuardian Personal EXE Private Beta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify an unsigned, offline, current-user Windows EXE installer for known private testers without implying public-release or production readiness.

**Architecture:** Preserve the existing deterministic PyInstaller one-folder payload, wrap it in a fixed Inno Setup script, and bind the installer and evidence to one exact source commit. A private-beta release profile, fail-closed verifier, Windows install/upgrade/uninstall smoke test, and eight-gate status ledger replace the active Store path.

**Tech Stack:** Python 3.12, PyInstaller, PySide6, Inno Setup 7.0.2 x64, PowerShell, pytest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-21-agentguardian-personal-exe-private-beta-design.md`

## Global Constraints

- Display version is `0.2.0-beta.1`; Python version is `0.2.0b1`; Windows numeric version is `0.2.0.1`.
- Installer `AppId` is `{7A76221A-CFA0-4860-B250-7083B736F3FB}` and never changes.
- Output is `AgentGuardian-Setup-0.2.0-beta.1-x64.exe` for Windows 11 x64.
- Installation is current-user only at `{localappdata}\Programs\AgentGuardian` with no elevation override.
- Runtime install, launch, upgrade, and uninstall perform no download or automatic update.
- User-selected reports are never deleted by upgrade or uninstall.
- Inno Setup input is release `is-7_0_2`, asset `innosetup-7.0.2-x64.exe`, SHA-256 `5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1`.
- The installed `ISCC.exe` SHA-256 is `0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d`; the official binary's fixed file version is `0.0.0.0` and is not release evidence.
- The artifact remains unsigned and within a known-tester maturity scope. In a
  public repository, an Actions artifact is not an access-controlled
  distribution channel; public release and production safety remain `NO-GO`.
- Use the locked Python 3.12 environment. Put pytest basetemp outside the project tree.
- Stage explicit paths only. Do not merge, create a GitHub Release, publish a website artifact, deploy, or force-push.

---

### Task 1: Bounded Protected-State Purge Command

**Files:**
- Modify: `src/agentguardian/state_store.py`
- Modify: `src/agentguardian/app.py`
- Modify: `tests/test_state_store.py`
- Modify: `tests/test_app_smoke.py`

**Interfaces:**
- Produces: `purge_protected_state() -> bool`; returns whether the recognized state file existed.
- Produces: `run_maintenance_command(arguments: list[str]) -> int | None`; handles only `--purge-protected-state` before Qt starts.
- Errors: `StateStoreError("PROTECTED_STATE_PURGE_FAILED")`; no path is included in output.

- [ ] **Step 1: Add failing state-purge tests**

```python
def test_purge_protected_state_removes_only_known_state(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    directory = tmp_path / "AgentGuardian"
    directory.mkdir()
    state = directory / "evidence-state-v1.bin"
    state.write_bytes(b"protected")
    unrelated = directory / "keep.txt"
    unrelated.write_text("keep", encoding="ascii")

    assert purge_protected_state() is True
    assert not state.exists()
    assert unrelated.read_text(encoding="ascii") == "keep"


def test_purge_protected_state_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert purge_protected_state() is False
```

Add Windows-only junction cases using the existing junction test helper. They must assert `PROTECTED_STATE_PURGE_FAILED` and prove that the junction target is unchanged.

- [ ] **Step 2: Run the purge tests and verify RED**

Run:

```powershell
rtk python -m pytest tests/test_state_store.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task1-red
```

Expected: FAIL because `purge_protected_state` does not exist.

- [ ] **Step 3: Implement exact-path purge**

```python
def purge_protected_state() -> bool:
    target = default_state_path()
    parent = target.parent
    if not parent.exists():
        return False
    if (
        not parent.is_dir()
        or _has_reparse_ancestor(parent)
        or _is_reparse(target)
        or target.resolve(strict=False).parent != parent.resolve(strict=True)
    ):
        raise StateStoreError("PROTECTED_STATE_PURGE_FAILED")
    try:
        existed = target.exists()
        target.unlink(missing_ok=True)
        return existed
    except OSError:
        raise StateStoreError("PROTECTED_STATE_PURGE_FAILED") from None
```

Do not delete the parent directory or any other file.

- [ ] **Step 4: Add the maintenance command before QApplication creation**

```python
def run_maintenance_command(arguments: list[str]) -> int | None:
    if arguments != ["--purge-protected-state"]:
        return None
    try:
        removed = purge_protected_state()
    except StateStoreError:
        sys.stdout.write('{"error":"PROTECTED_STATE_PURGE_FAILED","status":"fail"}\n')
        return 1
    result = "removed" if removed else "absent"
    sys.stdout.write(f'{{"result":"{result}","status":"pass"}}\n')
    return 0
```

Change `main()` to call this with `sys.argv[1:]` before constructing Qt. Add app-smoke tests for removed, absent, failure, and no-QApplication execution.

- [ ] **Step 5: Run focused and full tests**

```powershell
rtk python -m pytest tests/test_state_store.py tests/test_app_smoke.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task1-focused
rtk python -m pytest -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task1-full
rtk git diff --check
```

Expected: PASS; existing documented Windows GBK/junction warnings may remain warnings only.

- [ ] **Step 6: Commit Task 1**

```powershell
rtk git add -- src/agentguardian/state_store.py src/agentguardian/app.py tests/test_state_store.py tests/test_app_smoke.py
rtk git commit -m "Add bounded private-state purge command"
```

---

### Task 2: Private-Beta Version, Profile, And Status Contract

**Files:**
- Create: `release_profiles/personal_exe_private_beta.json`
- Create: `docs/security/personal-exe-private-beta-status.json`
- Modify: `scripts/verify_personal_release_profile.py`
- Modify: `scripts/build_windows_portable.py`
- Modify: `pyproject.toml`
- Modify: `src/agentguardian/__init__.py`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security/personal-v1-threat-model.md`
- Modify: `docs/security/personal-v1-release-runbook.md`
- Modify: `docs/security/windows-license-review.json`
- Modify: `tests/test_personal_release_profile.py`
- Modify version assertions in: `tests/test_app_smoke.py`, `tests/test_evidence_state.py`, `tests/test_release_evidence.py`, `tests/test_reporting.py`, `tests/test_self_audit.py`, `tests/test_state_store.py`, `tests/test_windows_packaging.py`

**Interfaces:**
- Produces: canonical profile name `personal_exe_private_beta` with fixed installer and compiler fields.
- Produces: canonical status decisions `PRIVATE-BETA-NOT-READY` and `PRIVATE-BETA-READY`.
- Preserves: formal public release `NO-GO` and all Personal v1 unsupported-data boundaries.

- [ ] **Step 1: Add failing canonical profile and version tests**

```python
def test_private_beta_identity_is_frozen():
    profile = json.loads(PRIVATE_BETA_PROFILE_PATH.read_text(encoding="ascii"))
    assert profile["product_version"] == "0.2.0-beta.1"
    assert profile["python_package_version"] == "0.2.0b1"
    assert profile["windows_file_version"] == "0.2.0.1"
    assert profile["installer_app_id"] == "{7A76221A-CFA0-4860-B250-7083B736F3FB}"
    assert profile["installer_filename"] == "AgentGuardian-Setup-0.2.0-beta.1-x64.exe"
    assert profile["inno_setup_sha256"] == "5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1"
```

The status test derives `PRIVATE-BETA-READY` only when all eight exact gates pass and otherwise requires `PRIVATE-BETA-NOT-READY`.

- [ ] **Step 2: Run focused tests and verify RED**

```powershell
rtk python -m pytest tests/test_personal_release_profile.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task2-red
```

Expected: FAIL because the private-beta profile and ledger do not exist.

- [ ] **Step 3: Add the canonical profile and transition-aware ledger**

Add flat, strictly validated profile fields for all fixed values in the spec plus a sorted `package_input_paths` array. Reject unknown keys, duplicate keys, non-ASCII canonical JSON, unsafe path patterns, invalid versions, and a changed AppId.

Initialize all gates as `pending`, all evidence values as `null`, candidate commit as `null`, private decision as `PRIVATE-BETA-NOT-READY`, and formal decision as `NO-GO`.

- [ ] **Step 4: Converge versions and active documents**

Set `pyproject.toml` and `src/agentguardian/__init__.py` to `0.2.0b1`. Make portable metadata use display version `0.2.0-beta.1`. Replace active Store-first language with private EXE beta language while preserving the unsigned warning and unsupported-data boundary.

- [ ] **Step 5: Run profile, version, and full tests**

```powershell
rtk python scripts/verify_personal_release_profile.py --project-root . --profile release_profiles/personal_exe_private_beta.json
rtk python -m pytest tests/test_personal_release_profile.py tests/test_app_smoke.py tests/test_evidence_state.py tests/test_release_evidence.py tests/test_reporting.py tests/test_state_store.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task2-focused
rtk python -m pytest -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task2-full
rtk git diff --check
```

- [ ] **Step 6: Commit Task 2**

Stage only the files listed in Task 2 and commit:

```powershell
rtk git commit -m "Define personal EXE private beta contract"
```

---

### Task 3: Static Inno Script And Fail-Closed Builder

**Files:**
- Create: `packaging/windows/AgentGuardian.iss`
- Create: `scripts/build_windows_installer.py`
- Create: `tests/test_windows_installer.py`
- Modify: `release_profiles/personal_exe_private_beta.json`

**Interfaces:**
- Produces: `build_installer(...) -> Path` returning the exact setup EXE.
- Consumes: verified portable bundle, exact profile snapshot, absolute `ISCC.exe`, exact source commit and commit UTC.
- Rejects: reparse paths, dirty source, unexpected payload files, compiler mismatch, unsafe defines, and existing output roots.

- [ ] **Step 1: Add failing command and script-contract tests**

```python
def test_iscc_command_uses_only_fixed_defines(tmp_path):
    command = build_iscc_command(
        iscc=tmp_path / "ISCC.exe",
        script=ROOT / "packaging/windows/AgentGuardian.iss",
        bundle_root=tmp_path / "bundle",
        output_root=tmp_path / "output",
        source_commit="a" * 40,
        built_at="2026-08-21T00:00:00Z",
    )
    assert command[0].endswith("ISCC.exe")
    assert all("http" not in item.casefold() for item in command)
    assert not any("password" in item.casefold() for item in command)
```

Contract tests require `PrivilegesRequired=lowest`, the fixed `AppId`, fixed install directory, x64 restriction, start-menu shortcut, opt-in desktop shortcut, and no download, service, task, startup, all-users, or signing directive.

- [ ] **Step 2: Run the new tests and verify RED**

```powershell
rtk python -m pytest tests/test_windows_installer.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task3-red
```

- [ ] **Step 3: Implement the minimal static Inno script**

```ini
[Setup]
AppId={{7A76221A-CFA0-4860-B250-7083B736F3FB}
AppName=AgentGuardian
AppVersion={#DisplayVersion}
VersionInfoVersion={#FileVersion}
DefaultDirName={localappdata}\Programs\AgentGuardian
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
Uninstallable=yes
OutputBaseFilename=AgentGuardian-Setup-{#DisplayVersion}-x64
```

Use compile-time defines only for validated bundle/output paths, versions,
source commit, and commit time. Use no `[Run]` download or external source.

- [ ] **Step 4: Implement builder validation and compiler invocation**

The builder verifies the release profile, bundle manifest, clean exact Git SHA,
absolute non-reparse paths, compiler file version `7.0.2`, and output filename.
It invokes `ISCC.exe` without a shell and rechecks the Git tree and profile
snapshot after compilation.

- [ ] **Step 5: Run focused tests**

```powershell
rtk python -m pytest tests/test_windows_installer.py tests/test_windows_packaging.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task3-focused
rtk git diff --check
```

- [ ] **Step 6: Commit Task 3**

```powershell
rtk git add -- packaging/windows/AgentGuardian.iss scripts/build_windows_installer.py tests/test_windows_installer.py release_profiles/personal_exe_private_beta.json
rtk git commit -m "Build offline current-user EXE installer"
```

---

### Task 4: Bounded Installer Evidence And Delivery Verifier

**Files:**
- Create: `scripts/verify_windows_installer_candidate.py`
- Create: `tests/test_windows_installer_evidence.py`
- Modify: `scripts/build_windows_installer.py`
- Modify: `release_profiles/personal_exe_private_beta.json`

**Interfaces:**
- Produces: canonical `PRIVATE-BETA-MANIFEST.json`, `BUILD-METADATA.json`, and `SHA256SUMS`.
- Produces: `verify_candidate(evidence_root, expected_commit, profile_snapshot) -> dict[str, str]`.
- Upload allowlist: the eight exact artifacts named in the design spec.

- [ ] **Step 1: Add failing evidence-chain tests**

```python
def test_private_beta_manifest_binds_installer_to_payload_and_commit(candidate):
    result = verify_candidate(
        candidate.root,
        expected_commit="a" * 40,
        profile_snapshot=candidate.profile,
    )
    assert result == {"channel": "personal_exe_private_beta", "status": "pass"}
```

Add mutations for installer bytes, payload digest, source commit, version,
compiler digest, duplicate JSON keys, extra files, missing files, oversized
files, reparse points, absolute paths, and noncanonical JSON.

- [ ] **Step 2: Run evidence tests and verify RED**

```powershell
rtk python -m pytest tests/test_windows_installer_evidence.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task4-red
```

- [ ] **Step 3: Implement canonical evidence creation and verification**

Use bounded binary reads, `json.loads(..., object_pairs_hook=...)`, canonical
ASCII JSON, SHA-256 streaming, exact filename allowlists, non-reparse traversal,
and fixed public error codes. Never emit local paths or usernames.

- [ ] **Step 4: Run focused and full evidence tests**

```powershell
rtk python -m pytest tests/test_windows_installer.py tests/test_windows_installer_evidence.py tests/test_windows_packaging.py tests/test_release_evidence.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task4-focused
rtk git diff --check
```

- [ ] **Step 5: Commit Task 4**

```powershell
rtk git add -- scripts/build_windows_installer.py scripts/verify_windows_installer_candidate.py tests/test_windows_installer_evidence.py release_profiles/personal_exe_private_beta.json
rtk git commit -m "Bind private installer evidence to exact source"
```

---

### Task 5: Install, Upgrade, And Uninstall Acceptance

**Files:**
- Create: `scripts/verify_windows_installer.ps1`
- Modify: `packaging/windows/AgentGuardian.iss`
- Modify: `tests/test_windows_installer.py`
- Create: `tests/test_windows_installer_acceptance.py`

**Interfaces:**
- Consumes: base test installer, exact candidate installer, fixed `AppId`, expected versions, and an evidence output path.
- Produces: canonical machine-neutral acceptance JSON.
- Exit status: nonzero for any install, launch, upgrade, cleanup, uninstall, or residue failure.

- [ ] **Step 1: Add failing PowerShell contract tests**

```python
def test_acceptance_script_covers_both_state_choices():
    script = (ROOT / "scripts/verify_windows_installer.ps1").read_text("utf-8")
    assert "--purge-protected-state" in script
    assert "retained_state" in script
    assert "deleted_state" in script
    assert "user_report_preserved" in script
    assert "Start-Process" in script
    assert "Get-ChildItem" in script
```

Require silent current-user install, start-menu registration, launch smoke,
base-to-candidate upgrade, downgrade rejection, uninstall registry removal,
program-directory removal, and no AgentGuardian service/task/startup entry.

- [ ] **Step 2: Run contract tests and verify RED**

```powershell
rtk python -m pytest tests/test_windows_installer.py tests/test_windows_installer_acceptance.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task5-red
```

- [ ] **Step 3: Implement the acceptance script and uninstall choice**

Use only literal paths derived from `$env:LOCALAPPDATA`, exact registry keys,
and fixed process names. Invoke Setup and Uninstall with silent, no-restart,
current-user arguments. Invoke the bounded purge command only for the delete
case. Never recursively remove a computed directory in PowerShell.

- [ ] **Step 4: Run contract tests locally**

```powershell
rtk python -m pytest tests/test_windows_installer.py tests/test_windows_installer_acceptance.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task5-focused
rtk git diff --check
```

The native install sequence runs in Task 6 on a clean Windows runner.

- [ ] **Step 5: Commit Task 5**

```powershell
rtk git add -- packaging/windows/AgentGuardian.iss scripts/verify_windows_installer.ps1 tests/test_windows_installer.py tests/test_windows_installer_acceptance.py
rtk git commit -m "Verify private installer lifecycle"
```

---

### Task 6: Exact-SHA Windows EXE Workflow

**Files:**
- Create: `.github/workflows/windows-exe-private-beta.yml`
- Modify: `tests/test_windows_installer.py`
- Modify: `tests/test_personal_release_profile.py`

**Interfaces:**
- Manual input: exact lowercase 40-character candidate SHA.
- Produces: short-retention `agentguardian-personal-exe-private-beta-<SHA>` Actions artifact.
- Does not publish: no release, tag, website, deployment, Partner Center, or signing API.

- [ ] **Step 1: Add failing workflow contract tests**

```python
def test_exe_workflow_pins_inno_and_never_publishes():
    workflow = (ROOT / ".github/workflows/windows-exe-private-beta.yml").read_text("utf-8")
    assert "is-7_0_2" in workflow
    assert "5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1" in workflow
    assert "gh release verify-asset" in workflow
    assert "verify_windows_installer.ps1" in workflow
    assert "actions/upload-artifact" in workflow
    assert "gh release create" not in workflow.casefold()
    assert "deploy" not in workflow.casefold()
```

- [ ] **Step 2: Run workflow tests and verify RED**

```powershell
rtk python -m pytest tests/test_windows_installer.py tests/test_personal_release_profile.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task6-red
```

- [ ] **Step 3: Implement the exact-SHA workflow**

The workflow checks out the requested SHA, verifies a clean tree, installs
hash-locked Python dependencies, runs all internal gates, downloads the exact
Inno asset, verifies SHA-256 plus upstream release attestation and Authenticode,
builds the deterministic portable payload, builds a synthetic lower base
installer and the exact candidate, runs lifecycle acceptance, verifies the
bounded evidence allowlist, and uploads only the eight approved files for 14
days.

- [ ] **Step 4: Run focused and full local tests**

```powershell
rtk python -m pytest tests/test_windows_installer.py tests/test_windows_installer_acceptance.py tests/test_windows_installer_evidence.py tests/test_personal_release_profile.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task6-focused
rtk python -m pytest -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task6-full
rtk git diff --check
```

- [ ] **Step 5: Commit Task 6**

```powershell
rtk git add -- .github/workflows/windows-exe-private-beta.yml tests/test_windows_installer.py tests/test_personal_release_profile.py
rtk git commit -m "Add exact-SHA EXE private beta workflow"
```

---

### Task 7: Retire The Active Store Path And Converge Documentation

**Files:**
- Delete: `.github/workflows/windows-mvp.yml`
- Delete: `.github/workflows/windows-store-candidate.yml`
- Delete: `scripts/build_windows_msix.py`
- Delete: `scripts/verify_windows_msix.ps1`
- Delete: `scripts/verify_wack_report.py`
- Delete: `scripts/verify_windows_release_candidate.py`
- Delete: `scripts/verify_windows_store_candidate.py`
- Delete: `tests/test_release_evidence.py`
- Delete: `tests/test_windows_msix.py`
- Delete: `tests/test_windows_store_candidate.py`
- Delete: `tests/fixtures/wack/windows-app-certification-kit-10.0.26100.7705.xml`
- Delete: `release_profiles/personal_store_release.json`
- Delete: `docs/security/personal-v1-release-status.json`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security/personal-v1-privacy.md`
- Modify: `docs/security/personal-v1-support.md`
- Modify: `docs/security/personal-v1-release-runbook.md`
- Modify: `docs/security/personal-v1-independent-machine-acceptance.md`
- Modify: `docs/security/personal-v1-threat-model.md`
- Modify: `docs/security/windows-mvp-threat-model.md`
- Modify: `docs/security/windows-release-evidence.md`
- Modify: `docs/reports/windows-mvp-release-candidate-report.md`
- Modify: `tests/test_personal_release_profile.py`

**Interfaces:**
- Governing route: `personal_exe_private_beta` only.
- Historical Store reports/specs/plans remain tracked and explicitly non-governing.

- [ ] **Step 1: Add failing active-surface tests**

```python
def test_active_tree_has_only_exe_private_beta_delivery():
    assert not (ROOT / ".github/workflows/windows-store-candidate.yml").exists()
    assert not (ROOT / ".github/workflows/windows-mvp.yml").exists()
    assert not (ROOT / "release_profiles/personal_store_release.json").exists()
    assert (ROOT / ".github/workflows/windows-exe-private-beta.yml").is_file()
    assert (ROOT / "release_profiles/personal_exe_private_beta.json").is_file()
```

Require all active docs to say unsigned private beta, known testers,
`PRIVATE-BETA-NOT-READY` or `PRIVATE-BETA-READY`, and formal public `NO-GO`.

- [ ] **Step 2: Run active-surface tests and verify RED**

```powershell
rtk python -m pytest tests/test_personal_release_profile.py -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task7-red
```

- [ ] **Step 3: Remove Store-only active code and update documents**

Delete only the listed active files after EXE equivalents pass. Preserve Git
history and historical reports/specs/plans. Update source-policy/profile
allowlists and all active links. Do not describe deletion as evidence that the
private beta is ready.

- [ ] **Step 4: Run all local gates**

```powershell
rtk python scripts/check_brand_assets.py
rtk python -m compileall -q src scripts tests
rtk python scripts/verify_personal_release_profile.py --project-root . --profile release_profiles/personal_exe_private_beta.json
rtk python -m pytest -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task7-full
rtk git diff --check
```

- [ ] **Step 5: Commit Task 7**

Stage the exact Task 7 manifest and commit:

```powershell
rtk git commit -m "Replace active Store delivery with EXE private beta"
```

---

### Task 8: Freeze Candidate And Complete Evidence Gates

**Files:**
- Modify only when exact evidence exists: `docs/security/personal-exe-private-beta-status.json`
- Modify only for factual convergence: active private-beta documents

**Interfaces:**
- Candidate SHA: exact clean commit `S` containing every package input.
- Later ledger commits may reference `S` but do not change its package inputs.
- Final private decision: `PRIVATE-BETA-READY` only after all eight gates pass.

- [ ] **Step 1: Run the clean local candidate gate**

```powershell
rtk git diff --check
rtk python -m compileall -q src scripts tests
rtk python scripts/check_brand_assets.py
rtk python scripts/verify_personal_release_profile.py --project-root . --profile release_profiles/personal_exe_private_beta.json
rtk python -m pytest -q -p no:cacheprovider --basetemp=../.pytest-tmp/exe-beta-task8-full
rtk git status --short
rtk git rev-parse HEAD
```

Expected: all commands pass and status is empty. Record this SHA as `S`.

- [ ] **Step 2: Obtain independent review for exact SHA `S`**

Review source, installer script, compiler provisioning, state purge, PowerShell
acceptance, evidence verifier, profile, and workflow. Resolve every Critical or
Important finding in a new candidate and repeat Step 1. Record dispositions for
all other findings.

- [ ] **Step 3: Push normally and verify exact-SHA remote checks**

```powershell
rtk git push origin agent/founder-alpha
rtk git ls-remote origin refs/heads/agent/founder-alpha
rtk gh pr checks 1 --repo yangjing6213-dev/AgentGuardian --watch --interval 10
```

The candidate-branch `push` trigger runs the EXE workflow for exact SHA `S`
without requiring a merge. The manual trigger may be used only after the
workflow exists on the default branch, and only for exact SHA `S`. Historical
green runs and another SHA do not pass the remote or installer gate. The
short-retention artifact in this public repository is CI evidence, not an
access-controlled distribution channel.

- [ ] **Step 4: Complete two-machine private acceptance**

Use two newly provisioned Windows 11 x64 machines without development tools.
Run the complete install, warning disclosure, launch, supported workflows,
manual upgrade, downgrade rejection, retained-state uninstall, deleted-state
uninstall, report preservation, and residue procedure. Record only bounded,
machine-neutral evidence and its SHA-256.

- [ ] **Step 5: Recompute the private-beta decision**

Set a gate to `pass` only when exact-SHA evidence, digest, and UTC time exist.
Keep `PRIVATE-BETA-NOT-READY` while any gate is not `pass`. A ledger-only commit
may set `PRIVATE-BETA-READY` for `S` after all eight gates pass. Formal public
release remains `NO-GO`; no merge, public asset, deployment, or production claim
is authorized.

---

## Plan Self-Review

- Spec coverage: installer architecture, immutable identity, version mapping,
  current-user install, no-network contract, state purge, manual upgrade,
  uninstall, evidence, eight gates, Store retirement, and publication boundary
  each map to one or more tasks.
- Type consistency: Task 1 produces the purge command consumed by Task 5; Task 2
  produces the profile consumed by Tasks 3, 4, 6, 7, and 8; Task 3 produces the
  installer consumed by Tasks 4 through 8; Task 4 produces the verifier used by
  the workflow and final gates.
- YAGNI: no updater, downloader, signer, service, driver, public website,
  publishing automation, second installer format, or enterprise feature is
  introduced.
- Evidence boundary: private-beta readiness, formal public release, and
  production safety remain separate decisions.
