# AgentGuardian GitHub Release Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Make the public repository deliver one verifiable Windows 11 x64 installer download that contains the current GUI, local STDIO MCP launcher, and Skill payload, while preserving the unsigned Public Preview boundary.

**Architecture:** Keep the existing local audit core, GUI, MCP server, Skill, and Inno Setup package unchanged in responsibility. Add a profile-backed Release asset contract and a local staging/verification tool that copies the already-built installer, portable ZIP, Skill ZIP, license, and notices into an explicit allowlist, creates canonical metadata and checksums, and hands that directory to a manual GitHub Release operator. Keep the candidate Actions workflow read-only; public publication and fixed-link verification remain separate, authorized steps.

**Tech Stack:** Python 3.12, existing pytest suite, PySide6, MCP Python SDK 2.0.0, PyInstaller 6.16, Inno Setup 7.0.2, PowerShell, GitHub Actions, canonical ASCII JSON, SHA-256.

---

## Execution Boundary

- Work only in C:/Users/HU/Documents/AI智能体数据安全审计/.worktrees/founder-alpha on codex/0.3-integrations-preview.
- Preserve main and the existing preview architecture. Do not redo the audit core, MCP authorization model, or Skill workflow.
- Do not create a Tag or Release, upload a Release asset, modify a remote branch, or push while executing this plan. Publication is a separate authorization step after all evidence is reviewed.
- Keep the candidate workflow at permissions: contents: read; it produces a temporary handoff artifact only.
- Stage only named paths. Never use git add . or git add -A.
- Do not lower assertions, suppress lint/type findings, turn a failed gate into a pass, or add a fallback Provider API.
- The first public channel remains 0.3.0-preview.1, unsigned_public_preview, Windows 11 x64, personal non-regulated data only.

## Baseline Evidence And Known State

- Baseline source commit: 1add24fd91a7bc060018903c6620235b45bef8f1.
- Current local HEAD after the approved specification commit: e3e450c.
- Existing baseline evidence observed before this plan: GitHub CI run 32924311288 succeeded with 1999 passed, 2 skipped; Windows integrations run 32924311365 succeeded.
- Existing Actions artifact agentguardian-downloadable-preview-1add24fd91a7bc060018903c6620235b45bef8f1 is temporary evidence, not a long-term user download.
- Current source tree has no committed .exe, .zip, .msix, or .appinstaller binary.
- Current installer builder emits AgentGuardian-Setup-0.3.0-preview.1-x64.exe; current portable builder emits a SHA-suffixed ZIP; current workflow manually assembles a temporary artifact and has no Release upload job.
- Current README and active status document still say INTEGRATIONS-PREVIEW-NOT-READY and NO-GO. The plan must preserve those maturity states until fresh release gates are evidenced.

## File Map

### Release contract and staging

- Modify release_profiles/integrations_preview.json: add the fixed Release identity, asset allowlist, filenames, status, and latest/download URL; bump the profile schema to 2.
- Modify scripts/verify_integrations_preview_profile.py: validate the new Release contract and its types with fixed failure codes.
- Create scripts/stage_public_preview_release.py: copy final build inputs, create the stable installer alias, emit canonical DOWNLOAD-METADATA.json and SHA256SUMS, and verify the exact staged set.
- Create tests/test_public_preview_release.py: test staging, byte identity, metadata, checksum coverage, tamper rejection, and path/secret exclusion.

### Existing package surfaces

- Modify scripts/build_windows_portable.py: use the profile's canonical portable asset name for the integrations preview while preserving the private-beta SHA-suffixed default.
- Modify packaging/windows/AgentGuardianIntegrationsPreview.iss: show the unsigned Public Preview and personal non-regulated boundary in the pre-install summary.
- Modify scripts/build_windows_integrations_preview_installer.py: require the new installer disclosure text and refresh the approved script digest.
- Modify tests/test_windows_packaging.py and tests/test_windows_integrations_preview_installer.py: cover canonical naming and installer disclosure.

### Documentation and candidate workflow

- Modify README.md: add the fixed primary download link, release asset list, unsigned warning, and an explicit pre-release availability statement.
- Modify docs/security/integrations-preview.md: add the manual Release handoff and public-link verification runbook without changing the NO-GO boundary.
- Modify .github/workflows/windows-integrations-preview.yml: call the staging tool and upload only the explicit temporary handoff directory; retain read-only permissions and no Release write.
- Modify tests/test_integrations_preview_workflow.py: assert the workflow is still non-publishing and uses the staging contract.
- Modify tests/test_integrations_preview_profile.py: cover the new profile identity and Release rules.

### Public-link verification

- Create scripts/verify_public_preview_download.ps1: verify the fixed unauthenticated primary URL against a supplied SHA-256 using one bounded curl.exe request, with no API token and no retry loop.
- Extend tests/test_public_preview_release.py: statically verify the URL, bounded request flags, and absence of credentials or alternate-owner fallbacks.

### Local-only evidence

- Keep post-build reports under .local-audit/; do not add them to Git.
- No source report, cache, test export, credential, or local user data is part of the Release asset allowlist.


## Task 1: Freeze the profile-backed Release contract

**Files**

- Modify release_profiles/integrations_preview.json.
- Modify scripts/verify_integrations_preview_profile.py in the profile key, identity, array, and validation sections.
- Modify tests/test_integrations_preview_profile.py.
- Modify tests/test_integrations_preview_workflow.py.

**Steps**

- [ ] Add failing profile tests for the exact public contract. The tests must require schema 2, release_artifact_status equal to unsigned_public_preview, release_tag equal to v0.3.0-preview.1, release_title equal to AgentGuardian 0.3.0 Public Preview (Unsigned), release_draft false, release_prerelease false, primary_download_filename equal to AgentGuardian-Setup-Windows-x64.exe, portable_filename equal to AgentGuardian-0.3.0-preview.1-windows-x64.zip, and release_download_url equal to https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe.
- [ ] Require release_assets to be the exact sorted eight-name list:
  - AgentGuardian-0.3.0-preview.1-windows-x64.zip
  - AgentGuardian-Setup-0.3.0-preview.1-x64.exe
  - AgentGuardian-Setup-Windows-x64.exe
  - AgentGuardian-Skill-0.2.0.zip
  - DOWNLOAD-METADATA.json
  - LICENSE
  - SHA256SUMS
  - THIRD_PARTY_NOTICES.md
- [ ] Add parametrized negative tests that mutate each release field and assert the stable failure code PROFILE_RELEASE_CONTRACT_INVALID. Add type tests for booleans, filenames, URL, tag, title, and the asset list.
- [ ] Run the focused tests before implementation:
  ~~~
  python -m pytest -q -p no:cacheprovider tests/test_integrations_preview_profile.py tests/test_integrations_preview_workflow.py
  ~~~
  Expected result: FAIL because the profile has schema 1 and no release contract fields.
- [ ] Add the fields to the canonical profile JSON. Keep the existing internal artifact_status value unsigned_development_only for the build bundle; release_artifact_status is the distinct external handoff state unsigned_public_preview. Do not add paths for scripts that do not yet exist. Tasks 2 and 6 add those paths in the same change that creates each script.
- [ ] Extend the verifier's exact key set and identity map, add release_assets to the sorted string-array validation, validate the new scalar types and safe basenames, enforce the fixed URL and exact asset list, and reject any draft or prerelease value other than false. Use PROFILE_RELEASE_CONTRACT_INVALID for all release-contract drift so callers do not receive path or secret contents in an error.
- [ ] Update profile tests for canonical ASCII JSON, the new schema, the release fields, and the existing rejection cases. Update the workflow test fixtures so they read the new profile contract instead of duplicating filenames.
- [ ] Run the focused tests again and require PASS.
- [ ] Stage only release_profiles/integrations_preview.json, scripts/verify_integrations_preview_profile.py, tests/test_integrations_preview_profile.py, and tests/test_integrations_preview_workflow.py. Run git diff --cached --check, then commit:
  ~~~
  git add -- release_profiles/integrations_preview.json scripts/verify_integrations_preview_profile.py tests/test_integrations_preview_profile.py tests/test_integrations_preview_workflow.py
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "chore(release): freeze public preview asset contract"
  ~~~

**Expected result**

The repository has one machine-verifiable source of truth for the public preview tag, title, flags, fixed download URL, asset names, and unsigned boundary. Existing runtime and private-beta profile behavior is unchanged.

## Task 2: Build an explicit public Release staging tool

**Files**

- Create scripts/stage_public_preview_release.py.
- Create tests/test_public_preview_release.py.
- Modify release_profiles/integrations_preview.json after the new script exists to include it in package_input_paths and required_source_paths as appropriate.

**Public API and constants**

- Define an immutable RELEASE_ASSET_NAMES tuple containing exactly the eight profile asset names.
- Define PRIMARY_INSTALLER_NAME, VERSIONED_INSTALLER_NAME, PORTABLE_NAME, and SKILL_NAME from the profile contract or verified constants.
- Set MAX_INPUT_BYTES to 2 GiB and use bounded reads for text and marker checks.
- Expose:
  ~~~
  def stage_public_preview_release(
      project_root: str | Path,
      output_root: str | Path,
      *,
      installer_path: str | Path,
      portable_path: str | Path,
      skill_path: str | Path,
      source_commit: str,
      built_at: str,
  ) -> dict[str, object]

  def verify_staged_release(
      output_root: str | Path,
      project_root: str | Path,
      *,
      source_commit: str,
  ) -> dict[str, object]
  ~~~
- Keep the Git state reader in a small named helper so tests can replace it with a clean, exact-SHA state without depending on the developer worktree.

**Steps**

- [ ] Add failing tests using a temporary output directory and bounded fake installer, portable, and Skill files. Replace the Git state helper in the tests with the current expected 40-character source SHA and an empty status result; do not make unit tests depend on an accidentally dirty checkout.
- [ ] Require the successful stage result to contain exactly the eight allowlisted files. Require the versioned installer and stable primary installer alias to be byte-identical, and require the metadata to report the two names separately.
- [ ] Require DOWNLOAD-METADATA.json to have exactly these top-level keys: architecture, artifact_status, channel, files, installer, release, schema, source_commit, supported_platform, version. Define schema 1 for this metadata, artifact_status unsigned_public_preview, architecture x64, supported_platform Windows 11 x64, channel integrations_preview, and the exact source commit and product version.
- [ ] Define installer metadata with primary_filename, versioned_filename, and built_at. Validate built_at as the supplied UTC commit timestamp. Define release metadata with tag, title, draft, prerelease, and fixed_download_url. Define files as six records for the two installer names, portable ZIP, Skill ZIP, LICENSE, and THIRD_PARTY_NOTICES.md; each record contains name, sha256, and size. Exclude metadata and SHA256SUMS from the files array to avoid circular metadata.
- [ ] Enforce the nested key sets exactly: installer has primary_filename, versioned_filename, and built_at; release has tag, title, draft, prerelease, and fixed_download_url; every files record has only name, sha256, and size. Reject unknown nested keys with RELEASE_MANIFEST_INVALID.
- [ ] Require SHA256SUMS to use sorted POSIX checksum lines for every staged file except SHA256SUMS itself, including DOWNLOAD-METADATA.json. Require the verifier to recompute all listed hashes, reject missing or extra lines, and never claim that the checksum file verifies its own hash.
- [ ] Add red tests for a changed stable alias, a missing asset, an extra asset, a tampered metadata file, a checksum mismatch, an input path that is relative, an input that is a directory, a symlink or reparse-point input, an output nested inside the project, and an output directory that already contains files. Each test must assert a fixed code such as RELEASE_ASSET_DIGEST_MISMATCH, RELEASE_INPUT_PATH_INVALID, RELEASE_OUTPUT_PATH_INVALID, or RELEASE_MANIFEST_INVALID.
- [ ] Add a red test that supplies a path component or bounded text/binary marker matching a credential/private-key signature and assert RELEASE_PRIVATE_DATA_DETECTED. The failure response must contain only the fixed code and a short remediation sentence; it must not echo the path, marker, or matched bytes.
- [ ] Run the new test module before implementation:
  ~~~
  python -m pytest -q -p no:cacheprovider tests/test_public_preview_release.py
  ~~~
  Expected result: FAIL because the staging module does not exist.
- [ ] Implement the staged-copy boundary. Resolve every input and output path, require a regular local file without a reparse component, enforce the size bound, require an exact lowercase source SHA, compare it with HEAD and a clean porcelain status, and reject output paths inside the project or inside any input directory.
- [ ] Copy only the named source artifacts into a new output directory. Copy the versioned installer under its versioned name, create the primary alias from the copied bytes, copy the canonical portable and Skill names, and copy LICENSE and THIRD_PARTY_NOTICES.md. Do not copy reports, source trees, caches, logs, credentials, or arbitrary files from a build directory.
- [ ] Scan path components and bounded textual content for the existing repository credential/private-key signatures. Scan binary payloads only for the fixed high-confidence signatures already used by the release gate. Raise fixed errors without returning matches or private paths.
- [ ] Write canonical ASCII metadata with stable key and list ordering, then write SHA256SUMS after metadata. Verify the final directory against the exact allowlist, alias byte identity, metadata schema, sizes, hashes, source SHA, and profile release contract.
- [ ] Add a CLI with required project-root, output-root, installer, portable, Skill, source-commit, and built-at arguments. Emit one compact JSON result on success and one fixed JSON error on failure; never print file contents or secret matches.
- [ ] Run the new tests and the profile/workflow focused tests. Require PASS.
- [ ] Add the new staging script to the profile's package and required source path lists, rerun the profile verifier, and stage only the profile, staging script, and new test file. Run git diff --cached --check, then commit:
  ~~~
  git add -- release_profiles/integrations_preview.json scripts/stage_public_preview_release.py tests/test_public_preview_release.py
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "feat(release): stage public preview assets safely"
  ~~~

**Expected result**

A build operator can produce a clean, exact eight-file handoff directory from already-verified build outputs without allowing arbitrary repository content, private data, or circular checksum claims into the public asset set.

## Task 3: Make the portable ZIP name canonical

**Files**

- Modify scripts/build_windows_portable.py in the integrations-preview build branch.
- Modify tests/test_windows_packaging.py and tests/test_integrations_preview_profile.py.
- Modify .github/workflows/windows-integrations-preview.yml only where it selects the portable output.

**Steps**

- [ ] Add a failing test that loads the integrations-preview profile, exercises the preview builder with deterministic test doubles, and asserts that the emitted ZIP basename equals profile portable_filename. Add a separate assertion that the private-beta builder still retains its existing source-SHA suffix.
- [ ] Run the focused packaging tests and expect the new canonical-name assertion to FAIL against the current SHA-suffixed preview output.
- [ ] In the integrations-preview branch, validate profile portable_filename as a basename ending in .zip and pass it to the deterministic ZIP writer. Preserve the private-beta naming and internal artifact status exactly as they are.
- [ ] Replace the workflow wildcard selection with an exact lookup of AgentGuardian-0.3.0-preview.1-windows-x64.zip and fail when the count is not one. Keep the deterministic two-build hash comparison.
- [ ] Run:
  ~~~
  python -m pytest -q -p no:cacheprovider tests/test_windows_packaging.py tests/test_integrations_preview_profile.py tests/test_integrations_preview_workflow.py
  ~~~
  Require PASS.
- [ ] Stage only the portable builder, the two test files, and the workflow. Run git diff --cached --check, then commit:
  ~~~
  git add -- scripts/build_windows_portable.py tests/test_windows_packaging.py tests/test_integrations_preview_profile.py .github/workflows/windows-integrations-preview.yml
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "build(windows): use canonical preview asset name"
  ~~~

**Expected result**

The portable build output has one stable, profile-defined filename suitable for a fixed Release asset list, while the older private-beta distribution remains compatible.


## Task 4: Put the unsigned preview boundary in the installer UI

**Files**

- Modify packaging/windows/AgentGuardianIntegrationsPreview.iss in the SelectedTargets summary.
- Modify scripts/build_windows_integrations_preview_installer.py in its approved-script markers and digest.
- Modify tests/test_windows_integrations_preview_installer.py.
- Modify tests/test_integrations_preview_profile.py only if a profile disclosure marker is asserted there.

**Steps**

- [ ] Add a failing static installer test that requires case-insensitive occurrences of Public Preview, unsigned, personal non-regulated, Unknown Publisher, SmartScreen, and redacted in the pre-install summary source. Require the existing opt-in tasks, current-user install path, no-elevation setting, and uninstall hooks to remain present.
- [ ] Run the focused installer tests and expect the new disclosure assertion to FAIL.
- [ ] Prepend this exact information to the SelectedTargets result while preserving the selected-category details:
  ~~~
  AgentGuardian 0.3.0 Public Preview (unsigned).
  Use only personal non-regulated configuration data.
  Windows may show Unknown Publisher or SmartScreen warnings.
  Reports and redacted results may be visible to the configured host.
  ~~~
  Keep the existing task defaults unchecked and do not add network download, elevation, service, startup, updater, or automatic repair behavior.
- [ ] Add the disclosure markers to the installer builder's static contract checks. Recompute the approved Inno script SHA-256 using the repository's existing byte-level digest routine after the source edit, update only the canonical profile/builder digest values, and leave generated installers out of Git.
- [ ] Run the installer tests and the profile verifier. Require PASS and confirm the digest check reads the exact checked-in script bytes.
- [ ] Stage only packaging/windows/AgentGuardianIntegrationsPreview.iss, scripts/build_windows_integrations_preview_installer.py, tests/test_windows_integrations_preview_installer.py, and any directly required profile test. Run git diff --cached --check, then commit:
  ~~~
  git add -- packaging/windows/AgentGuardianIntegrationsPreview.iss scripts/build_windows_integrations_preview_installer.py tests/test_windows_integrations_preview_installer.py tests/test_integrations_preview_profile.py
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "docs(windows): disclose unsigned preview boundary"
  ~~~

**Expected result**

A user sees the unsigned Public Preview and personal-data boundary before selecting installation tasks, while the installer remains a current-user offline package with explicit opt-in host integration.


## Task 5: Publish the download route and operating boundary in active documentation

**Files**

- Modify README.md.
- Modify docs/security/integrations-preview.md.
- Modify tests/test_integrations_preview_workflow.py.
- Extend tests/test_public_preview_release.py.

**Steps**

- [ ] Add failing documentation-contract tests requiring the exact fixed URL in README.md and docs/security/integrations-preview.md, the phrases unsigned Public Preview and personal non-regulated, a high-sensitivity-data prohibition, a production-safety prohibition, the installer filename, and the eight-name asset list. Reject temporary Actions artifact URLs in README.md.
- [ ] Run the documentation tests and expect the new fixed-link assertions to FAIL.
- [ ] Add a concise README download section with the primary fixed link:
  ~~~
  https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe
  ~~~
  State that the link resolves only after the manually authorized public Release is published, that the first channel is AgentGuardian 0.3.0 Public Preview (unsigned), and that Windows can show Unknown Publisher or SmartScreen warnings.
- [ ] Explain that the installer contains the current GUI executable, AgentGuardianMcp.exe for local STDIO MCP, and the independent AgentGuardian Skill payload. State that Codex/other hosts still require explicit opt-in configuration, and that the installer does not silently download or enable a Provider API.
- [ ] List the exact eight Release assets and tell users to verify SHA256SUMS. State Windows 11 x64, personal non-regulated use only, no high-sensitivity real data, no production-safety claim, and no enterprise-control-plane guarantee. Keep the existing INTEGRATIONS-PREVIEW-NOT-READY and NO-GO status until fresh gates are recorded; retain historical test results as historical evidence rather than current verification.
- [ ] Add a Public Release handoff section to docs/security/integrations-preview.md. It must describe: run the read-only Windows workflow for the exact source SHA; stage the exact eight files locally; review DOWNLOAD-METADATA.json and SHA256SUMS; create a published, non-draft, non-prerelease Release with tag v0.3.0-preview.1 and title AgentGuardian 0.3.0 Public Preview (Unsigned); upload only the allowlisted files; verify the fixed unauthenticated link; and write a local-only post-publish report.
- [ ] Document that GitHub API or credential outages, including HTTP 503, do not justify alternate owners, alternate accounts, force pushes, token disclosure, or bypassing repository protection. The operator waits, retries only through the normal authorized GitHub path outside the candidate workflow, or performs the manually authorized browser/API Release step after the source and files are revalidated.
- [ ] Run the documentation, workflow, profile, and staging tests. Require PASS without changing the status document to a passing maturity state.
- [ ] Stage only README.md, docs/security/integrations-preview.md, tests/test_integrations_preview_workflow.py, and tests/test_public_preview_release.py. Run git diff --cached --check, then commit:
  ~~~
  git add -- README.md docs/security/integrations-preview.md tests/test_integrations_preview_workflow.py tests/test_public_preview_release.py
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "docs(release): add public preview download route"
  ~~~

**Expected result**

A repository visitor can find one stable primary download path and understand exactly what the installer contains, which data is permitted, how to verify the files, and why the preview is not a production-security claim.



## Task 6: Add a bounded fixed-link verifier

**Files**

- Create scripts/verify_public_preview_download.ps1.
- Extend tests/test_public_preview_release.py.

**Steps**

- [ ] Add a failing static test that requires the exact fixed URL, curl.exe, --fail, --location, --max-time, --proto '=https', and --tlsv1.2. Require that the script has no GitHub token, Authorization header, alternate-owner URL, retry loop, or API endpoint.
- [ ] Run the new static test and expect it to FAIL because the verifier script does not exist.
- [ ] Create a one-request PowerShell verifier with a mandatory ExpectedSha256 parameter validated as exactly 64 lowercase hexadecimal characters. Use StrictMode and a unique temporary EXE path. Perform one bounded curl.exe request to the fixed URL, check the native exit code, compute the downloaded SHA-256 with Get-FileHash, compare case-insensitively to the supplied expected value, emit compact JSON with status pass or fail and the expected/actual digest, and exit nonzero on failure.
- [ ] Remove the temporary file in finally. Keep error output fixed and concise; do not include response bodies, credentials, local usernames, or arbitrary downloaded content. Do not add retries, API calls, authentication, mirror URLs, or automatic execution of the downloaded EXE.
- [ ] Add tests for invalid expected-digest input and the fixed failure JSON contract without contacting GitHub. Do not contact GitHub until a Release exists and a separate publication authorization is active. Keep the network verification script as a manual post-publish tool.
- [ ] Run the static tests and PowerShell syntax/lint checks available on the host. Record NOT_RUN for checks that are unavailable rather than weakening the script.
- [ ] Add the new script to the profile package and required source path lists, rerun the profile verifier, and stage only scripts/verify_public_preview_download.ps1, tests/test_public_preview_release.py, and the profile. Run git diff --cached --check, then commit:
  ~~~
  git add -- scripts/verify_public_preview_download.ps1 tests/test_public_preview_release.py release_profiles/integrations_preview.json
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "test(release): verify fixed public download link"
  ~~~

**Expected result**

After publication, one manual command can verify the unauthenticated primary installer URL against a known SHA-256 without exposing credentials or silently running the downloaded program.

## Task 7: Make the candidate workflow produce the same explicit handoff bundle

**Files**

- Modify .github/workflows/windows-integrations-preview.yml.
- Modify tests/test_integrations_preview_workflow.py.
- Modify release_profiles/integrations_preview.json only if the workflow path change requires a profile input update.

**Steps**

- [ ] Add failing workflow-contract tests requiring the staging script invocation, all eight asset names, the stable and versioned installer names, DOWNLOAD-METADATA.json, SHA256SUMS, and the public-preview artifact name agentguardian-public-preview-bundle-. Require the workflow to retain permissions contents: read and to contain no contents: write, gh release create, release action, create-release, PAT, or references to secrets. Preserve the existing GH_TOKEN value derived from github.token only for downloading the pinned public Inno Setup dependency; it must not be used for Release publication.
- [ ] Run the workflow-contract tests and expect the staging assertions to FAIL against the current five-file manual assembly.
- [ ] Keep exact candidate SHA checkout, clean-tree verification, hash-locked dependency installation, all current pytest/privacy/brand/profile/compile/secret/diff gates, deterministic two-build Skill comparison, deterministic two-build portable comparison, pinned Inno Setup download and digest verification, exact installer build, and all three lifecycle modes.
- [ ] Add a RELEASE_ROOT environment value under the existing runner temporary directory. Replace the manual downloadable-preview PowerShell assembly with one call to scripts/stage_public_preview_release.py using the existing project root, installer path, exact canonical portable path, Skill ZIP path, EXPECTED_SOURCE_COMMIT, and COMMIT_UTC.
- [ ] Pass a non-existent RELEASE_ROOT to the staging tool; remove the current precreation and manual Copy-Item, ConvertTo-Json, and checksum assembly so the tool owns directory creation and verification.
- [ ] After staging, assert that the output directory contains exactly the profile release_assets list and that the staging verifier reports the expected source SHA and unsigned_public_preview state. Fail on any extra or missing file.
- [ ] Upload only RELEASE_ROOT as an Actions artifact named agentguardian-public-preview-bundle-${{ env.EXPECTED_SOURCE_COMMIT }} with the existing 14-day retention. Keep the separate exact-SHA evidence artifact. Do not add a Release API call, a write permission, a PAT, a tag operation, or a retry loop.
- [ ] Update workflow tests to check the exact staging command, canonical portable lookup, stable installer alias, artifact name, read-only permission, pinned action SHAs, and absence of temporary artifact URLs in documentation.
- [ ] Run:
  ~~~
  python -m pytest -q -p no:cacheprovider tests/test_integrations_preview_workflow.py tests/test_public_preview_release.py
  ~~~
  Require PASS.
- [ ] Stage only .github/workflows/windows-integrations-preview.yml, tests/test_integrations_preview_workflow.py, and any profile file directly changed by the workflow contract. Run git diff --cached --check, then commit:
  ~~~
  git add -- .github/workflows/windows-integrations-preview.yml tests/test_integrations_preview_workflow.py release_profiles/integrations_preview.json
  git diff --cached --name-only
  git diff --cached --check
  git commit -m "ci(windows): stage public preview release bundle"
  ~~~

**Expected result**

The read-only Windows workflow produces the exact same eight-file handoff directory that a human Release operator will inspect, without acquiring repository write capability.

## Task 8: Run local and Windows acceptance against synthetic personal data

**Files**

- Keep evidence under the ignored .local-audit/ directory and the runner temporary directory.
- Do not add generated installers, ZIP files, reports, caches, or user data to the source tree.

**Steps**

- [ ] Run the repository gates from a clean checkout:
  ~~~
  python -m pytest -q -p no:cacheprovider
  python scripts/run_personal_privacy_acceptance.py --evidence-path "$env:TEMP\agentguardian-public-preview-privacy.json"
  python scripts/check_brand_assets.py
  python scripts/verify_integrations_preview_profile.py --project-root "$pwd" --profile "$pwd\release_profiles\integrations_preview.json"
  python -m compileall -q src scripts tests
  git diff --check
  git status --short --branch
  ~~~
  Run the repository's available Ruff, mypy, coverage, and PowerShell checks as configured. Record each actual result as PASS, FAIL, or NOT_RUN; do not change assertions or configuration to manufacture a pass.
- [ ] Run a repository secret scan that reports only a count and exit status. Inspect changed filenames and staged bytes for credentials, private keys, local reports, caches, and personal data without printing matches.
- [ ] Build the Skill twice, the portable ZIP twice, and the installer once from the exact candidate SHA. Run the staging tool and verify the exact eight names, stable/versioned installer byte identity, metadata source SHA, metadata release flags, sorted SHA256SUMS, and no extra files.
- [ ] Dispatch or observe the read-only Windows workflow only for the exact candidate SHA after the implementation branch is pushed through its separately authorized update route. Verify the returned artifact name, source SHA, eight-file set, and archived evidence. Treat all previous CI runs as historical evidence until this exact source SHA run succeeds.
- [ ] On a clean Windows 11 x64 machine or isolated account, verify SHA256SUMS before execution, run the unsigned installer, and exercise GUI, MCP, and Skill modes using synthetic personal non-regulated data for browser, clipboard, files, and public_share. Confirm that each selected operation prompts before continuing, that no Provider API is called by default, that MCP exposes only prepare_audit and run_prepared_audit, and that the Skill remains independently installable.
- [ ] Test installer upgrade over the same preview version, interrupted installation, failed host configuration, explicit uninstall, and post-uninstall residue. Verify that the GUI, MCP executable, Skill files, opt-in Codex configuration, backup, and manifest are removed or preserved exactly according to the existing lifecycle contract. Verify that the older 0.2 route is not modified.
- [ ] If a clean machine, Windows workflow, or configured lint/type tool is unavailable, preserve the corresponding NOT_RUN state and record the exact missing capability in the local evidence report. Do not promote INTEGRATIONS-PREVIEW-NOT-READY or NO-GO based on historical results alone.

**Expected result**

The product has current evidence for build determinism, payload composition, runtime behavior, privacy boundary, and lifecycle behavior. Any unavailable environment remains an explicit evidence gap rather than an implied pass.

## Task 9: Independent review and local publication handoff

**Files**

- Review all changed source, workflow, packaging, profile, test, and documentation files.
- Create or update only .local-audit/PRE-PUBLISH-REPORT.md.
- Keep the report ignored and outside the Release asset directory.

**Steps**

- [ ] Request a fresh read-only independent review after the implementation commits. Use this scope:
  ~~~
  Review the AgentGuardian public-preview distribution changes on the current candidate commit. Check the profile-backed eight-file allowlist, staging path and reparse protections, secret/private-data exclusion, metadata and checksum circularity, installer contents and unsigned disclosure, fixed-link documentation, workflow permissions, pinned Actions, and separation between read-only CI and manual Release publication. Report Critical, Important, and Minor findings with file and line references. Do not edit files, commit, push, create tags, or create Releases.
  ~~~
- [ ] Resolve every Critical or Important finding with a focused test and a fresh verification run. Do not close a finding by weakening an assertion, hiding output, or changing the maturity label.
- [ ] Generate the local PRE-PUBLISH-REPORT.md with the final branch, HEAD, profile/source SHA, profile digest, exact asset allowlist, build/test/lint/type/clean-machine states, per-asset SHA-256 and size, installer disclosure state, unsigned status, workflow permission state, and explicit statements that no tag, Release, push, production-safety claim, or high-sensitivity-data support is included in this implementation turn.
- [ ] Perform the final local review:
  ~~~
  git status --short --branch
  git diff --check
  git log -1 --oneline --decorate
  git diff --name-only main...HEAD
  ~~~
  Confirm every changed path is intentional and the only untracked output is ignored local evidence.
- [ ] Stop at the publication boundary and request a separate explicit authorization if publication is desired. The future authorized sequence is: update the intended branch through the approved non-force route; promote the exact reviewed source to main; create tag v0.3.0-preview.1; create a published, non-draft, non-prerelease Release titled AgentGuardian 0.3.0 Public Preview (Unsigned); upload only the eight allowlisted files; run the fixed-link verifier; and create a local POST-PUBLISH-REPORT. Never overwrite a non-empty repository, create a second owner, use the retired account, bypass Push Protection, or expose credentials.
- [ ] Keep the fixed-link rationale in the report: GitHub's latest release download route selects the latest published release, so the preview product label can use a preview tag while the first public Release object must use the profile's false draft and false prerelease flags for the stable latest/download URL. Cite the official GitHub release API and release-link documentation in the active runbook:
  ~~~
  https://docs.github.com/en/rest/releases/releases
  https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases
  ~~~

**Expected result**

An independent reviewer and a local evidence report can determine whether the exact handoff is ready for a separately authorized public Release, without confusing historical CI results with current verification or implying production security.

## Plan Self-Review

- [ ] Trace every approved specification requirement to one or more tasks:
  - One-click Windows x64 download route: Tasks 1, 2, 5, 7, and 9.
  - Installer containing GUI, local STDIO MCP, and independent Skill payload: Tasks 4, 5, and 8.
  - Fixed releases/latest/download URL: Tasks 1, 5, 6, and 9.
  - Unsigned Public Preview disclosure: Tasks 1, 4, 5, and 9.
  - Exact hashes and metadata: Tasks 2, 7, 8, and 9.
  - Read-only CI and separately authorized publication: Tasks 5, 7, and 9.
  - No high-sensitivity data or production-safety claim: Tasks 4, 5, 8, and 9.
- [ ] Check that all task file paths match the current repository layout and that each new script is added to the profile only after it exists.
- [ ] Check that test commands cover red, green, packaging, workflow, profile, static, lifecycle, and full-suite verification without lowering standards.
- [ ] Scan this plan for unfinished marker wording, unresolved names, contradictory Release flags, accidental remote-write commands, secret output, and unintended binary or report publication.
- [ ] Keep the intentionally separate scopes out of this implementation: Authenticode signing, enterprise controls, dynamic MCP sandboxing, browser database acquisition, automatic remediation, and the broader quality-debt program. They require their own reviewed specifications and gates.
- [ ] Do not mark the repository ready, production-safe, high-sensitivity-data capable, or formally delivered merely because this plan is complete.
