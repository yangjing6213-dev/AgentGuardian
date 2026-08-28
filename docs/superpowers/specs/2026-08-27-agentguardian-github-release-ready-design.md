# AgentGuardian GitHub Release-Ready Public Preview Distribution Design

**Date:** 2026-08-27
**Status:** Approved concept; written-spec review pending
**Source baseline:** `1add24fd91a7bc060018903c6620235b45bef8f1`
**Development branch:** `codex/0.3-integrations-preview`
**Target repository:** `yangjing6213-dev/AgentGuardian`
**License:** Apache-2.0
**Initial channel:** `0.3.0-preview.1` unsigned Public Preview

## 1. Decision Summary

The first public distribution uses one primary Windows x64 installer file hosted
on a GitHub Release:

```text
AgentGuardian-Setup-Windows-x64.exe
```

The file is a traditional Inno Setup installer, not an MSIX package. It is a
single download for the user's normal path and has no Python prerequisite. The
installer bundles the current desktop GUI, the local STDIO MCP launcher, and
the standalone Codex Skill payload. It may also install the Skill and managed
MCP configuration only after the user sees and accepts the corresponding
choices.

The independent Skill ZIP remains a separate deliverable for Agensi and
AgentPowers. Bundling the Skill in the Windows installer does not replace that
marketplace package and does not give it a different license.

The repository README will use this fixed primary link:

```text
https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe
```

The first release is explicitly an **unsigned Public Preview**. It must not be
described as production-safe, suitable for highly sensitive real data, or an
enterprise product. SHA-256 checksums, metadata, notices, and optional GitHub
attestation improve verification but do not substitute for Authenticode code
signing.

This document defines the release-ready product and verification contract. It
does not authorize a merge to `main`, a tag, a GitHub Release, a repository
write, or a push.

## 2. GitHub `latest` Compatibility Rule

The fixed asset URL is a product requirement, not merely a documentation
convention. GitHub resolves `releases/latest` to the most recent published
release that is neither a draft nor a prerelease. Therefore a GitHub Release
marked `prerelease=true` cannot be the target of the first fixed download link.

For the first public preview, the release contract is:

- Git tag: `v0.3.0-preview.1`.
- Release title: `AgentGuardian 0.3.0 Public Preview (Unsigned)`.
- Release object: published, non-draft, non-prerelease, so `latest` resolves.
- Release body and metadata: prominently state `unsigned_public_preview`,
  SmartScreen/Unknown Publisher expectations, supported scope, and all
  exclusions.
- Product version in the installer and metadata: `0.3.0-preview.1`.

This preserves the preview version identity while making the fixed homepage
link usable from the first release. It also means the GitHub UI may show this
preview as the repository's latest full release; the title, README warning,
release body, and metadata must make its maturity unambiguous.

If the product owner later requires the GitHub prerelease flag to be `true`,
the fixed `releases/latest/download` requirement must be revisited before
publication. Under this design it is not silently changed to a versioned or
Actions-artifact URL.

Reference: [GitHub REST release semantics](https://docs.github.com/en/rest/releases/releases)
and [GitHub release links](https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases).

## 3. User-Facing Success Criteria

The primary user journey is:

1. Open the public repository homepage.
2. Click the primary download link or the visible Releases link.
3. Download one `AgentGuardian-Setup-Windows-x64.exe` file.
4. Run it on Windows 11 x64 as an ordinary user.
5. Install and launch the GUI without installing Python or manually assembling
   a runtime.
6. Optionally select Codex Skill installation and/or local MCP configuration
   after reading the displayed scope and target paths.
7. Use the GUI, the installed Skill plus MCP, or both against supported
   personal non-regulated data.
8. Uninstall through Windows Apps/Programs and confirm that AgentGuardian-owned
   files and managed integration state are removed or restored according to
   the documented transaction rules.

"One file" means one primary installer download. It does not mean that the
installer has no internal files, nor that optional verification files are
unavailable. The installer must work offline after it has been downloaded;
there is no background updater, remote rule fetch, automatic component
download, or default Provider API call.

## 4. Scope And Explicit Non-Goals

### In scope

- Windows 11 x64 current-user installation through the existing Inno Setup
  route.
- One local audit core shared by the desktop GUI, Codex Skill workflow, and
  STDIO MCP adapter.
- The four currently supported bounded operations: `files`, `browser`,
  `clipboard`, and `public_share`.
- The current MCP contract with exactly `prepare_audit` and
  `run_prepared_audit`.
- Skill installation as a host integration with fixed guidance when MCP is
  unavailable.
- Public GitHub Release assets, stable asset naming, checksums, metadata,
  license, third-party notices, and release verification.

### Out of scope for this first release

- Authenticode signing, an EV certificate, MSIX, App Installer, Store, WACK,
  Partner Center, or a certificate-dependent trust claim.
- Browser database content extraction, clipboard persistence, arbitrary SQL,
  arbitrary command execution, dynamic MCP loading, automatic remediation, or
  writes to audited user data.
- Enterprise administration, a cloud console, telemetry, accounts, licensing
  enforcement, remote rule service, or automatic updates.
- Default OpenAI, Anthropic, or other Provider API requests. OpenAI Provider
  behavior remains local adaptation, detection, and manual guidance only.
- Processing medical, financial, identity, biometric, legally privileged,
  customer-dataset, state-secret, regulated, or other high-sensitivity real
  data.
- A production-safety, compliance, or security guarantee.

## 5. Product And Package Architecture

The package exposes three user-facing entry points over one local audit core:

```text
                         +---------------------+
                         | Local Audit Core    |
                         +----------+----------+
                                    |
             +----------------------+----------------------+
             |                      |                      |
      +------v------+        +------v------+        +------v------+
      | Desktop GUI |        | STDIO MCP   |        | Codex Skill |
      | Windows EXE |        | local EXE   |        | host package |
      +-------------+        +-------------+        +-------------+
```

The installer contains the reviewed GUI and MCP launchers in one packaged
runtime plus the Skill files. The launchers are adapters, not separate audit
implementations:

- `AgentGuardian.exe` starts the windowed GUI and supported maintenance modes.
- `AgentGuardianMcp.exe --stdio-mcp` starts the console STDIO MCP process.
- The Skill contains workflow instructions and fixed installation guidance;
  it does not duplicate detectors, include an executable, or read target data
  itself.

The current-preview install identity and current-user path remain frozen for
the first public preview so that the already reviewed lifecycle behavior is
not silently changed:

```text
%LOCALAPPDATA%\Programs\AgentGuardian Integrations Preview
```

The exact AppId and installer profile values are taken from the release
profile. A future stable channel requires a separate identity/migration
decision and must not pretend that this preview path is already a stable
product identity.

The installer always carries the three component payloads. GUI installation
is the base action. Skill installation and managed MCP configuration are
visible, independently selectable integration actions; selection is not
silently inferred from the presence of Codex or another host.

## 6. Consent And Configuration Behavior

The installer wizard displays, before it changes anything:

- the install directory;
- the Skill destination;
- the Codex MCP configuration path;
- the exact integration actions selected; and
- the personal non-regulated data boundary and unsigned-preview warning.

The installer does not start or close Codex, restart a host, create a service,
add a startup task, open a firewall port, or make a network request. A
successful configuration step instructs the user to restart the relevant host
manually.

The managed MCP configuration points to the absolute installed console
launcher and the exact argument `--stdio-mcp`. It enables only the two reviewed
AgentGuardian tools and leaves the run operation under host-level approval.
The helper changes only the AgentGuardian-owned configuration block, preserves
unrelated TOML content, snapshots the previous state, and restores it on
uninstall or rollback according to the existing transaction contract.

The Skill's fallback behavior is deliberately bounded:

- If the MCP tools are available, it explains the prepare/approval/run flow and
  uses the existing two-tool contract.
- If MCP is unavailable, it reports the missing integration and shows the
  fixed GitHub Release installation/configuration guidance.
- It does not execute arbitrary shell commands, download an installer, edit
  host configuration, or call a Provider API on the user's behalf.

## 7. Release Asset Contract

The first Release contains the following assets. Names are part of the public
interface and must be checked before publication:

| Asset | Purpose |
| --- | --- |
| `AgentGuardian-Setup-Windows-x64.exe` | Primary stable-name installer used by the README fixed link |
| `AgentGuardian-Setup-0.3.0-preview.1-x64.exe` | Versioned installer for immutable, direct release links |
| `AgentGuardian-0.3.0-preview.1-windows-x64.zip` | Portable fallback package |
| `AgentGuardian-Skill-0.2.0.zip` | Independent Skill product for Agensi and AgentPowers |
| `SHA256SUMS` | SHA-256 checksums for all downloadable files except itself |
| `DOWNLOAD-METADATA.json` | Machine-readable version, source, scope, and integrity metadata |
| `LICENSE` | Apache License 2.0 notice |
| `THIRD_PARTY_NOTICES.md` | Runtime and build dependency notices and obligations |

The two installer assets must be byte-for-byte identical. The stable-name
asset is an alias for the versioned installer, not a separately built binary.
Every subsequent release keeps the stable asset name within its own Release;
old Releases and their assets are never overwritten to simulate an update.

`DOWNLOAD-METADATA.json` must include, without secrets or private paths:

- schema version;
- product and Skill versions;
- channel and architecture;
- source commit and build profile;
- supported Windows version;
- signing state `unsigned_public_preview`;
- primary asset name and versioned asset name;
- file names, sizes, and SHA-256 values for installable payloads; and
- explicit limitations and verification instructions.

The metadata must not contain access tokens, API keys, cookies, user paths,
clipboard text, browser URLs, audit findings, or private test data. The
checksum file must be generated from the final bytes copied to the release
upload directory. It must not be generated before a later rename or rebuild.

## 8. README And Repository Surface

The `main` branch README must make the normal path visible in the first
viewport or first download section:

```markdown
[Download AgentGuardian for Windows x64](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe)
```

The surrounding text must state all of the following in plain language:

- this is an unsigned Public Preview;
- Windows may display Unknown Publisher or SmartScreen warnings;
- the supported platform is Windows 11 x64;
- the installer contains GUI, MCP, and Skill payloads, with integration
  configuration requiring explicit selection;
- the supported data boundary is personal non-regulated data only;
- no production-safety or high-sensitivity-data claim is made; and
- the Release page contains the portable package, independent Skill ZIP,
  checksums, metadata, license, and notices.

The homepage source and the Release must describe the same product version and
scope. The fixed link may be merged into `main` before the first Release is
published, but the release handoff is not complete until an unauthenticated
browser request to that link returns the intended installer bytes.

The repository source remains the authoritative implementation. Binaries are
Release assets, not committed to Git history. Actions artifacts remain
short-lived CI handoff evidence and are not the user's long-term download
channel.

## 9. Build And Publication Workflow

The release process has separate candidate, approval, and publication stages:

1. Freeze an exact source commit after review and required CI on the release
   branch. The Windows build runs on a fixed Windows x64 runner and uses the
   hash-locked Python and build dependencies already required by the project.
2. Build the portable payload, Skill ZIP, and installer from that exact commit.
   Validate the profile, launcher layout, resource inclusion, deterministic
   package inputs, and final file hashes.
3. Run the required tests, privacy acceptance, package/lifecycle checks,
   secret scan, license/notice scan, and clean-machine acceptance before any
   public upload.
4. Hold publication behind a manual approval or protected environment. The
   publish job uploads only the allowlisted assets, verifies the uploaded asset
   names and hashes, and creates the Release with the exact tag and body.
5. Verify the public Release, fixed README link, asset downloads, checksums,
   metadata, and source commit from a clean unauthenticated client.

The workflow must use least-privilege permissions, pinned third-party Actions
references, a pinned and hash-verified Inno Setup compiler, and no repository
secret embedded in the package. It must not publish on every push, use force
push, rewrite an existing Release, overwrite an existing asset, create a
second account when GitHub is unavailable, or repeatedly hammer a failing API.
If the API is temporarily unavailable, the supported fallback is a deliberate
manual GitHub web/CLI operation using the already verified local asset set and
the authorized account, followed by the same public verification. No bypass of
GitHub protection or push protection is allowed.

The required repository promotion order is:

```text
release-ready feature branch
        -> review and CI
        -> merge exact release-ready commit to main
        -> create the exact version tag
        -> create and publish the GitHub Release
        -> verify latest download link and assets
```

This order keeps the repository homepage, source tree, tag, and downloadable
binary aligned. It is a future execution sequence, not an action taken by this
specification commit.

## 10. Integrity, Provenance, And Trust Messaging

The first preview uses layered evidence appropriate to an unsigned artifact:

- SHA-256 values in `SHA256SUMS` and `DOWNLOAD-METADATA.json`;
- exact source commit recorded in metadata and release notes;
- reproducible or deterministic package-input checks where the current build
  supports them;
- pinned build tools and dependency hashes;
- complete license and third-party notices;
- optional GitHub artifact attestation when the repository/account supports it;
- immutable Releases when the GitHub feature is available; otherwise a policy
  of versioned, never-overwritten Release assets.

None of these proves that Windows trusts the executable. The release body must
say that the installer is unsigned and may trigger Windows warnings. It must
not call a checksum a signature, an attestation a code-signing certificate,
or a successful test run a production-security certification.

References:

- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
- [Immutable Releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)

## 11. Verification And Acceptance Contract

The following evidence is required for the release handoff. Each item is tied
to the exact source commit and must be freshly recorded after any release-ready
implementation change.

### Current baseline evidence, not release evidence

At the time this specification was written, the current baseline had the
following observed evidence:

- GitHub CI run `32924311288`: success, `1999 passed, 2 skipped`.
- Windows integrations workflow run `32924311365`: success.
- Temporary Actions artifact
  `agentguardian-downloadable-preview-1add24fd91a7bc060018903c6620235b45bef8f1`:
  downloaded and inspected successfully, with a 14-day retention window.

These facts demonstrate the state of the baseline workflow only. They do not
prove that the future Release assets, fixed link, main branch, clean machine,
or final release workflow pass.

### Required release checks

| Check | Acceptance condition |
| --- | --- |
| Exact source | Build metadata, tag, and uploaded assets identify one reviewed commit |
| Functional tests | The real project test suite passes without weakened assertions or skipped gate logic |
| Windows package | Installer contains GUI, MCP launcher, Skill payload, license, and notices |
| Install | Clean Windows 11 x64 machine installs and launches GUI without Python |
| GUI audit | Synthetic personal non-regulated fixtures exercise all four supported operations and visible consent behavior |
| Skill/MCP | Skill detects configured/unconfigured MCP correctly; prepare/run approval and bounded results work through the supported host |
| Uninstall | Clean-machine uninstall removes AgentGuardian-owned files and restores managed configuration without touching unrelated user data |
| Upgrade/rollback | A later preview can upgrade the same preview identity, and a failed integration transaction restores the prior state |
| Integrity | Final uploaded bytes match `SHA256SUMS` and metadata; both installer names have the same hash |
| Public access | Release page and all allowlisted assets are public; fixed `latest/download` URL returns the primary installer without authentication |
| Supply chain | Secret scan, license review, third-party notices, and build-tool provenance complete with no unreviewed findings |
| Scope messaging | README, Release notes, metadata, and installer text consistently state unsigned preview and data limitations |

The current known quality debt is tracked separately and cannot be hidden by
reducing assertions or bypassing gates: Ruff findings, mypy findings, missing
coverage evidence, missing package-build evidence, and CodeQL coverage are
quality-remediation work. Closing that debt is required before any stable or
production-safety claim. A Public Preview may retain a clearly disclosed,
reviewed quality backlog only if the hard release checks above pass and a human
explicitly accepts the documented preview boundary; a workflow must never
convert a failure into a pass by changing the standard.

## 12. Runtime And Privacy Boundary

The installer and runtime are local-first:

- no default Provider API call;
- no telemetry or account sign-in;
- no upload of audited files, clipboard text, browser URLs, credentials, or
  findings;
- only explicit public URL reachability verification may perform network I/O;
- redacted, bounded MCP results may enter the host model context after the
  host approval flow;
- unsupported or high-sensitivity real data is refused by policy and must not
  be marketed as supported.

The installer package itself must not contain real user data, local reports,
backup files, credentials, tokens, caches, test exports, or private account
identifiers. The release manifest is generated from an explicit allowlist.

## 13. Failure, Correction, And Rollback Policy

- A source, test, package, or acceptance failure stops publication before any
  public asset upload.
- A name, hash, or metadata mismatch stops the upload and invalidates the
  candidate; it is rebuilt from the frozen commit.
- A published Release is never silently edited to replace a binary or make an
  old version appear to be a new one. A corrected build receives a new version
  and an explicit correction note.
- The stable filename is reused only inside a new immutable/versioned Release;
  old Release URLs remain historical records.
- A failed installer integration transaction restores its recorded prior state.
- Uninstall removes only files and configuration owned by AgentGuardian. User
  data and unrelated host configuration are not repaired or rewritten.
- If the latest-link verification fails, the release is not announced as
  usable; the versioned Release URL remains a diagnostic path, not a substitute
  for the required homepage experience.

## 14. High-Level Implementation Phases

This design is intentionally separate from the detailed implementation plan.
The plan should execute these phases in order:

1. **Release identity and documentation:** freeze public-preview version,
   stable asset names, README wording, release metadata schema, and notices.
2. **Packaging alignment:** make the existing Windows build emit the stable
   installer alias plus versioned assets while preserving GUI/MCP/Skill
   contents and explicit integration consent.
3. **Release workflow:** add exact-commit candidate validation, allowlisted
   staging, protected manual publication, and public asset verification.
4. **Acceptance:** run clean-machine install, use, upgrade, rollback, and
   uninstall checks, including supported Skill/MCP host behavior.
5. **Public Preview handoff:** only after separate publication authorization,
   promote the verified commit, tag it, publish the Release, and verify the
   fixed link.
6. **Quality remediation:** address Ruff, mypy, coverage, CodeQL, signing,
   and broader installation trust as separately evidenced work. This phase
   does not retroactively upgrade the preview to production status.

## 15. Rejected Distribution Alternatives

### Commit binaries into Git history

Rejected because it bloats the repository, makes history remediation harder,
and encourages users to treat source commits as a mutable binary channel.

### Actions artifact as the user download

Rejected because it is temporary, has retention limits, normally requires
workflow access, and is a CI handoff rather than a long-term public product
download.

### External website or object storage as the first channel

Deferred because it adds hosting, domain, access-control, integrity, and
operational cost before the GitHub-native path is proven. It can be considered
later without changing the installer contract.

### MSIX/App Installer

Deferred because the first release has no signing certificate and the requested
route is a traditional unsigned installer. The first package therefore does
not depend on `Package/Identity/Name`, `Publisher`, or
`PublisherDisplayName` MSIX metadata.

## 16. Traceability To The Current Repository

The design is grounded in the current implementation and packaging surfaces:

- `release_profiles/integrations_preview.json` defines the current preview
  channel, version, installer identity, supported operations, and MCP contract.
- `packaging/windows/AgentGuardianIntegrationsPreview.iss` defines the current
  user-scoped Inno Setup installer, bundled payload, and explicit integration
  tasks.
- `scripts/build_windows_integrations_preview_installer.py` validates the
  preview bundle layout, exact commit, payload, and installer evidence.
- `scripts/build_windows_portable.py` builds the Windows portable payload.
- `scripts/build_agentguardian_skill.py` builds the deterministic standalone
  Skill ZIP.
- `.github/workflows/windows-integrations-preview.yml` defines the current
  Windows build, lifecycle, checksum, metadata, and temporary-artifact path.
- `README.md`, `LICENSE`, and `THIRD_PARTY_NOTICES.md` define the repository
  user-facing scope and redistribution notices that must be synchronized with
  the first Release.
- `docs/superpowers/specs/2026-08-24-agentguardian-integrations-preview-design.md`
  remains the approved architecture and safety boundary for the three entry
  points; this document adds the public distribution contract.

The existing source tree currently has no committed installer, ZIP, MSIX, or
App Installer binary. The release-ready implementation must generate those
files in a controlled build directory and publish only the explicit asset
allowlist above.

## 17. Authorization Boundary

Approval of this design means that the product distribution direction is
settled. It does not authorize any of the following actions:

- editing implementation files;
- changing `main`;
- creating or moving a tag;
- creating, editing, or publishing a GitHub Release;
- pushing a branch or release asset;
- claiming that the product is production-safe; or
- accepting high-sensitivity real data.

Those actions require the implementation plan, fresh verification evidence,
and the user's explicit publication authorization at the applicable step.
