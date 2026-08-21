# AgentGuardian Personal EXE Private Beta Design

**Date:** 2026-08-21
**Status:** Approved design
**Distribution channel:** Direct private delivery of an offline Windows EXE installer

**Supersedes:** The Store distribution and Task 8 acceptance sections of
`2026-08-16-agentguardian-personal-v1-design.md` and
`2026-08-16-agentguardian-personal-v1-implementation.md`. All previously
approved Personal v1 product, privacy, and unsupported-data boundaries remain
in force.

## Context

AgentGuardian builds a deterministic Windows x64 portable payload. The retired
Microsoft Store route required Partner Center identity values and external
Store acceptance. Directly distributed MSIX would instead require a publicly
trusted signing certificate that might not be available to the current
publisher.

The selected replacement is a traditional, unsigned, offline EXE installer for
delivery to known private testers. Users may see Windows SmartScreen or unknown
publisher warnings. This channel is not a formal public release, does not
establish production safety, and does not expand the supported data boundary.

## Goals

- Produce one offline Windows 11 x64 installer executable from the existing
  hash-locked portable payload.
- Install for the current user without administrator privileges.
- Support start-menu launch, manual same-user upgrades, and complete program
  removal.
- Preserve application state during upgrades and handle optional state removal
  safely during uninstall.
- Bind every candidate and delivery artifact to an exact source commit,
  dependency set, payload manifest, and SHA-256 digest.
- Provide an evidence-bounded private-beta readiness decision without implying
  public-release readiness.

## Non-Goals

- No Microsoft Store, Partner Center, WACK, MSIX, App Installer, or Store
  identity integration remains in the active delivery path.
- No public website download, GitHub binary release, automatic deployment, or
  public rollout is authorized by this design.
- No Authenticode, PFX, signing password, timestamp service, or signing secret
  is required for the private beta.
- No automatic updater, background network check, downloader, service, driver,
  scheduled task, shell extension, or browser extension is introduced.
- No support is added for regulated, highly sensitive, or other unsupported
  real-world data.
- No production-safety claim is permitted.

## Release Identity

The first installer candidate uses these fixed values:

- Display version: `0.2.0-beta.1`
- Python package version: `0.2.0b1`
- Windows numeric file version: `0.2.0.1`
- Architecture: `x64`
- Channel: `personal_exe_private_beta`
- Inno Setup `AppId`: `{7A76221A-CFA0-4860-B250-7083B736F3FB}`
- Installer filename: `AgentGuardian-Setup-0.2.0-beta.1-x64.exe`
- Install directory: `{localappdata}\Programs\AgentGuardian`

The `AppId` and installation directory are immutable after the first private
delivery. A later beta increments both the display and numeric versions while
retaining the same `AppId`. The installer rejects an installed version newer
than itself. The project does not use `1.0.0` while the channel is an unsigned
private beta.

## Build Architecture

The build pipeline is:

1. Install development and build dependencies from hash-locked files.
2. Run the existing deterministic PyInstaller x64 portable build.
3. Verify the portable payload, SBOM, third-party notices, build metadata,
   payload manifest, and checksums.
4. Compile a static Inno Setup script around that verified payload.
5. Verify installer metadata, filename, architecture, embedded source metadata,
   and SHA-256 digest.
6. Create the bounded private-beta delivery evidence set.

The approved compiler is Inno Setup `7.0.2` x64 from the immutable upstream
GitHub release asset:

- Asset: `innosetup-7.0.2-x64.exe`
- SHA-256: `5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1`
- Installed `ISCC.exe` SHA-256: `0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d`
- Release tag: `is-7_0_2`

The build must verify the pinned SHA-256, upstream GitHub release attestation,
and valid upstream Authenticode signature before executing the compiler
installer. It must not use a moving download URL, `winget`, Chocolatey, or an
unpinned package source.

The portable payload remains subject to byte-reproducibility checks. The Inno
Setup wrapper is bound by digest and provenance; it is not called
byte-reproducible unless two clean builds independently prove identical bytes.

## Installer Contract

The Inno Setup script must enforce:

- `PrivilegesRequired=lowest` with no all-users override.
- Windows 11 x64 as the only supported target.
- A fixed current-user application directory.
- No network source, download flag, URL, remote archive, or runtime fetch.
- No service, driver, scheduled task, startup entry, file association, shell
  extension, browser integration, or machine-wide registry write.
- A start-menu shortcut and an opt-in desktop shortcut.
- Standard current-user uninstall registration.
- Detection of a running AgentGuardian process before replacement or removal.
- Visible failure when required files cannot be installed or removed.
- No launch-on-failure and no success message after a failed operation.

The installer contains the complete portable payload. It never executes an
untrusted helper outside that payload.

## State, Reports, Upgrade, And Uninstall

Program files and user data have separate ownership:

- Program files: `%LOCALAPPDATA%\Programs\AgentGuardian`
- DPAPI-protected state:
  `%LOCALAPPDATA%\AgentGuardian\evidence-state-v1.bin`
- Reports and diagnostics: only paths explicitly selected by the user

A same-user upgrade replaces program files and preserves DPAPI-protected state.
Downgrade is rejected by default. A tester who needs to roll back uninstalls the
new version and then runs the older installer.

Uninstall always removes the program directory, shortcuts, and uninstall
registration. It asks whether to remove AgentGuardian-owned protected state.
Optional state removal is implemented by a bounded application command that:

- accepts no caller-supplied path;
- resolves only the fixed current-user state location;
- rejects UNC, relative, reparse-point, junction, and unexpected paths;
- never follows links;
- deletes only recognized AgentGuardian state files; and
- reports residue or failure without exposing machine-specific paths.

The uninstaller never deletes user-selected reports or diagnostics. Those files
remain under user control regardless of the uninstall selection.

## Delivery Artifacts

Each candidate produces exactly one bounded evidence directory containing:

- `AgentGuardian-Setup-0.2.0-beta.1-x64.exe`
- `SHA256SUMS`
- `BUILD-METADATA.json`
- `PAYLOAD-MANIFEST.json`
- `AgentGuardian.cdx.json`
- `THIRD_PARTY_NOTICES.md`
- `PRIVATE-BETA-README.txt`
- `PRIVATE-BETA-MANIFEST.json`

The manifest records the exact source commit, commit time, product versions,
installer compiler version and digest, payload digest, installer digest,
architecture, channel, and artifact status. It contains no username, machine
path, credential, signing material, or user content.

The README states the unsupported-data boundary, unsigned publisher warning,
manual installation and upgrade procedure, checksum procedure, uninstall
behavior, support contact, and issue-reporting process.

## Release Profile And Status

The active release profile becomes `personal_exe_private_beta`. It pins:

- version mappings;
- immutable `AppId` and installation directory;
- architecture and output filename;
- Inno Setup version, asset, release tag, and SHA-256;
- all package input paths;
- forbidden installer capabilities and workflow tokens; and
- the exact active documentation set.

The status ledger uses two private-beta decisions:

- `PRIVATE-BETA-NOT-READY`
- `PRIVATE-BETA-READY`

The formal public-release status remains `NO-GO` in active documentation. A
private-beta-ready decision never implies formal delivery or production safety.

The private-beta ledger contains these exact gates:

1. `scope`
2. `local`
3. `remote`
4. `supply_chain`
5. `installer`
6. `independent_machine`
7. `independent_review`
8. `operations`

Each gate records status, exact source commit, evidence SHA-256, and UTC
verification time. The ledger remains `PRIVATE-BETA-NOT-READY` while any gate
is not `pass`.

The package candidate commit `S` is frozen before gate evidence is collected.
A later ledger-only commit may bind evidence to `S`; it cannot serve as evidence
for itself. Any change to source, dependencies, compiler, version, installer
script, release profile, or package input invalidates affected gates and creates
a new candidate.

## Gate Definitions

### Scope

Removed enterprise, high-sensitivity, dynamic MCP, API-default, telemetry,
updater, service, and downloader capabilities are absent from source, runtime,
workflow, payload, installer, and active documentation.

### Local

The full test suite, privacy acceptance, brand validation, compileall, release
profile verification, installer-focused tests, secret scan, and
`git diff --check` pass on a clean tree for `S`.

### Remote

Normal CI and the Windows EXE private-beta workflow pass for exact SHA `S`.
Historical runs and runs for another SHA do not count.

### Supply Chain

Hash-locked dependencies, deterministic portable payload, SBOM, third-party
notices, compiler verification, payload manifest, checksums, and provenance all
pass. The license review covers Python, PySide/Qt, PyInstaller, Inno Setup, and
every shipped component. Commercial use of Inno Setup remains outside this
private-testing authorization and requires an explicit license decision.

### Installer

The exact installer from `S` passes current-user install, launch, shortcut,
manual upgrade, downgrade rejection, uninstall, retained-state, deleted-state,
report-preservation, and residue checks. It creates no forbidden system
integration and performs no network access.

### Independent Machine

At least two newly provisioned Windows 11 x64 environments without development
tools install and exercise the exact candidate. Evidence covers the expected
unsigned warning, first launch, eligible scans, browser metadata audit,
clipboard audit, explicit share verification, remediation and rollback,
report comparison, crash/restart, upgrade, uninstall, and residue inspection.

### Independent Review

An independent reviewer examines the exact source SHA, installer script,
builder, cleanup path, workflow, payload, and evidence contract. No unresolved
Critical or Important finding may remain. Lower-severity findings require an
explicit disposition.

### Operations

The private-beta README, privacy notice, support contact, security reporting
channel, issue intake, version support statement, manual update procedure,
rollback procedure, and checksum distribution procedure are operational.

## CI And Publication Boundary

The Windows workflow builds and verifies the unsigned installer on a clean
GitHub-hosted Windows runner. It uploads only the bounded evidence directory as
a short-retention Actions artifact. In this public repository, that artifact
is not an access-controlled distribution channel and must not be represented as
private delivery. The workflow does not create a GitHub Release, attach an
asset to a tag, publish to a website, deploy, call Partner Center, or expose
credentials.

Private delivery is a deliberate human action after the ledger records
`PRIVATE-BETA-READY`. The sender provides the installer, README, and checksum to
known testers. The repository and CI never claim that SmartScreen warnings are
absent.

## Failure Behavior

- A dirty tree, version mismatch, compiler mismatch, invalid compiler
  provenance, forbidden capability, unexpected package input, or non-x64 host
  fails before installer compilation.
- A payload or evidence digest mismatch fails closed.
- Unsupported Windows versions or architectures fail before file installation.
- Running-process, file-copy, shortcut, upgrade, cleanup, or uninstall failures
  remain visible and do not produce success evidence.
- State cleanup rejects unsafe paths and preserves data on uncertainty.
- No error path enables elevation, network download, automatic update,
  telemetry, API access, or removal of user-selected reports.

## Verification Strategy

Automated tests cover:

- canonical release-profile and status-ledger schemas;
- version and immutable installer identity convergence;
- compiler provenance and digest rejection;
- builder path, traversal, reparse-point, size, and input allowlist failures;
- forbidden Inno directives and tokens;
- deterministic portable payload comparison;
- installer evidence and checksum validation;
- state-purge path confinement and failure behavior;
- silent current-user install, launch, same-user upgrade, downgrade rejection,
  uninstall, retained state, deleted state, and report preservation;
- absence of service, driver, task, updater, and network activity; and
- bounded, machine-neutral evidence output.

Manual acceptance on two clean machines validates the user-visible wizard,
SmartScreen warning disclosure, start-menu and optional desktop shortcuts,
normal application workflows, upgrade behavior, uninstall choices, and residue.

## Migration From The Store Path

The implementation replaces the active Store release profile, workflow,
version assertions, status model, and active documentation with the EXE private
beta equivalents. Store-only workflow files, WACK fixtures, MSIX builders,
Store evidence validators, and tests are removed after equivalent EXE coverage
passes. Historical reports, specifications, plans, commits, and Git history are
retained as historical evidence and marked non-governing where needed.

The migration does not rewrite or erase prior Store work. It prevents that work
from being mistaken for the active delivery route.

## Acceptance Criteria

This design is implemented only when:

- the exact pinned compiler is verified before use;
- the private-beta profile rejects all unapproved installer behavior;
- a clean exact-SHA build produces the bounded offline EXE and evidence set;
- focused and full tests pass locally and remotely;
- independent review has no unresolved Critical or Important finding;
- two clean machines pass the complete install-to-uninstall workflow; and
- the status ledger records `PRIVATE-BETA-READY` for the exact candidate SHA.

Even after these criteria pass, the result remains an unsigned private beta for
known testers. Formal public release, production safety, and support for highly
sensitive real data remain unapproved.
