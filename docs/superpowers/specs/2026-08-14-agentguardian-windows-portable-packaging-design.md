# AgentGuardian Windows Portable Packaging Design

Status: user delegated the packaging choice and authorized continued development on 2026-08-14.

## Decision

Batch 5 is split into two independently gated layers:

1. Build an unsigned PyInstaller `onedir` portable package and deterministic ZIP from a hash-locked Windows Python 3.12 build environment.
2. Add a native Windows installer and trusted code signing only after the portable package gate passes and signing credentials and GitHub workflow permissions are separately authorized.

Passing layer 1 means only that the package can be built from a recorded clean commit, inspected file by file, launched in a bounded smoke test, checked against an SBOM and SHA-256 manifest, rebuilt in the same declared environment, and removed with its test state. It does not mean the package is signed, trusted by Windows, clean-machine accepted, production-safe, or ready for release.

## Why `onedir`

An `onedir` bundle exposes its executable, Qt libraries, Python runtime, package data, and reviewed source copies as separate files. That makes manifest comparison, license inspection, malware scanning, SBOM reconciliation, and deletion-residue tests more direct than a self-extracting `onefile` executable. PyInstaller is a build-only dependency and is not imported by AgentGuardian at runtime.

`pyside6-deploy`/Nuitka remains a possible later optimization, not a parallel implementation. MSIX is deferred because Windows requires signed, trusted packages and this workspace currently has neither an approved signing certificate nor the required packaging tools.

## Package Boundary

The portable package contains:

- `AgentGuardian.exe` built without elevation, console, updater, telemetry, network, or one-file extraction options;
- the PySide6 and Python runtime files selected by PyInstaller;
- `agentguardian/rules/default.json` and `agentguardian/source_policy.json`;
- byte-identical copies of every reviewed `src/agentguardian/*.py` module named by `source_policy.json`, so the existing static self-audit can still inspect its declared source set;
- the Apache-2.0 project license and a generated third-party component notice;
- a CycloneDX SBOM, build metadata, a sorted file manifest, and SHA-256 checksums.

The copied Python source supports the existing package-source policy. It does not by itself prove that frozen bytecode or native binaries were derived from those copies. Rebuild comparison, build provenance, signatures, and independent binary review are separate evidence.

## Build Contract

The canonical build runs on 64-bit Windows with Python 3.12 and hash-locked build dependencies. It fails closed when the Git tree is dirty, the source-policy module set differs from the package source set, required resources are missing, a package path is a symlink/reparse point, or generated metadata contains an absolute workspace path.

The build command uses PyInstaller `--onedir`, `--windowed`, `--noupx`, `--clean`, and a fixed application name. It never requests UAC elevation. Generated files use sorted relative POSIX paths and canonical JSON. ZIP entries use a fixed timestamp and permissions. Two builds count as reproducible only when all file hashes and the final ZIP hash match under the same recorded Python, dependency lock, operating system image, source commit, and build script.

## Verification Layers

1. **Unit contract:** command construction, reviewed-source inclusion, manifest validation, canonical metadata, and deterministic ZIP behavior use synthetic files.
2. **Local frozen smoke:** build on Python 3.12, verify resources and self-audit behavior, launch the GUI long enough to detect an immediate crash, terminate it, and delete the copied test package and isolated state directories.
3. **Rebuild check:** build twice from the same clean commit in separate directories and compare manifests and ZIP hashes.
4. **Fresh-runner check:** a later GitHub Actions job downloads the built artifact into a separate Windows runner, repeats verification and removal, and records provenance. Editing workflow files requires separate workflow-scope authorization.
5. **Native/signing check:** create the selected installer, sign with an approved trusted certificate and timestamp service, verify the signature, install as a standard user, uninstall, and inspect declared state locations for residue.

## Security And Licensing Limits

- PyInstaller packaging does not expand AgentGuardian's application network or API capability.
- OpenAI Provider behavior remains local static detection and manual guidance only.
- PySide6/Qt redistribution is subject to LGPLv3/GPLv3 or a commercial Qt license; the artifact must carry the applicable notices and permit relinking as required. This design is engineering evidence, not legal advice.
- No secret, certificate, PFX, API key, endpoint value, full user path, local audit evidence, or GitHub token may enter the package or metadata.
- Unsigned output is a development artifact only. It must not be called a release, installer, Windows MVP, or production-safe build.

## Acceptance

Layer 1 is accepted only when its focused tests, full local suite, dual-build comparison, package-source self-audit, license/SBOM checks, launch smoke, cleanup check, brand validation, compile check, and diff check pass at one clean commit. Layer 2 and Batch 6 remain pending after that acceptance.
