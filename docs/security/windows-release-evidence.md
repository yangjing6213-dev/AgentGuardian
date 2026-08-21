# Windows Release Evidence Runbook

> **HISTORICAL AND NON-GOVERNING STORE/MSIX SNAPSHOT**
>
> The Store/MSIX/WACK/Partner Center route and file references below are retained only for historical traceability. They are not active instructions, product promises, or current release evidence. The only active route is the unsigned `personal_exe_private_beta` maturity track for known testers. It remains `PRIVATE-BETA-NOT-READY` because no real installer EXE, successful native workflow execution evidence, or two-machine acceptance evidence exists; formal public release is `NO-GO`.
>
> Retiring or deleting historical Store files is not readiness evidence. An Actions artifact from the public repository is not an access-controlled private distribution channel. See `personal-v1-release-runbook.md` for the active release gate.

At the time of this snapshot, the historical runbook applied only to a clean exact source commit and a package signed by the target organization. It did not establish production safety. OpenAI Provider remains limited to local adaptation, detection, and manual guidance, with no provider API call by default.

## Historical Required Order

1. Complete the dependency, SBOM, and redistribution-license review. Every
   CycloneDX component must have a reviewed license expression; `NOASSERTION`
   is an intentional failure state.
2. Build the portable bundle from a clean exact commit. A trusted candidate
   must explicitly use `--artifact-status trusted_release`; the default is
   `unsigned_development_only`.
3. Build the same-identity MSIX package and its higher-version upgrade, then
   sign both with the organization certificate and a trusted SHA-256
   timestamp. Private key material stays in the CI secret/store.
4. On an independently provisioned clean Windows machine, run
   `scripts/verify_windows_msix.ps1` with both
   `-RequireTrustedSignature` and `-RequireFreshUserState`. The evidence must
   show install, upgrade, launch, bounded liveness, termination, uninstall,
   `package_residue=false`, and `app_data_residue=false`.
5. Run `scripts/verify_windows_release_candidate.py` against the exact bundle,
   smoke evidence, source SHA, and an approved license-review record. This
   final gate rejects unsigned evidence, source drift, unknown licenses,
   missing/stale license review, incomplete uninstall evidence, and an
   unsigned build metadata status. Every input path must be absolute, local,
   non-symlink, and free of UNC/reparse components.

## Historical Final Gate Example

Do not use this command as an active release instruction. The Store-only script names are preserved as historical references and may be absent after route retirement.

```powershell
python scripts/verify_windows_release_candidate.py `
  --bundle-root .analysis\signed-portable\dist\AgentGuardian `
  --smoke-evidence .analysis\signed-msix-smoke.json `
  --expected-source-commit <40-character-lowercase-commit> `
  --require-trusted-signature `
  --require-fresh-user-state `
  --license-review docs/security/windows-license-review.json
```

Do not commit the package, PFX, password, private key, raw user data, or
unredacted machine profile. The final evidence JSON may contain status,
version, digest, signer identity, and fixed pass/fail fields only.
