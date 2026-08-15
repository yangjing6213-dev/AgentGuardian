# Windows Release Evidence Runbook

This runbook is a release gate, not a production-safety claim. It is only
valid for a clean exact source commit and a package signed by the target
organization.

## Required order

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
   unsigned build metadata status.

## Final gate example

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
