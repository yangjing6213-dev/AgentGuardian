# AgentGuardian Integrations Preview

This document is the active 0.3 boundary for the desktop GUI, standalone
Codex Skill, and local STDIO MCP entry points. All three use one local audit
core and require an explicit human decision before an operation reads local
content, reads the clipboard, copies a browser database, or performs public
share verification.

The supported boundary is personal non-regulated configuration only. Medical,
financial, identity, biometric, customer, legally privileged, regulated, and
other high-sensitivity real data are unsupported. This is a use restriction,
not a production safety claim. The product is currently
`INTEGRATIONS-PREVIEW-NOT-READY` and formal release is `NO-GO`.
This is an unsigned Public Preview, not a production release.

## Workflow routing

`Windows Integrations Preview` is the required Windows candidate gate for the
0.3 Public Preview branch `codex/0.3-public-preview-release`. The older
`codex/0.3-integrations-preview` branch remains an explicit 0.3 development
route. The `Windows EXE private beta candidate` workflow is a separate 0.2
channel: it remains bound to `agent/founder-alpha`,
`personal_exe_private_beta`, and version `0.2.0-beta.1`.

Selecting the private-beta workflow with any other ref causes its candidate job
to be skipped before checkout and build. That run is **not applicable**, not a
successful 0.3 gate. A 0.3 candidate must be verified by
`Windows Integrations Preview`; changing the private-beta profile or lowering
its identity assertion is not a valid migration path.

The runtime must not call OpenAI or another Provider API by default. Provider
configuration is handled through local adaptation, static detection, and
manual guidance. The product has no telemetry, background listener, automatic
update, arbitrary execution, or dynamic MCP loading.

## Public preview staging boundary

The Windows 11 x64 preview staging path binds the output parent and temporary
directory handles, uses short-lived child-handle checks for identities and
digests, closes those child handles before the directory rename, and performs
one final content and source-state recheck before the no-replace atomic rename.
This bounds the release workflow without claiming to remove all kernel-level
TOCTOU behavior. A same-user process can still change content in the narrow
close-to-rename window; such changes are rejected when observed, and
unsupported handle or filesystem behavior fails closed with a fixed error.
The source and decompressed-archive checks include high-confidence modern
OpenAI key formats and GitHub token formats; they are leakage gates, not a
complete secret scanner or cryptographic build provenance.
The candidate Windows workflow additionally fetches full Git history and runs
the pinned official Gitleaks 8.30.1 Windows scanner with redacted, suppressed
output against repository history and the final staged asset directory. A
scanner failure or finding stops the workflow. This improves release screening
but does not prove that arbitrary personal data is absent from every binary.

## Operation and approval contract

The supported operations are exactly `files`, `browser`, `clipboard`, and
`public_share`. `prepare_audit` validates the operation and scope shape only;
it is configured for automatic approval and must not read content or use the
network. `run_prepared_audit` is configured for `prompt` approval, consumes the
one-time authorization, and is the only step that may perform the selected
bounded operation after the user chooses to continue.

Redacted tool arguments and results may enter the Codex model context. A
rejection, expiry, scope mismatch, or incomplete result stops the operation;
the Skill and local MCP entry point must not guess, repair, or silently retry.

The Windows installer is unsigned, current-user only, offline, and opt-in for
the Skill and MCP integration tasks. It never starts or restarts Codex. The
Skill source and runtime are Apache-2.0; a paid listing cannot remove rights
granted by that license. Reports remain outside installer ownership.

The checked-in lifecycle script is fail-closed and requires `-TestMode`; it
uses an isolated synthetic profile and rejects evidence paths inside user
ownership paths. Clean-machine lifecycle acceptance remains a separate pending
gate and must use a dedicated Windows account or machine, not a normal user's
profile.
For the current candidate it also requires `-Portable_Bundle_Root`: after each
test installation it validates `PAYLOAD-MANIFEST.json`, hashes every installed
payload file, compares the complete installed file set with the portable bundle,
and permits only Inno Setup's `unins000.exe` and `unins000.dat` as installer-
generated files. The evidence records `payload_tree_match` and both payload file
counts. This is local package-integrity evidence, not publisher authenticity.

## Public Release handoff (future, authorization required)

This is an operator runbook for a future, separately authorized handoff. It is
not an instruction to publish the current candidate, whose status remains
`INTEGRATIONS-PREVIEW-NOT-READY` and `NO-GO`.

1. Run the read-only Windows workflow against the exact source SHA selected for
   the candidate. Record the workflow result as current evidence; do not treat
   an earlier run as a fresh verification.
2. On the local Windows build machine, stage exactly the eight allowlisted
   files. The staging CLI must receive `--portable-bundle-root` pointing to the
   exact `dist/AgentGuardian` directory used to create the portable ZIP; it
   compares every decompressed path, size, and SHA-256 before accepting the
   archive. With that binding, the staged `THIRD_PARTY_NOTICES.md` is copied
   from the verified portable bundle; its component inventory is generated from
   the same specifications as `AgentGuardian.cdx.json`, so runtime patch
   versions are not taken from a stale repository snapshot. Review
   `DOWNLOAD-METADATA.json` for the source SHA, version, platform, and file
   records, then recompute and review every entry in `SHA256SUMS`. A Python API
   call without this binding is
   structural validation only and is not public-release evidence.
3. After the source and staged files pass their gates, create tag
   `v0.3.0-preview.1` and a Release titled
   `AgentGuardian 0.3.0 Public Preview (Unsigned)`. This is an unsigned Public
   Preview. The Release must be published, non-draft, and non-prerelease.
4. Upload only the exact allowlist from the profile. Do not upload local
   reports, caches, backups, credentials, tokens, or user data.
5. Verify the fixed unauthenticated link, then compare the downloaded installer
   and all other assets with `SHA256SUMS`.
6. Write a local-only post-publish report containing the verified source SHA,
   asset names and hashes, link result, and remaining evidence gaps. Do not
   commit that report.

The fixed primary link is:

https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe

GitHub API or credential outages, including HTTP 503, do not justify using an
alternate owner or alternate account, force push, token disclosure, or bypassing
repository protection. The operator may wait and retry only through the normal
authorized GitHub path. Alternatively, after revalidating the exact source SHA
and staged files, the operator may complete the already authorized Release
manually in the normal browser or API route. No alternate publication route is
part of this runbook.

The handoff is for Windows 11 x64 and personal non-regulated use only. High-
sensitivity real data is prohibited. It does not establish a production-safety
claim or an enterprise control-plane guarantee. The installer contains the
current GUI, local `AgentGuardianMcp.exe` STDIO MCP, and independent Skill
payload, but Codex and other hosts require explicit user configuration; no
Provider API is silently downloaded or enabled.

The exact eight Release assets are:

- `AgentGuardian-0.3.0-preview.1-windows-x64.zip`
- `AgentGuardian-Setup-0.3.0-preview.1-x64.exe`
- `AgentGuardian-Setup-Windows-x64.exe`
- `AgentGuardian-Skill-0.2.0.zip`
- `DOWNLOAD-METADATA.json`
- `LICENSE`
- `SHA256SUMS`
- `THIRD_PARTY_NOTICES.md`
