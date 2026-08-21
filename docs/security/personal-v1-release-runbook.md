# Personal v1 Release Gate Runbook

This runbook is a release gate, not a production-safety claim.

## Current state

The only active delivery and governance route is `personal_exe_private_beta`: a traditional unsigned offline EXE for known testers. Frozen candidate `8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6` has current GitHub CI, native unsigned-installer lifecycle, and independent-review evidence. Version `0.2.0-beta.1` remains `PRIVATE-BETA-NOT-READY` because local secret-scan evidence, external license and Qt approval, two-machine acceptance, and operations/security readiness are pending; formal public release remains `NO-GO`. Current evidence does not prove license approval, independent-machine acceptance, or operations readiness.

An unsigned installer may trigger Unknown Publisher or SmartScreen warnings. Any private handoff must include an independently retained SHA-256 bound to the exact candidate source commit.

An artifact uploaded by this public repository's GitHub Actions workflow is not an access-controlled private distribution channel. `Private beta` is a maturity label for the known-tester scope, not a confidentiality claim. A restricted handoff requires a separate controlled channel. OpenAI Provider behavior remains local adaptation, detection, and manual guidance only; the runtime must not call OpenAI or another provider API by default.

## Freeze the target candidate

1. Freeze product versions, installer identity, source, dependencies, package inputs, and release configuration before the target enters any gate.
2. Commit that state as the target candidate source commit `S`.
3. Any later change to a version, installer identity, source, dependency, or package input creates a new candidate and invalidates all prior gate evidence.

The status ledger is a repository template. A later ledger commit may reference `S`; it cannot use its own commit as package evidence. Exact-SHA evidence and digests are generated and retained externally.

## Two-stage same-SHA license flow

### Stage 1: candidate materials

Build the candidate package, source bundle, and SBOM from the same source commit S. Record external hashes and build provenance. The repository license template remains pending and is not authorization.

### Stage 2: external decision and rerun

An authorized person reviews the Stage 1 source bundle, SBOM, Qt terms, and redistribution obligations outside the repository. The decision is stored as a canonical external record bound to the same source commit S and the reviewed SBOM digest.

Rerun the gate against the same source commit S and consume that canonical external record. Approval must not be written back into S. The formal package must be built from S. If a repository commit changes version, identity, source, dependencies, license inputs, or package content, it is a new candidate and every affected gate returns to pending.

## Eight gates

The canonical scopes are `scope`, `local`, `remote`, `supply_chain`, `installer`, `independent_machine`, `independent_review`, and `operations`. A gate passes only with an external evidence digest, target source commit, and verification time. Missing evidence stays `pending`; a failed prerequisite is `blocked`.

Required external work includes verifying the pinned Inno Setup download, external license and Qt review, building and hashing the exact unsigned installer, install/run/uninstall checks on two independent clean machines, independent final review, ordinary support verification, a private security channel, and operations readiness.

Private beta remains `PRIVATE-BETA-NOT-READY` while any gate is not `pass`. `PRIVATE-BETA-READY` authorizes only bounded testing by known testers within the documented unsupported-data boundary. Formal public release remains `NO-GO`; no private-beta decision authorizes public binary release, deployment, high-sensitivity real data, or production-safety wording. Retiring the historical Store/MSIX/WACK/Partner Center route is governance cleanup, not readiness evidence.
