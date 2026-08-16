# Personal v1 Release Gate Runbook

This runbook is a release gate, not a production-safety claim.

## Current state

Version `0.1.0` remains `NO-GO`. Store-first is the intended distribution path. Candidate infrastructure does not prove a Store workflow ran, WACK passed, a license was approved, a package was trusted-signed, or a clean machine accepted the product.

The Store candidate workflow is infrastructure only. A Store dispatch is claimed only when external workflow evidence binds it to the exact candidate SHA.

## Freeze the target candidate

1. Freeze product version, Store identity, source, dependencies, and release configuration before the target enters any gate.
2. Commit that state as the target candidate source commit `S`.
3. Any later change to version, Store identity, source, dependencies, or package inputs creates a new candidate and invalidates all prior gate evidence.

The status ledger is a repository template. A later ledger commit may reference `S`; it cannot use its own commit as package evidence. Exact-SHA evidence and digests are generated and retained externally.

## Two-stage same-SHA license flow

### Stage 1: candidate materials

Build the candidate package, source bundle, and SBOM from the same source commit S. Record external hashes and build provenance. The repository license template remains pending and is not authorization.

### Stage 2: external decision and rerun

An authorized person reviews the Stage 1 source bundle, SBOM, Qt terms, and redistribution obligations outside the repository. The decision is stored as a canonical external record bound to the same source commit S and the reviewed SBOM digest.

Rerun the gate against the same source commit S and consume that canonical external record. Approval must not be written back into S. The formal package must be built from S. If a repository commit changes version, identity, source, dependencies, license inputs, or package content, it is a new candidate and every affected gate returns to pending.

## Eight gates

The canonical scopes are `scope`, `local`, `remote`, `supply_chain`, `store`, `independent_machine`, `independent_review`, and `operations`. A gate passes only with an external evidence digest, target source commit, and verification time. Missing evidence stays `pending`; a failed prerequisite is `blocked`.

Required external work includes real WACK, external license and Qt approval, private Store flight, trusted Store signature, two independent machines, independent final review, ordinary support verification, a private security channel, and operations readiness.

Decision remains `NO-GO` while any gate is not `pass`. A `GO` decision does not authorize a public Store rollout, GitHub binary release, deployment, or production-safety wording.
