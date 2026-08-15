# Enterprise and MCP Control Core

This document records the current product boundary. It is an implementation
contract, not a production-safety claim.

## Offline enterprise policy core

`src/agentguardian/enterprise_policy.py` validates a bounded JSON policy with
schema, tenant/device/policy identifiers, a monotonic version, UTC issue/expiry
times, role capability allowlists, and an explicit high-sensitivity confirmation
requirement.

Every capability decision is fail-closed unless:

1. The policy parses with no duplicate or unknown fields.
2. The operator-provisioned SHA-256 digest pin matches the canonical policy.
3. The policy is active and the role has the requested capability.
4. High-sensitivity confirmation is present when the policy requires it.
5. `mcp_dynamic` additionally has an independently attested sandbox.

The digest pin is an integrity check for a locally provisioned document. The
optional `enterprise_signing.py` module adds an Ed25519 envelope and the
control plane accepts a policy only after the supplied public-key verifier
passes. The cryptography dependency is opt-in and hash-locked; the default
desktop path does not load it. This still does not provide remote policy
distribution. The desktop now provides a local-only control-plane page backed by the same SQLite core for
tenant/device/role registration, offline policy import, device revocation, and
bounded operational summaries. Administrator token authentication is available
only through the separate service boundary below; this is not a remote
administrator console or a tenant-isolated hosted service.

## Dynamic MCP supervisor

`src/agentguardian/mcp_sandbox.py` accepts only a fixed executable plus a
bounded argv tuple and an expected executable SHA-256. It rechecks the file
hash immediately before launch, rejects UNC/reparse executables, forbids shell
command construction, requires explicit confirmation, uses a temporary working
directory, bounds request/output/runtime, and never retains adapter output.

`windows_job_object.py` provides a Windows Job Object launcher that assigns a
child before resume, limits the job to one active process, kills the job on
close, and enforces bounded runtime and output. `windows_appcontainer.py`
creates a unique short-lived AppContainer profile with no declared
capabilities, starts the fixed adapter with the Job Object boundary, and
removes the profile before returning. The local Windows integration test
proves that a system adapter cannot connect to a parent loopback listener and
that the transient profile directory is removed.

The supervisor uses this provider only when the required Windows APIs load and
the provider can complete its fail-closed lifecycle. Unsupported environments,
provider errors, nonzero adapters, timeouts, and output-limit violations do not
fall back to an ordinary child process. A crashing/nonzero adapter returns a
bounded failure, is not automatically restarted, retains no raw output, and
leaves no temporary work directory. Synthetic attestation remains limited to
unit tests. The native Windows path also rechecks the executable SHA-256,
requires a locally trusted embedded Authenticode signature, and requires an
explicit exact-match X.500 publisher-subject allowlist before launch. The
signature check and subject extraction are local and cache-only; no certificate
data is fetched. Native policy requires both an exact X.500 subject allowlist and
an exact signer-certificate DER SHA-256 pin. The validated executable is held
open without write/delete sharing through process creation. Empty or non-matching
allowlists are denied. Unexpected
ordinary exceptions from either native launcher are converted to the fixed
`sandbox_launch_failed` result instead of escaping into the desktop boundary.

## Packaged MCP release evidence

Trusted portable builds require all four external adapter inputs: an absolute
adapter path, its exact SHA-256, an exact X.500 publisher subject, and the exact
DER certificate SHA-256. While holding the source executable without
write/delete sharing, the build verifies the actual bytes, trusted
Authenticode, publisher subject, and certificate pin. It then stages only
`adapters/AgentGuardianMcpAdapter.exe` and `MCP-ADAPTER.json` before generating
payload manifests, checksums, and the deterministic ZIP. Unsigned builds reject
all adapter inputs.

Trusted MSIX acceptance requires an exact source SHA, fresh user state, and a
completed same-identity package upgrade. It resolves the installed adapter
under the package install root, rejects reparse components, and runs the actual
installed bytes through AppContainer plus a Job Object. The bounded acceptance
record binds the source SHA, adapter SHA-256, publisher subject, certificate
SHA-256, completed native sandbox metadata, response byte count, enforced
limits, and `raw_response_retained=false`. The final release gate cross-checks
that record against the packaged manifest and actual packaged adapter bytes.

The manual workflow requires four non-secret repository variables for the
adapter URL, SHA-256, publisher subject, and certificate SHA-256. It permits
only an absolute HTTPS URL, downloads to a fixed new path, and verifies the
hash before building. Organization PFX/password material is scoped only to the
steps that need it. Imported certificates/private keys and the PFX are removed
and residue-checked fail-closed, and the job has a 30-minute outer timeout.

Task 1 and Task 2 passed independent specification and quality/security review
with no remaining Critical or Important issues. This does not complete the
release gate: `windows-mvp-signed.yml` has not been dispatched or passed with a
real organization adapter/certificate. Required repository variables, signing
material, an approved `windows-license-review.json`, real sanitized-sample human
signoff, and independent clean-machine install/upgrade/run/uninstall evidence
remain pending. Current normal GitHub CI for code-bearing SHA
`3febfd57b6841181597bd5476e176710e81a011f` was not revalidated when this
documentation was prepared.

Residual Minor/defense-in-depth items are adapter download redirect/size limits,
the staged-destination lock gap through manifest/ZIP generation, evidence-output
parent-path TOCTOU, streaming/size bounds in acceptance and sandbox hashing, and
synchronous AppX operations bounded only by the outer workflow timeout. Remote
device enrollment, remote policy distribution, and a remote administrator
console remain unimplemented. The current evidence supports local implementation
and synthetic gates only, not production isolation, high-sensitive real-data
readiness, or legal approval.

## Network-neutral enterprise service boundary

`src/agentguardian/enterprise_service.py` provides an in-process request
boundary for tenant-scoped summaries, device/policy metadata, bounded audit
export, signed-policy provisioning, device revocation, and admin-token
rotation. Tokens are prefixed by an opaque token id and only their salted
PBKDF2-HMAC digest is stored. Every request is tenant-bound and role-checked;
policy writes require the Ed25519 verifier.

`EnterpriseLoopbackServer` is an explicit development/test adapter. It is not
started by the desktop, accepts only the literal IPv4 loopback address
`127.0.0.1`, serializes requests over the SQLite control plane, and returns
fixed errors without internal exception details. It has no TLS, remote
enrollment, deployment authentication, rate limiting, key rotation, or
enterprise-console deployment contract. A future remote adapter needs all of
those controls plus independent security review before it can be exposed
beyond the local host.
