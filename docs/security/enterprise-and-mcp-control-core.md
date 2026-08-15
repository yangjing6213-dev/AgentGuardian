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
unit tests. The native Windows path also rechecks the executable SHA-256 and
requires a locally trusted embedded Authenticode signature before launch. The
signature check is cache-only and does not fetch certificate data; a missing or
invalid signature is denied.

This does not complete the release gate. An organization publisher allowlist,
packaged-adapter filesystem accessibility, packaged crash/restart acceptance, clean-machine install and
uninstall evidence, remote device registration, remote policy distribution,
remote administrator authentication, and an administrator console remain outstanding.
The current evidence supports a locally verified Windows MVP boundary, not
production isolation or processing of highly sensitive real data.

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
