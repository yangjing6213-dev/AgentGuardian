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

The digest pin is an integrity check for a locally provisioned document. It is
not a digital signature, device registration, tenant service, administrator
console, or remote policy distribution mechanism. Those remain release gates.

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
fall back to an ordinary child process. Synthetic attestation remains limited
to unit tests.

This does not complete the release gate. Signed adapters, packaged-adapter
filesystem accessibility, crash/restart acceptance, clean-machine install and
uninstall evidence, device registration, remote policy distribution, and an
administrator console remain outstanding. The current evidence supports a
locally verified Windows MVP boundary, not production isolation or processing
of highly sensitive real data.
