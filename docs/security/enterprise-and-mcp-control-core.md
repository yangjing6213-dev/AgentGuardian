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

The portable and current MSIX full-trust launchers do not provide proof of
outbound network denial or process-tree isolation for a child adapter. The
native attestation probe therefore returns no provider and the supervisor
refuses to start an adapter. Synthetic attestation is used only in unit tests.

The remaining implementation gate is a real Windows provider based on
AppContainer or an equivalent network-deny boundary plus Job Object process
tree limits, followed by signed-adapter and clean-machine acceptance. Until
that evidence exists, AgentGuardian provides static MCP detection and a
default-deny supervisor contract, not dynamic MCP execution or production
isolation.
