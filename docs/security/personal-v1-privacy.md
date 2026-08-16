# Personal v1 Privacy

## Data handling

- **Directory local reads:** AgentGuardian performs bounded, read-only static inspection only after the user selects a directory and confirms the personal non-regulated configuration boundary.
- **Browser temporary copy:** an explicitly triggered browser metadata audit copies approved SQLite files and sidecars to a bounded local temporary workspace. It retains fixed metadata counts, not URLs, cookies, passwords, or page text. Cleanup runs on success and failure.
- **Clipboard one-time in-memory read:** the user must trigger and confirm each read. Raw clipboard text is not written to a report, diagnostic, or state file and is not retained after inspection.
- **DPAPI-protected state:** explicit saves protect bounded dispositions and fixed summaries for the current Windows user. State excludes raw matches, scan keys, full paths, and evidence source filenames.
- **Explicit public URL network action:** share reachability runs only for an explicit public URL. It performs a bounded response read and does not send local scan data, reports, credentials, browser data, or clipboard text.

## Retention and user deletion

Reports and diagnostics exist only when the user explicitly creates or retains them at a local destination. AgentGuardian does not upload them by default. The user controls retention and performs user deletion through normal Windows file and application-data controls. Uninstall behavior and residue remain an external acceptance gate, not a completed claim.

Temporary browser copies and transient comparison workspaces are cleaned by the operation. A process or operating-system failure can interrupt cleanup; independent-machine acceptance must inspect residue.

## Unsupported data

Do not process medical, financial, identity or biometric, legally privileged, customer data, state-secret, other regulated, or other high-sensitivity real data. The warning is a supported-use declaration, not a content-classification guarantee.

## Network and provider defaults

There is no telemetry, cloud console, or automatic report upload. OpenAI Provider behavior is local detection and manual guidance only, with no provider API call by default. The share-reachability action is the only declared product network module and requires an explicit public URL.
