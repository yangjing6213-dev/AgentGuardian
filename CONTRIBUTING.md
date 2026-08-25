# Contributing

Contributions are welcome when they preserve AgentGuardian's local-first,
user-approved and fail-closed boundaries.

## Before opening a change

- Use synthetic or personal non-regulated test data only.
- Do not add credentials, private paths, customer data, browser databases,
  clipboard contents, generated reports, build output, or vendored binaries.
- Keep OpenAI Provider behavior local-first; do not add a default network or
  Provider API call.
- Keep the GUI, standalone Skill, and local STDIO MCP entry point on the
  shared audit core. Do not duplicate audit logic in an integration layer.

## Local checks

```powershell
python -m pip install -r requirements-dev.lock --require-hashes
python -m pytest -q -p no:cacheprovider
python scripts/run_personal_privacy_acceptance.py --evidence-path .local-audit/privacy.json
python scripts/check_brand_assets.py
python scripts/verify_integrations_preview_profile.py --project-root . --profile release_profiles/integrations_preview.json
python -m compileall -q src scripts tests
```

Do not commit `.local-audit/` or other generated evidence. Explain any skipped
check and keep the diff focused. Never force-push or publish a release from a
contributor branch.
