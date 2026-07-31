from agentguardian import domain

_PROVIDER_LABELS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "github": "GitHub",
    "generic": "generic provider",
}
_RULE_ID_START_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_RULE_ID_CHARACTERS = _RULE_ID_START_CHARACTERS + "0123456789_"
_VERIFICATION_STEPS = (
    "Rerun the read-only audit and have a reviewer compare the new findings.",
)


def guidance_for(
    rule_id: str,
    asset_ref: str,
    *,
    provider: str | None = None,
) -> domain.RemediationPlan:
    if type(rule_id) is not str:
        raise TypeError
    if type(provider) is not str:
        provider = "generic"
    if (
        not rule_id
        or rule_id[80:]
        or rule_id[0] not in _RULE_ID_START_CHARACTERS
    ):
        raise ValueError
    for character in rule_id[1:]:
        if character not in _RULE_ID_CHARACTERS:
            raise ValueError

    provider_label = _PROVIDER_LABELS.get(provider, _PROVIDER_LABELS["generic"])
    if rule_id == "PUBLIC_ACTIVE_CREDENTIAL" or rule_id.endswith("_API_KEY"):
        steps = (
            f"Revoke the exposed {provider_label} credential before any other action.",
            "Rotate the credential and manually update authorized dependent applications.",
            "Review credential usage records for unauthorized activity.",
            "Perform a read-only review of the credential configuration.",
        )
    elif rule_id == "MCP_DANGEROUS_COMBINATION":
        steps = (
            "Disable the affected MCP service before making configuration changes.",
            "Restrict shell access to the minimum required commands.",
            "Remove filesystem write access unless it is strictly required.",
            "Restrict network access to the minimum required destinations.",
        )
    elif rule_id in {"EMAIL_ADDRESS", "CN_MOBILE_PHONE", "CUSTOM_KEYWORD"} or (
        "PII" in rule_id or "KEYWORD" in rule_id
    ):
        steps = (
            "Confirm the business necessity for retaining the flagged data.",
            "Use the original application to manually delete or redact the data.",
        )
    else:
        steps = (
            "Pause use of the affected asset until an owner reviews the finding.",
            "Confirm whether the flagged data or capability is required.",
            "Use the original application controls to remove data or reduce access manually.",
        )

    return domain.RemediationPlan(
        rule_id=rule_id,
        asset_ref=asset_ref,
        mode=domain.RemediationMode.MANUAL,
        steps=steps,
        verification_steps=_VERIFICATION_STEPS,
    )
