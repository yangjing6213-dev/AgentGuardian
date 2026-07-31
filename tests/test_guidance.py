import ast
import hashlib
import hmac
import re
from collections import Counter
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from agentguardian import domain
from agentguardian.guidance import guidance_for

ASSET_REF = hmac.new(
    b"synthetic scan key for guidance tests",
    b"synthetic asset",
    hashlib.sha256,
).hexdigest()


class HostileValue:
    def __init__(self) -> None:
        object.__setattr__(self, "calls", [])

    def __getattribute__(self, name: str) -> object:
        calls = object.__getattribute__(self, "calls")
        calls.append(f"__getattribute__:{name}")
        raise AssertionError("hostile __getattribute__ hook called")

    def __hash__(self) -> int:
        calls = object.__getattribute__(self, "calls")
        calls.append("__hash__")
        raise AssertionError("hostile __hash__ hook called")

    def __eq__(self, other: object) -> bool:
        calls = object.__getattribute__(self, "calls")
        calls.append("__eq__")
        raise AssertionError("hostile __eq__ hook called")

    def __bool__(self) -> bool:
        calls = object.__getattribute__(self, "calls")
        calls.append("__bool__")
        raise AssertionError("hostile __bool__ hook called")


def test_public_credential_guidance_is_manual_ordered_and_immutable() -> None:
    plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider="openai",
    )

    assert isinstance(plan, domain.RemediationPlan)
    assert plan.mode is domain.RemediationMode.MANUAL
    assert "revoke" in plan.steps[0].lower()
    assert "openai" in plan.steps[0].lower()
    assert "rotate" in plan.steps[1].lower()
    assert "usage records" in plan.steps[2].lower()
    assert "read-only" in plan.steps[3].lower()
    with pytest.raises(FrozenInstanceError):
        plan.mode = domain.RemediationMode.MANUAL  # type: ignore[misc]


@pytest.mark.parametrize("rule_id", ("OPENAI_API_KEY", "GENERIC_API_KEY"))
def test_api_key_rules_use_credential_guidance(rule_id: str) -> None:
    plan = guidance_for(rule_id, ASSET_REF, provider="github")

    assert "revoke" in plan.steps[0].lower()
    assert "github" in plan.steps[0].lower()
    assert "rotate" in plan.steps[1].lower()


def test_mcp_guidance_disables_service_before_restricting_capabilities() -> None:
    plan = guidance_for("MCP_DANGEROUS_COMBINATION", ASSET_REF)

    assert "disable" in plan.steps[0].lower()
    assert "shell" in plan.steps[1].lower()
    assert "filesystem write" in plan.steps[2].lower()
    assert "network" in plan.steps[3].lower()


@pytest.mark.parametrize(
    "rule_id",
    ("EMAIL_ADDRESS", "CN_MOBILE_PHONE", "CUSTOM_KEYWORD", "PII_EXPOSURE"),
)
def test_pii_and_keyword_guidance_uses_original_application(rule_id: str) -> None:
    plan = guidance_for(rule_id, ASSET_REF)

    assert "business necessity" in plan.steps[0].lower()
    assert "original application" in plan.steps[1].lower()
    assert "delete or redact" in plan.steps[1].lower()
    assert len(plan.steps) == 2
    assert "audit" not in " ".join(plan.steps).lower()
    assert "read-only audit" in " ".join(plan.verification_steps).lower()


@pytest.mark.parametrize(
    "rule_id",
    (None, 17, b"PRIVATE_RULE_MARKER", Path("private-rule-marker")),
)
def test_rule_id_rejects_non_strings_without_echoing_input(rule_id: object) -> None:
    with pytest.raises(TypeError) as captured:
        guidance_for(rule_id, ASSET_REF)  # type: ignore[arg-type]

    error = captured.value
    assert error.__class__ is TypeError
    assert str(error) == ""
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "PRIVATE_RULE_MARKER" not in repr(error)
    assert "private-rule-marker" not in repr(error)


@pytest.mark.parametrize(
    "rule_id",
    (
        "",
        "lowercase",
        "1_STARTS_WITH_DIGIT",
        "HAS-HYPHEN",
        "HTTPS://PRIVATE.EXAMPLE/RULE",
        "C:\\PRIVATE\\RULE",
        "C:/PRIVATE/RULE",
        "/PRIVATE/RULE",
        "CONTROL\nRULE",
        "A" * 81,
        "规则",
    ),
)
def test_rule_id_rejects_unsafe_values_with_fixed_error(rule_id: str) -> None:
    with pytest.raises(ValueError) as captured:
        guidance_for(rule_id, ASSET_REF)

    error = captured.value
    assert error.__class__ is ValueError
    assert str(error) == ""
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "PRIVATE.EXAMPLE" not in repr(error)
    assert "PRIVATE\\RULE" not in repr(error)
    assert "CONTROL" not in repr(error)


def test_hostile_rule_id_is_rejected_without_invoking_hooks() -> None:
    rule_id = HostileValue()

    with pytest.raises(TypeError):
        guidance_for(rule_id, ASSET_REF)  # type: ignore[arg-type]

    assert object.__getattribute__(rule_id, "calls") == []


def test_hostile_provider_becomes_generic_without_invoking_hooks() -> None:
    provider = HostileValue()

    plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider=provider,  # type: ignore[arg-type]
    )
    generic_plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider="generic",
    )

    assert plan.steps == generic_plan.steps
    assert object.__getattribute__(provider, "calls") == []


@pytest.mark.parametrize("provider", (None, 17, Path("private-provider"), []))
def test_non_string_provider_becomes_generic(provider: object) -> None:
    plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider=provider,  # type: ignore[arg-type]
    )
    generic_plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider="generic",
    )

    assert plan.steps == generic_plan.steps


def test_rule_id_validation_runs_before_provider_handling() -> None:
    with pytest.raises(TypeError) as captured:
        guidance_for(
            Path("private-rule-marker"),  # type: ignore[arg-type]
            ASSET_REF,
            provider=[],  # type: ignore[arg-type]
        )

    assert captured.value.__class__ is TypeError
    assert str(captured.value) == ""


@pytest.mark.parametrize("rule_id", ("A", "UNKNOWN_RULE_1", "Z" * 80))
def test_unknown_safe_rule_ids_return_generic_plans(rule_id: str) -> None:
    plan = guidance_for(rule_id, ASSET_REF)

    assert plan.rule_id == rule_id
    assert plan.mode is domain.RemediationMode.MANUAL
    assert "owner reviews the finding" in plan.steps[0].lower()


def test_unknown_provider_and_rule_use_safe_generic_text() -> None:
    untrusted_provider = "https://attacker.invalid/run synthetic-command"

    unknown_provider_plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider=untrusted_provider,
    )
    generic_provider_plan = guidance_for(
        "PUBLIC_ACTIVE_CREDENTIAL",
        ASSET_REF,
        provider="generic",
    )
    unknown_rule_plan = guidance_for("UNRECOGNIZED_RULE", ASSET_REF)

    assert unknown_provider_plan.steps == generic_provider_plan.steps
    assert untrusted_provider not in " ".join(unknown_provider_plan.steps)
    assert unknown_rule_plan.rule_id == "UNRECOGNIZED_RULE"
    assert unknown_rule_plan.mode is domain.RemediationMode.MANUAL
    assert unknown_rule_plan.steps


def test_plan_uses_opaque_asset_ref_and_requires_domain_validation() -> None:
    plan = guidance_for("UNRECOGNIZED_RULE", ASSET_REF)

    assert plan.asset_ref == ASSET_REF
    assert not hasattr(plan, "target_path")
    with pytest.raises(ValueError, match="64-character lowercase HMAC"):
        guidance_for("UNRECOGNIZED_RULE", "not-an-hmac")
    with pytest.raises(TypeError):
        guidance_for("UNRECOGNIZED_RULE", Path("synthetic-target"))  # type: ignore[arg-type]


def test_all_guidance_branches_emit_safe_text_and_read_only_verification() -> None:
    plans = (
        guidance_for("PUBLIC_ACTIVE_CREDENTIAL", ASSET_REF, provider="anthropic"),
        guidance_for("MCP_DANGEROUS_COMBINATION", ASSET_REF),
        guidance_for("EMAIL_ADDRESS", ASSET_REF),
        guidance_for("UNRECOGNIZED_RULE", ASSET_REF),
    )

    for plan in plans:
        output = (*plan.steps, *plan.verification_steps)
        for value in output:
            assert "://" not in value
            assert "/" not in value
            assert "\\" not in value
            assert re.search(r"[A-Za-z]:[\\/]", value) is None
            assert value.isprintable()
        assert "read-only audit" in " ".join(plan.verification_steps).lower()


def test_verification_status_remains_outside_remediation_plan() -> None:
    plan = guidance_for("UNRECOGNIZED_RULE", ASSET_REF)

    assert not hasattr(plan, "verification_status")
    assert not hasattr(plan, "verification_result")

    result = domain.VerificationResult(
        domain.VerificationStatus.NOT_PERFORMED,
        plan.verification_steps,
    )

    assert result.status is domain.VerificationStatus.NOT_PERFORMED
    assert result.notes == plan.verification_steps
    with pytest.raises(ValueError, match="not performed"):
        domain.VerificationResult(
            "not_performed",  # type: ignore[arg-type]
            plan.verification_steps,
        )


def _call_path(function: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(function, ast.Attribute):
        parts.append(function.attr)
        function = function.value
    if not isinstance(function, ast.Name):
        pytest.fail(f"indirect call is not allowed: {ast.dump(function)}")
    return ".".join((function.id, *reversed(parts)))


def test_guidance_module_uses_only_exact_imports_and_calls() -> None:
    module_path = Path(__file__).parents[1] / "src" / "agentguardian" / "guidance.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))

    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Import)]
    imports_from = [
        node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    ]
    assert len(imports_from) == 1
    assert imports_from[0].module == "agentguardian"
    assert imports_from[0].level == 0
    assert [(alias.name, alias.asname) for alias in imports_from[0].names] == [
        ("domain", None)
    ]

    call_paths = Counter(
        _call_path(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    )
    assert call_paths == Counter(
        {
            "_PROVIDER_LABELS.get": 1,
            "rule_id.endswith": 1,
            "domain.RemediationPlan": 1,
            "type": 2,
        }
    )

    source = ast.unparse(tree)
    assert "VerificationResult" not in source


def test_guidance_source_string_constants_are_safe() -> None:
    module_path = Path(__file__).parents[1] / "src" / "agentguardian" / "guidance.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    constants = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert constants
    for value in constants:
        assert "://" not in value
        assert "/" not in value
        assert "\\" not in value
        assert re.search(r"[A-Za-z]:[\\/]", value) is None
        assert value.isprintable()
