"""Offline enterprise policy validation with fail-closed capability decisions.

This module is an enforcement core, not a cloud control plane.  The digest pin
is an integrity check for a policy already provisioned by an operator; it is
not a substitute for a trusted signing key or an enterprise service.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re


MAX_POLICY_BYTES = 64 * 1024
POLICY_SCHEMA = 1
POLICY_CAPABILITIES = frozenset(
    {
        "local_scan",
        "browser_metadata",
        "clipboard_once",
        "share_verify",
        "fixed_remediation",
        "mcp_dynamic",
    }
)
_POLICY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_POLICY_KEYS = frozenset(
    {
        "schema",
        "version",
        "policy_id",
        "tenant_id",
        "device_id",
        "issued_at",
        "expires_at",
        "roles",
        "high_sensitivity_requires_confirmation",
    }
)


class PolicyDecisionStatus(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class EnterprisePolicy:
    schema: int
    version: int
    policy_id: str
    tenant_id: str
    device_id: str
    issued_at: datetime
    expires_at: datetime
    roles: tuple[tuple[str, tuple[str, ...]], ...]
    high_sensitivity_requires_confirmation: bool
    canonical_bytes: bytes

    def capabilities_for(self, role: str) -> tuple[str, ...]:
        for role_name, capabilities in self.roles:
            if role_name == role:
                return capabilities
        return ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    status: PolicyDecisionStatus
    allowed: bool
    reason: str
    policy_sha256: str
    integrity_pin_verified: bool
    role: str
    capability: str


def parse_enterprise_policy(document: bytes) -> EnterprisePolicy:
    if type(document) is not bytes or not document or len(document) > MAX_POLICY_BYTES:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    try:
        parsed = json.loads(document.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("POLICY_DOCUMENT_INVALID") from None
    if type(parsed) is not dict or set(parsed) != _POLICY_KEYS:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    if parsed.get("schema") != POLICY_SCHEMA:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    version = parsed.get("version")
    if type(version) is not int or version < 1:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    policy_id = _policy_id(parsed.get("policy_id"), "policy_id")
    tenant_id = _policy_id(parsed.get("tenant_id"), "tenant_id")
    device_id = _policy_id(parsed.get("device_id"), "device_id")
    issued_at = _parse_timestamp(parsed.get("issued_at"))
    expires_at = _parse_timestamp(parsed.get("expires_at"))
    if expires_at <= issued_at:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    roles = _parse_roles(parsed.get("roles"))
    confirmation = parsed.get("high_sensitivity_requires_confirmation")
    if type(confirmation) is not bool:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    canonical = {
        "device_id": device_id,
        "expires_at": _format_timestamp(expires_at),
        "high_sensitivity_requires_confirmation": confirmation,
        "issued_at": _format_timestamp(issued_at),
        "policy_id": policy_id,
        "roles": {role: list(capabilities) for role, capabilities in roles},
        "schema": POLICY_SCHEMA,
        "tenant_id": tenant_id,
        "version": version,
    }
    canonical_bytes = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return EnterprisePolicy(
        schema=POLICY_SCHEMA,
        version=version,
        policy_id=policy_id,
        tenant_id=tenant_id,
        device_id=device_id,
        issued_at=issued_at,
        expires_at=expires_at,
        roles=roles,
        high_sensitivity_requires_confirmation=confirmation,
        canonical_bytes=canonical_bytes,
    )


def canonical_policy_sha256(document: bytes) -> str:
    policy = parse_enterprise_policy(document)
    return hashlib.sha256(policy.canonical_bytes).hexdigest()


def evaluate_capability(
    document: bytes,
    *,
    expected_sha256: str,
    role: str,
    capability: str,
    device_id: str,
    now: datetime,
    high_sensitivity: bool = False,
    confirmation: bool = False,
    sandbox_enforced: bool = False,
    last_seen_version: int | None = None,
) -> PolicyDecision:
    if capability not in POLICY_CAPABILITIES:
        raise ValueError("POLICY_CAPABILITY_INVALID")
    role = _policy_id(role, "role")
    device_id = _policy_id(device_id, "device_id")
    if type(expected_sha256) is not str or _SHA256.fullmatch(expected_sha256) is None:
        raise ValueError("POLICY_PIN_INVALID")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("POLICY_TIME_INVALID")
    policy = parse_enterprise_policy(document)
    digest = hashlib.sha256(policy.canonical_bytes).hexdigest()
    base = {
        "policy_sha256": digest,
        "integrity_pin_verified": digest == expected_sha256,
        "role": role,
        "capability": capability,
    }
    if digest != expected_sha256:
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="policy_pin_mismatch",
            **base,
        )
    now_utc = now.astimezone(timezone.utc)
    if now_utc < policy.issued_at:
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="policy_not_yet_active",
            **base,
        )
    if now_utc >= policy.expires_at:
        return PolicyDecision(
            status=PolicyDecisionStatus.EXPIRED,
            allowed=False,
            reason="policy_expired",
            **base,
        )
    if device_id != policy.device_id:
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="device_not_bound",
            **base,
        )
    if (
        last_seen_version is not None
        and (type(last_seen_version) is not int or last_seen_version < 0)
    ):
        raise ValueError("POLICY_VERSION_INVALID")
    if last_seen_version is not None and policy.version <= last_seen_version:
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="policy_version_rollback",
            **base,
        )
    if capability not in policy.capabilities_for(role):
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="role_not_granted",
            **base,
        )
    if capability == "mcp_dynamic" and not sandbox_enforced:
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="mcp_isolation_required",
            **base,
        )
    if policy.high_sensitivity_requires_confirmation and high_sensitivity and not confirmation:
        return PolicyDecision(
            status=PolicyDecisionStatus.DENIED,
            allowed=False,
            reason="high_sensitivity_confirmation_required",
            **base,
        )
    return PolicyDecision(
        status=PolicyDecisionStatus.ALLOWED,
        allowed=True,
        reason="policy_granted",
        **base,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate keys")
    return dict(pairs)


def _policy_id(value: object, name: str) -> str:
    if type(value) is not str or _POLICY_ID.fullmatch(value) is None:
        raise ValueError("POLICY_DOCUMENT_INVALID" if name != "role" else "POLICY_ROLE_INVALID")
    return value


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("POLICY_DOCUMENT_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("POLICY_DOCUMENT_INVALID") from None
    return parsed


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_roles(value: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if type(value) is not dict or not value:
        raise ValueError("POLICY_DOCUMENT_INVALID")
    roles: list[tuple[str, tuple[str, ...]]] = []
    for role, capabilities in value.items():
        _policy_id(role, "role")
        if type(capabilities) is not list or not capabilities:
            raise ValueError("POLICY_DOCUMENT_INVALID")
        if any(type(capability) is not str for capability in capabilities):
            raise ValueError("POLICY_CAPABILITY_INVALID")
        if len(set(capabilities)) != len(capabilities) or any(
            capability not in POLICY_CAPABILITIES for capability in capabilities
        ):
            raise ValueError("POLICY_CAPABILITY_INVALID")
        roles.append((role, tuple(capabilities)))
    return tuple(sorted(roles))
