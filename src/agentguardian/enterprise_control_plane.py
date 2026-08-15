"""Local enterprise control-plane core with fail-closed boundaries.

This module provides a transactional local registry for tenants, devices,
role bindings, policy versions, revocations, and bounded audit metadata. It
does not expose a network service, authenticate administrators, or verify
digital signatures. Those controls remain separate release gates.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import json
import os
import pathlib
import re
import sqlite3
from typing import Self
import uuid

from .enterprise_policy import (
    PolicyDecision,
    PolicyDecisionStatus,
    canonical_policy_sha256,
    evaluate_capability,
    parse_enterprise_policy,
)
from .enterprise_signing import PolicyVerifier, verify_signed_policy


MAX_DISPLAY_NAME = 120
MAX_METADATA_ITEMS = 20
MAX_METADATA_VALUE = 120
MAX_EVENT_RETENTION = timedelta(days=366)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_EVENT_TYPE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_RBAC_ROLES = frozenset({"admin", "auditor", "operator"})
_FORBIDDEN_METADATA_TERMS = frozenset(
    {"raw", "content", "secret", "token", "password", "cookie", "url", "path", "prompt", "chat"}
)
_CONTROL_PLANE_FILENAME = "control-plane-v1.sqlite3"


def default_control_plane_path() -> pathlib.Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or _is_unc_path(local_app_data):
        raise ValueError("CONTROL_PLANE_DATABASE_UNAVAILABLE")
    root = pathlib.Path(local_app_data)
    if not root.is_absolute():
        raise ValueError("CONTROL_PLANE_DATABASE_UNAVAILABLE")
    return root / "AgentGuardian" / _CONTROL_PLANE_FILENAME


@dataclass(frozen=True, slots=True)
class TenantSummary:
    tenant_id: str
    display_name: str
    device_count: int
    active_device_count: int
    active_policy_count: int
    audit_event_count: int


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    tenant_id: str
    device_id: str
    status: str
    registered_at: str
    revoked_at: str | None


@dataclass(frozen=True, slots=True)
class PolicySummary:
    tenant_id: str
    policy_id: str
    version: int
    device_id: str
    policy_sha256: str
    status: str
    issued_at: str
    expires_at: str


class EnterpriseControlPlane:
    """Manage a local, tenant-scoped administrative state store.

    The store is intentionally local-first. Every read includes the tenant
    key, and policy evaluation requires a registered, non-revoked device and
    subject role. Stored event metadata is bounded and rejects raw-data-like
    field names.
    """

    def __init__(self, database_path: str | pathlib.Path) -> None:
        path = pathlib.Path(database_path)
        if not path.is_absolute() or path.exists() and path.is_symlink():
            raise ValueError("CONTROL_PLANE_DATABASE_INVALID")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
                registered_at TEXT NOT NULL,
                revoked_at TEXT,
                PRIMARY KEY (tenant_id, device_id),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
            );
            CREATE TABLE IF NOT EXISTS role_bindings (
                tenant_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (tenant_id, subject_id, role),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
            );
            CREATE TABLE IF NOT EXISTS policies (
                tenant_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                document BLOB NOT NULL,
                policy_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('active', 'superseded', 'revoked')),
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                provisioned_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, policy_id, version),
                FOREIGN KEY (tenant_id, device_id)
                    REFERENCES devices(tenant_id, device_id)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                FOREIGN KEY (tenant_id, device_id)
                    REFERENCES devices(tenant_id, device_id)
            );
            CREATE INDEX IF NOT EXISTS policies_active_idx
                ON policies (tenant_id, policy_id, status, version DESC);
            CREATE INDEX IF NOT EXISTS audit_expiry_idx
                ON audit_events (tenant_id, expires_at);
            """
        )

    def close(self) -> None:
        self._connection.close()

    def list_tenant_summaries(self) -> tuple[TenantSummary, ...]:
        rows = self._connection.execute(
            "SELECT t.tenant_id, t.display_name, "
            "COUNT(DISTINCT d.device_id) AS device_count, "
            "COUNT(DISTINCT CASE WHEN d.status = 'active' THEN d.device_id END) "
            "AS active_device_count, "
            "(SELECT COUNT(*) FROM policies p WHERE p.tenant_id = t.tenant_id "
            "AND p.status = 'active') AS active_policy_count, "
            "(SELECT COUNT(*) FROM audit_events a WHERE a.tenant_id = t.tenant_id) "
            "AS audit_event_count "
            "FROM tenants t LEFT JOIN devices d ON d.tenant_id = t.tenant_id "
            "GROUP BY t.tenant_id, t.display_name ORDER BY t.tenant_id"
        ).fetchall()
        return tuple(
            TenantSummary(
                tenant_id=row["tenant_id"],
                display_name=row["display_name"],
                device_count=row["device_count"],
                active_device_count=row["active_device_count"],
                active_policy_count=row["active_policy_count"],
                audit_event_count=row["audit_event_count"],
            )
            for row in rows
        )

    def list_device_summaries(self, tenant_id: str) -> tuple[DeviceSummary, ...]:
        tenant_id = _identifier(tenant_id, "tenant_id")
        self._require_tenant(tenant_id)
        rows = self._connection.execute(
            "SELECT tenant_id, device_id, status, registered_at, revoked_at "
            "FROM devices WHERE tenant_id = ? ORDER BY device_id",
            (tenant_id,),
        ).fetchall()
        return tuple(DeviceSummary(**dict(row)) for row in rows)

    def list_policy_summaries(self, tenant_id: str) -> tuple[PolicySummary, ...]:
        tenant_id = _identifier(tenant_id, "tenant_id")
        self._require_tenant(tenant_id)
        rows = self._connection.execute(
            "SELECT tenant_id, policy_id, version, device_id, policy_sha256, status, "
            "issued_at, expires_at FROM policies WHERE tenant_id = ? "
            "ORDER BY policy_id, version DESC",
            (tenant_id,),
        ).fetchall()
        return tuple(PolicySummary(**dict(row)) for row in rows)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def register_tenant(self, tenant_id: str, display_name: str, *, now: datetime) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        display_name = _display_name(display_name)
        timestamp = _timestamp(now)
        try:
            with self._connection:
                self._connection.execute(
                    "INSERT INTO tenants(tenant_id, display_name, created_at) VALUES (?, ?, ?)",
                    (tenant_id, display_name, timestamp),
                )
        except sqlite3.IntegrityError:
            raise ValueError("TENANT_ALREADY_REGISTERED") from None

    def register_device(self, tenant_id: str, device_id: str, *, now: datetime) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        device_id = _identifier(device_id, "device_id")
        timestamp = _timestamp(now)
        self._require_tenant(tenant_id)
        try:
            with self._connection:
                self._connection.execute(
                    "INSERT INTO devices(tenant_id, device_id, status, registered_at) "
                    "VALUES (?, ?, 'active', ?)",
                    (tenant_id, device_id, timestamp),
                )
        except sqlite3.IntegrityError:
            raise ValueError("DEVICE_ALREADY_REGISTERED") from None

    def revoke_device(self, tenant_id: str, device_id: str, *, now: datetime) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        device_id = _identifier(device_id, "device_id")
        self._require_tenant(tenant_id)
        with self._connection:
            result = self._connection.execute(
                "UPDATE devices SET status = 'revoked', revoked_at = ? "
                "WHERE tenant_id = ? AND device_id = ?",
                (_timestamp(now), tenant_id, device_id),
            )
        if result.rowcount != 1:
            raise ValueError("DEVICE_NOT_REGISTERED")

    def grant_role(self, tenant_id: str, subject_id: str, role: str) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        subject_id = _identifier(subject_id, "subject_id")
        if role not in _RBAC_ROLES:
            raise ValueError("RBAC_ROLE_INVALID")
        self._require_tenant(tenant_id)
        with self._connection:
            self._connection.execute(
                "INSERT OR IGNORE INTO role_bindings(tenant_id, subject_id, role) VALUES (?, ?, ?)",
                (tenant_id, subject_id, role),
            )

    def revoke_role(self, tenant_id: str, subject_id: str, role: str) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        subject_id = _identifier(subject_id, "subject_id")
        if role not in _RBAC_ROLES:
            raise ValueError("RBAC_ROLE_INVALID")
        self._require_tenant(tenant_id)
        with self._connection:
            result = self._connection.execute(
                "DELETE FROM role_bindings WHERE tenant_id = ? AND subject_id = ? AND role = ?",
                (tenant_id, subject_id, role),
            )
        if result.rowcount != 1:
            raise ValueError("RBAC_BINDING_NOT_FOUND")

    def provision_policy(self, document: bytes, *, now: datetime) -> str:
        policy = parse_enterprise_policy(document)
        timestamp = _timestamp(now)
        self._require_tenant(policy.tenant_id)
        device = self._connection.execute(
            "SELECT status FROM devices WHERE tenant_id = ? AND device_id = ?",
            (policy.tenant_id, policy.device_id),
        ).fetchone()
        if device is None:
            raise ValueError("DEVICE_NOT_REGISTERED")
        if device["status"] != "active":
            raise ValueError("DEVICE_REVOKED")
        latest = self._connection.execute(
            "SELECT version FROM policies WHERE tenant_id = ? AND policy_id = ? "
            "ORDER BY version DESC LIMIT 1",
            (policy.tenant_id, policy.policy_id),
        ).fetchone()
        if latest is not None and policy.version <= latest["version"]:
            raise ValueError("POLICY_VERSION_ROLLBACK")
        digest = canonical_policy_sha256(document)
        with self._connection:
            self._connection.execute(
                "UPDATE policies SET status = 'superseded' "
                "WHERE tenant_id = ? AND policy_id = ? AND status = 'active'",
                (policy.tenant_id, policy.policy_id),
            )
            self._connection.execute(
                "INSERT INTO policies(tenant_id, policy_id, version, device_id, document, "
                "policy_sha256, status, issued_at, expires_at, provisioned_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                (
                    policy.tenant_id,
                    policy.policy_id,
                    policy.version,
                    policy.device_id,
                    policy.canonical_bytes,
                    digest,
                    policy.issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    policy.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    timestamp,
                ),
            )
        return digest

    def provision_signed_policy(
        self,
        document: bytes,
        *,
        verifier: PolicyVerifier,
        now: datetime,
    ) -> str:
        policy_document = verify_signed_policy(document, verifier)
        return self.provision_policy(policy_document, now=now)

    def revoke_policy(self, tenant_id: str, policy_id: str, version: int, *, now: datetime) -> None:
        tenant_id = _identifier(tenant_id, "tenant_id")
        policy_id = _identifier(policy_id, "policy_id")
        if type(version) is not int or version < 1:
            raise ValueError("POLICY_VERSION_INVALID")
        self._require_tenant(tenant_id)
        _timestamp(now)
        with self._connection:
            result = self._connection.execute(
                "UPDATE policies SET status = 'revoked' WHERE tenant_id = ? "
                "AND policy_id = ? AND version = ?",
                (tenant_id, policy_id, version),
            )
        if result.rowcount != 1:
            raise ValueError("POLICY_NOT_FOUND")

    def evaluate_capability(
        self,
        *,
        tenant_id: str,
        device_id: str,
        subject_id: str,
        policy_id: str,
        capability: str,
        now: datetime,
        high_sensitivity: bool = False,
        confirmation: bool = False,
        sandbox_enforced: bool = False,
    ) -> PolicyDecision:
        tenant_id = _identifier(tenant_id, "tenant_id")
        device_id = _identifier(device_id, "device_id")
        subject_id = _identifier(subject_id, "subject_id")
        policy_id = _identifier(policy_id, "policy_id")
        tenant_decision = self._require_tenant(
            tenant_id,
            decision=True,
            capability=capability,
        )
        if tenant_decision is not None:
            return tenant_decision
        device = self._connection.execute(
            "SELECT status FROM devices WHERE tenant_id = ? AND device_id = ?",
            (tenant_id, device_id),
        ).fetchone()
        if device is None:
            return _denied("device_not_registered", capability)
        if device["status"] != "active":
            return _denied("device_revoked", capability)
        policy = self._connection.execute(
            "SELECT document, policy_sha256, status FROM policies WHERE tenant_id = ? "
            "AND policy_id = ? AND device_id = ? ORDER BY version DESC LIMIT 1",
            (tenant_id, policy_id, device_id),
        ).fetchone()
        if policy is None:
            return _denied("policy_not_provisioned", capability)
        if policy["status"] == "revoked":
            return _denied("policy_revoked", capability, policy["policy_sha256"])
        roles = self._connection.execute(
            "SELECT role FROM role_bindings WHERE tenant_id = ? AND subject_id = ? ORDER BY role",
            (tenant_id, subject_id),
        ).fetchall()
        if not roles:
            return _denied("subject_role_not_granted", capability, policy["policy_sha256"])
        decisions = [
            evaluate_capability(
                bytes(policy["document"]),
                expected_sha256=policy["policy_sha256"],
                role=row["role"],
                capability=capability,
                device_id=device_id,
                now=now,
                high_sensitivity=high_sensitivity,
                confirmation=confirmation,
                sandbox_enforced=sandbox_enforced,
            )
            for row in roles
        ]
        for decision in decisions:
            if decision.allowed:
                return decision
        return decisions[0]

    def record_event(
        self,
        *,
        tenant_id: str,
        device_id: str,
        event_type: str,
        metadata: Mapping[str, object],
        occurred_at: datetime,
        retention: timedelta,
    ) -> str:
        tenant_id = _identifier(tenant_id, "tenant_id")
        device_id = _identifier(device_id, "device_id")
        if type(event_type) is not str or _EVENT_TYPE.fullmatch(event_type) is None:
            raise ValueError("AUDIT_EVENT_TYPE_INVALID")
        occurred = _datetime(occurred_at)
        if type(retention) is not timedelta or retention <= timedelta(0) or retention > MAX_EVENT_RETENTION:
            raise ValueError("AUDIT_RETENTION_INVALID")
        encoded_metadata = _metadata_json(metadata)
        self._require_tenant(tenant_id)
        device = self._connection.execute(
            "SELECT 1 FROM devices WHERE tenant_id = ? AND device_id = ?",
            (tenant_id, device_id),
        ).fetchone()
        if device is None:
            raise ValueError("DEVICE_NOT_REGISTERED")
        event_id = uuid.uuid4().hex
        with self._connection:
            self._connection.execute(
                "INSERT INTO audit_events(event_id, tenant_id, device_id, event_type, "
                "occurred_at, expires_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    tenant_id,
                    device_id,
                    event_type,
                    _timestamp(occurred),
                    _timestamp(occurred + retention),
                    encoded_metadata,
                ),
            )
        return event_id

    def export_events(self, tenant_id: str, *, now: datetime) -> str:
        tenant_id = _identifier(tenant_id, "tenant_id")
        current = _timestamp(now)
        self._require_tenant(tenant_id)
        rows = self._connection.execute(
            "SELECT device_id, event_type, occurred_at, metadata_json FROM audit_events "
            "WHERE tenant_id = ? AND expires_at > ? ORDER BY occurred_at, event_id",
            (tenant_id, current),
        ).fetchall()
        events = [
            {
                "device_id": row["device_id"],
                "event_type": row["event_type"],
                "metadata": json.loads(row["metadata_json"]),
                "occurred_at": row["occurred_at"],
            }
            for row in rows
        ]
        return json.dumps(
            {"schema": 1, "tenant_id": tenant_id, "events": events},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

    def purge_expired_events(self, now: datetime) -> int:
        current = _timestamp(now)
        with self._connection:
            result = self._connection.execute(
                "DELETE FROM audit_events WHERE expires_at <= ?",
                (current,),
            )
        return result.rowcount

    def _require_tenant(
        self,
        tenant_id: str,
        *,
        decision: bool = False,
        capability: str = "unknown",
    ) -> None | PolicyDecision:
        row = self._connection.execute(
            "SELECT 1 FROM tenants WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if row is not None:
            return None
        if decision:
            return _denied("tenant_not_registered", capability)
        raise ValueError("TENANT_NOT_REGISTERED")


def _identifier(value: object, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"CONTROL_PLANE_{name.upper()}_INVALID")
    return value


def _is_unc_path(value: str | pathlib.Path) -> bool:
    text = str(value).replace("/", "\\")
    return text.startswith("\\\\") or text.startswith("//")


def _display_name(value: object) -> str:
    if type(value) is not str or not value or len(value) > MAX_DISPLAY_NAME or any(
        ord(character) < 32 for character in value
    ):
        raise ValueError("TENANT_DISPLAY_NAME_INVALID")
    return value


def _datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("CONTROL_PLANE_TIME_INVALID")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _timestamp(value: object) -> str:
    return _datetime(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _metadata_json(metadata: object) -> str:
    if not isinstance(metadata, Mapping) or len(metadata) > MAX_METADATA_ITEMS:
        raise ValueError("AUDIT_METADATA_INVALID")
    normalized: dict[str, bool | int | str] = {}
    for key, value in metadata.items():
        if type(key) is not str or _IDENTIFIER.fullmatch(key) is None:
            raise ValueError("AUDIT_METADATA_KEY_INVALID")
        terms = set(key.lower().split("_"))
        if terms & _FORBIDDEN_METADATA_TERMS:
            raise ValueError("AUDIT_METADATA_KEY_INVALID")
        if type(value) not in (bool, int, str):
            raise ValueError("AUDIT_METADATA_VALUE_INVALID")
        if type(value) is str and len(value) > MAX_METADATA_VALUE:
            raise ValueError("AUDIT_METADATA_VALUE_INVALID")
        if type(value) is int and not -(2**31) <= value <= 2**31 - 1:
            raise ValueError("AUDIT_METADATA_VALUE_INVALID")
        normalized[key] = value
    return json.dumps(normalized, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _denied(reason: str, capability: str, policy_sha256: str | None = None) -> PolicyDecision:
    return PolicyDecision(
        status=PolicyDecisionStatus.DENIED,
        allowed=False,
        reason=reason,
        policy_sha256=policy_sha256 or "0" * 64,
        integrity_pin_verified=False,
        role="unbound",
        capability=capability,
    )
