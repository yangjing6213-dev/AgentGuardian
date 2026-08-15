"""Network-neutral enterprise service boundary.

This module handles authenticated requests in-process and deliberately does
not open a socket. A future HTTP adapter must provide TLS, deployment
authentication, rate limiting, and independent security review before it can
be exposed beyond the host.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re

from .enterprise_control_plane import EnterpriseControlPlane
from .enterprise_signing import PolicyVerifier


MAX_SERVICE_BODY_BYTES = 128 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_ROLES = frozenset({"admin", "auditor", "operator"})


@dataclass(frozen=True, slots=True)
class ServiceRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class ServiceResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class EnterpriseService:
    """Serve tenant-scoped control-plane operations without binding a port."""

    def __init__(
        self,
        control_plane: EnterpriseControlPlane,
        *,
        verifier: PolicyVerifier | None,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        if type(control_plane) is not EnterpriseControlPlane:
            raise ValueError("ENTERPRISE_CONTROL_PLANE_INVALID")
        if not callable(now):
            raise ValueError("ENTERPRISE_CLOCK_INVALID")
        self._control_plane = control_plane
        self._verifier = verifier
        self._now = now

    def handle(self, request: ServiceRequest) -> ServiceResponse:
        if type(request) is not ServiceRequest:
            return _error(400, "REQUEST_INVALID")
        if request.method not in {"GET", "POST", "DELETE"}:
            return _error(405, "METHOD_NOT_ALLOWED")
        if type(request.body) is not bytes or len(request.body) > MAX_SERVICE_BODY_BYTES:
            return _error(413, "REQUEST_BODY_TOO_LARGE")
        normalized_headers = _headers(request.headers)
        if normalized_headers is None:
            return _error(400, "REQUEST_HEADERS_INVALID")
        auth = normalized_headers.get("authorization", "")
        identity = self._authenticate(auth)
        if identity is None:
            return _error(401, "AUTHENTICATION_REQUIRED")
        tenant_id, role = identity
        segments = _path_segments(request.path)
        if segments is None or len(segments) < 3 or segments[:2] != ("v1", "tenants"):
            return _error(404, "ROUTE_NOT_FOUND")
        requested_tenant = segments[2]
        if requested_tenant != tenant_id:
            return _error(403, "TENANT_FORBIDDEN")
        try:
            return self._dispatch(
                request,
                role=role,
                tenant_id=tenant_id,
                segments=segments,
            )
        except ValueError as error:
            code = str(error)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", code):
                code = "REQUEST_REJECTED"
            return _error(403 if code == "ROLE_FORBIDDEN" else 400, code)
        except (OSError, RuntimeError):
            return _error(500, "CONTROL_PLANE_UNAVAILABLE")

    def _authenticate(self, authorization: str) -> tuple[str, str] | None:
        if type(authorization) is not str or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if not token or " " in token:
            return None
        try:
            now = self._now()
        except Exception:
            return None
        return self._control_plane.authenticate_admin_token(token, now=now)

    def _dispatch(
        self,
        request: ServiceRequest,
        *,
        role: str,
        tenant_id: str,
        segments: tuple[str, ...],
    ) -> ServiceResponse:
        tail = segments[3:]
        if not tail and request.method == "GET":
            return self._summary(tenant_id, role)
        if tail == ("summary",) and request.method == "GET":
            return self._summary(tenant_id, role)
        if tail == ("devices",) and request.method == "GET":
            self._require_role(role, "read")
            devices = self._control_plane.list_device_summaries(tenant_id)
            return _json_response(200, {"schema": 1, "devices": [_asdict(device) for device in devices]})
        if tail == ("policies",) and request.method == "GET":
            self._require_role(role, "read")
            policies = self._control_plane.list_policy_summaries(tenant_id)
            return _json_response(200, {"schema": 1, "policies": [_asdict(policy) for policy in policies]})
        if tail == ("audit",) and request.method == "GET":
            self._require_role(role, "read")
            return _json_response(
                200,
                json.loads(self._control_plane.export_events(tenant_id, now=self._now())),
            )
        if tail == ("policies",) and request.method == "POST":
            self._require_role(role, "admin")
            if self._verifier is None:
                raise ValueError("POLICY_SIGNATURE_REQUIRED")
            digest = self._control_plane.provision_signed_policy(
                request.body,
                verifier=self._verifier,
                now=self._now(),
            )
            return _json_response(201, {"schema": 1, "policy_sha256": digest})
        if len(tail) == 2 and tail[0] == "devices" and request.method == "DELETE":
            self._require_role(role, "admin")
            device_id = _identifier(tail[1], "device_id")
            self._control_plane.revoke_device(tenant_id, device_id, now=self._now())
            return _json_response(200, {"schema": 1, "device_id": device_id, "status": "revoked"})
        if tail == ("admin-tokens",) and request.method == "POST":
            self._require_role(role, "admin")
            document = _request_json(request.body)
            token_role = document.get("role")
            expires_at = _parse_timestamp(document.get("expires_at"))
            if token_role not in _ROLES:
                raise ValueError("RBAC_ROLE_INVALID")
            token_id, token = self._control_plane.issue_admin_token(
                tenant_id,
                token_role,
                now=self._now(),
                expires_at=expires_at,
            )
            return _json_response(201, {"schema": 1, "token_id": token_id, "token": token})
        if len(tail) == 2 and tail[0] == "admin-tokens" and request.method == "DELETE":
            self._require_role(role, "admin")
            token_id = _identifier(tail[1], "token_id")
            self._control_plane.revoke_admin_token(tenant_id, token_id, now=self._now())
            return _json_response(200, {"schema": 1, "token_id": token_id, "status": "revoked"})
        return _error(404, "ROUTE_NOT_FOUND")

    def _summary(self, tenant_id: str, role: str) -> ServiceResponse:
        self._require_role(role, "summary")
        summaries = [
            summary
            for summary in self._control_plane.list_tenant_summaries()
            if summary.tenant_id == tenant_id
        ]
        if not summaries:
            raise ValueError("TENANT_NOT_REGISTERED")
        return _json_response(200, {"schema": 1, "tenants": [_asdict(summaries[0])]})

    @staticmethod
    def _require_role(role: str, operation: str) -> None:
        allowed = {
            "summary": {"admin", "auditor", "operator"},
            "read": {"admin", "auditor"},
            "admin": {"admin"},
        }
        if role not in allowed[operation]:
            raise ValueError("ROLE_FORBIDDEN")


def _headers(headers: Mapping[str, str]) -> dict[str, str] | None:
    if not isinstance(headers, Mapping) or len(headers) > 32:
        return None
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        if type(key) is not str or type(value) is not str or len(key) > 128 or len(value) > 8192:
            return None
        folded = key.casefold()
        if folded in normalized:
            return None
        normalized[folded] = value
    return normalized


def _path_segments(path: str) -> tuple[str, ...] | None:
    if type(path) is not str or not path.startswith("/") or "?" in path or "#" in path:
        return None
    raw = tuple(path.split("/"))[1:]
    if not raw or any(_IDENTIFIER.fullmatch(segment) is None for segment in raw):
        return None
    return raw


def _identifier(value: object, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"CONTROL_PLANE_{name.upper()}_INVALID")
    return value


def _request_json(body: bytes) -> dict[str, object]:
    if not body:
        raise ValueError("REQUEST_BODY_INVALID")
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("REQUEST_BODY_INVALID") from None
    if not isinstance(value, dict):
        raise ValueError("REQUEST_BODY_INVALID")
    return value


def _parse_timestamp(value: object) -> datetime:
    if type(value) is not str:
        raise ValueError("CONTROL_PLANE_TIME_INVALID")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError("CONTROL_PLANE_TIME_INVALID") from None
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("REQUEST_BODY_INVALID")
        result[key] = value
    return result


def _asdict(value: object) -> dict[str, object]:
    if hasattr(value, "__dataclass_fields__"):
        return {name: getattr(value, name) for name in value.__dataclass_fields__}
    raise ValueError("SERVICE_SERIALIZATION_INVALID")


def _json_response(status: int, value: object) -> ServiceResponse:
    try:
        body = (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError):
        return _error(500, "SERVICE_SERIALIZATION_INVALID")
    return ServiceResponse(
        status=status,
        body=body,
        headers={
            "Cache-Control": "no-store",
            "Content-Type": "application/json; charset=utf-8",
        },
    )


def _error(status: int, code: str) -> ServiceResponse:
    return _json_response(status, {"schema": 1, "error": code})
