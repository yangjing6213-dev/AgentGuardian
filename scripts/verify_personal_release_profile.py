"""Verify the bounded Personal EXE private-beta source and payload profile."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

MAX_PROFILE_BYTES = 64 * 1024
MAX_RUNTIME_SOURCE_BYTES = 256 * 1024
_MAX_RUNTIME_AGGREGATE_BYTES = 8 * 1024 * 1024
_MAX_WORKFLOW_FILE_BYTES = 256 * 1024
_MAX_WORKFLOW_AGGREGATE_BYTES = 2 * 1024 * 1024
_MAX_DOCUMENT_FILE_BYTES = 512 * 1024
_MAX_DOCUMENT_AGGREGATE_BYTES = 4 * 1024 * 1024
_MAX_TRAVERSAL_ENTRIES = 20_000
_MAX_TRAVERSAL_DEPTH = 64
_MAX_ARRAY_ITEMS = 128
_MAX_VALUE_LENGTH = 256
_MAX_RUNTIME_AST_NODES = 16_384
_ROOT_PROJECT_EXCLUSIONS = frozenset(
    {
        ".analysis",
        ".git",
        ".local-audit",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".superpowers",
        ".tmp",
        ".tox",
        ".venv",
        ".worktrees",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "target",
        "venv",
    }
)
_BASE_PROFILE_KEYS = frozenset(
    {
        "active_document_paths",
        "declared_network_modules",
        "forbidden_document_promises",
        "forbidden_payload_globs",
        "forbidden_runtime_imports",
        "forbidden_runtime_member_prefixes",
        "forbidden_runtime_members",
        "forbidden_runtime_names",
        "forbidden_runtime_symbols",
        "forbidden_source_globs",
        "forbidden_workflow_tokens",
        "name",
        "network_import_families",
        "required_document_markers",
        "required_source_paths",
        "schema",
    }
)
_PRIVATE_BETA_IDENTITY = MappingProxyType(
    {
        "architecture": "x64",
        "channel": "personal_exe_private_beta",
        "inno_setup_asset": "innosetup-7.0.2-x64.exe",
        "inno_setup_iscc_sha256": (
            "0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d"
        ),
        "inno_setup_release_tag": "is-7_0_2",
        "inno_setup_sha256": (
            "5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1"
        ),
        "inno_setup_version": "7.0.2",
        "install_directory": r"{localappdata}\Programs\AgentGuardian",
        "installer_app_id": "{7A76221A-CFA0-4860-B250-7083B736F3FB}",
        "installer_filename": "AgentGuardian-Setup-0.2.0-beta.1-x64.exe",
        "name": "personal_exe_private_beta",
        "product_version": "0.2.0-beta.1",
        "python_package_version": "0.2.0b1",
        "schema": 2,
        "windows_file_version": "0.2.0.1",
    }
)
_PRIVATE_BETA_PROFILE_KEYS = _BASE_PROFILE_KEYS | frozenset(
    {
        "architecture",
        "channel",
        "forbidden_installer_capabilities",
        "inno_setup_asset",
        "inno_setup_iscc_sha256",
        "inno_setup_release_tag",
        "inno_setup_sha256",
        "inno_setup_version",
        "install_directory",
        "installer_app_id",
        "installer_filename",
        "package_input_paths",
        "product_version",
        "python_package_version",
        "windows_file_version",
    }
)
_BASE_ARRAY_KEYS = _BASE_PROFILE_KEYS - {"name", "schema"}
_PRIVATE_BETA_ARRAY_KEYS = _BASE_ARRAY_KEYS | frozenset(
    {"forbidden_installer_capabilities", "package_input_paths"}
)
_COMMON_PATH_ARRAY_KEYS = frozenset(
    {
        "active_document_paths",
        "declared_network_modules",
        "forbidden_payload_globs",
        "forbidden_source_globs",
        "required_source_paths",
    }
)
_PRIVATE_BETA_GATE_NAMES = (
    "scope",
    "local",
    "remote",
    "supply_chain",
    "installer",
    "independent_machine",
    "independent_review",
    "operations",
)
_PRIVATE_BETA_STATUS_KEYS = frozenset(
    {
        "candidate_commit",
        "formal_release_decision",
        "gates",
        "note",
        "private_beta_decision",
        "schema",
    }
)
_PRIVATE_BETA_GATE_KEYS = frozenset(
    {"evidence_sha256", "name", "source_commit", "status", "verified_at"}
)


class ProfileViolation(ValueError):
    """A fixed-code release-profile failure with no private context."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProfileSnapshot:
    """Immutable canonical profile data shared by every verification stage."""

    canonical_bytes: bytes
    profile: Mapping[str, Any]
    sha256: str


@dataclass(frozen=True)
class PrivateBetaStatusSnapshot:
    """Immutable canonical private-beta gate ledger."""

    canonical_bytes: bytes
    status: Mapping[str, Any]
    sha256: str


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def load_profile_snapshot(
    project_root: str | Path, profile_path: str | Path
) -> ProfileSnapshot:
    root = _resolved_project_root(project_root)
    path = _resolved_profile_path(root, profile_path)
    raw = _read_bounded(path, MAX_PROFILE_BYTES, "PROFILE_JSON_TOO_LARGE")
    return profile_snapshot_from_bytes(raw)


def profile_snapshot_from_bytes(raw: bytes) -> ProfileSnapshot:
    if not isinstance(raw, bytes):
        raise ProfileViolation("PROFILE_JSON_INVALID")
    if len(raw) > MAX_PROFILE_BYTES:
        raise ProfileViolation("PROFILE_JSON_TOO_LARGE")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except ProfileViolation:
        raise
    except (MemoryError, UnicodeError, json.JSONDecodeError):
        raise ProfileViolation("PROFILE_JSON_INVALID") from None
    if not isinstance(value, dict):
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    if raw != canonical_json_bytes(value):
        raise ProfileViolation("PROFILE_JSON_INVALID")
    _validate_profile_value(value)
    frozen = MappingProxyType(
        {
            key: tuple(item) if isinstance(item, list) else item
            for key, item in value.items()
        }
    )
    return ProfileSnapshot(raw, frozen, hashlib.sha256(raw).hexdigest())


def load_private_beta_status_snapshot(
    project_root: str | Path, status_path: str | Path
) -> PrivateBetaStatusSnapshot:
    root = _resolved_project_root(project_root)
    path = _resolved_profile_path(root, status_path)
    raw = _read_bounded(path, MAX_PROFILE_BYTES, "STATUS_JSON_TOO_LARGE")
    return private_beta_status_snapshot_from_bytes(raw)


def private_beta_status_snapshot_from_bytes(
    raw: bytes,
) -> PrivateBetaStatusSnapshot:
    if not isinstance(raw, bytes):
        raise ProfileViolation("STATUS_JSON_INVALID")
    if len(raw) > MAX_PROFILE_BYTES:
        raise ProfileViolation("STATUS_JSON_TOO_LARGE")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_status_object)
    except ProfileViolation:
        raise
    except (MemoryError, UnicodeError, json.JSONDecodeError):
        raise ProfileViolation("STATUS_JSON_INVALID") from None
    if not isinstance(value, dict) or set(value) != _PRIVATE_BETA_STATUS_KEYS:
        raise ProfileViolation("STATUS_SCHEMA_INVALID")
    if raw != canonical_json_bytes(value):
        raise ProfileViolation("STATUS_JSON_INVALID")
    _validate_private_beta_status(value)
    frozen = MappingProxyType(
        {
            **value,
            "gates": tuple(MappingProxyType(dict(gate)) for gate in value["gates"]),
        }
    )
    return PrivateBetaStatusSnapshot(raw, frozen, hashlib.sha256(raw).hexdigest())


def verify_private_beta_status(
    snapshot: PrivateBetaStatusSnapshot,
) -> dict[str, str]:
    if not isinstance(snapshot, PrivateBetaStatusSnapshot):
        raise ProfileViolation("STATUS_SCHEMA_INVALID")
    return {
        "formal_release": snapshot.status["formal_release_decision"],
        "private_beta": snapshot.status["private_beta_decision"],
        "status": "pass",
    }


def _validate_private_beta_status(value: dict[str, Any]) -> None:
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ProfileViolation("STATUS_SCHEMA_INVALID")
    if value["formal_release_decision"] != "NO-GO":
        raise ProfileViolation("STATUS_DECISION_INVALID")
    if value["private_beta_decision"] not in {
        "PRIVATE-BETA-NOT-READY",
        "PRIVATE-BETA-READY",
    }:
        raise ProfileViolation("STATUS_DECISION_INVALID")
    if (
        type(value["note"]) is not str
        or not value["note"]
        or len(value["note"]) > _MAX_VALUE_LENGTH
        or "\x00" in value["note"]
    ):
        raise ProfileViolation("STATUS_SCHEMA_INVALID")
    candidate = value["candidate_commit"]
    if candidate is not None and not _lower_hex(candidate, 40):
        raise ProfileViolation("STATUS_CANDIDATE_INVALID")
    gates = value["gates"]
    if (
        not isinstance(gates, list)
        or len(gates) != len(_PRIVATE_BETA_GATE_NAMES)
        or any(not isinstance(gate, dict) for gate in gates)
        or tuple(gate.get("name") for gate in gates) != _PRIVATE_BETA_GATE_NAMES
    ):
        raise ProfileViolation("STATUS_GATE_INVALID")
    for gate in gates:
        _validate_private_beta_gate(gate, candidate)
    expected = (
        "PRIVATE-BETA-READY"
        if all(gate["status"] == "pass" for gate in gates)
        else "PRIVATE-BETA-NOT-READY"
    )
    if value["private_beta_decision"] != expected:
        raise ProfileViolation("STATUS_DECISION_INVALID")


def _validate_private_beta_gate(gate: dict[str, Any], candidate: object) -> None:
    if set(gate) != _PRIVATE_BETA_GATE_KEYS:
        raise ProfileViolation("STATUS_GATE_INVALID")
    status = gate["status"]
    if status not in {"blocked", "fail", "pass", "pending"}:
        raise ProfileViolation("STATUS_GATE_INVALID")
    evidence = gate["evidence_sha256"]
    source = gate["source_commit"]
    verified_at = gate["verified_at"]
    if status == "pending":
        if any(item is not None for item in (evidence, source, verified_at)):
            raise ProfileViolation("STATUS_GATE_INVALID")
        return
    if (
        candidate is None
        or source != candidate
        or not _lower_hex(evidence, 64)
        or not _canonical_utc_seconds(verified_at)
    ):
        raise ProfileViolation("STATUS_GATE_INVALID")


def _lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_utc_seconds(value: object) -> bool:
    if type(value) is not str or len(value) != 20 or not value.endswith("Z"):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def require_profile_snapshot_unchanged(
    project_root: str | Path,
    profile_path: str | Path,
    snapshot: ProfileSnapshot,
) -> None:
    if not isinstance(snapshot, ProfileSnapshot):
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    try:
        root = _resolved_project_root(project_root)
        path = _resolved_profile_path(root, profile_path)
        raw = _read_bounded(path, MAX_PROFILE_BYTES, "PROFILE_SNAPSHOT_CHANGED")
    except ProfileViolation:
        raise ProfileViolation("PROFILE_SNAPSHOT_CHANGED") from None
    if raw != snapshot.canonical_bytes:
        raise ProfileViolation("PROFILE_SNAPSHOT_CHANGED")


def _validate_profile_value(value: dict[str, Any]) -> None:
    if (
        value.get("name") != "personal_exe_private_beta"
        or value.get("schema") != 2
    ):
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    if set(value) != _PRIVATE_BETA_PROFILE_KEYS:
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    for key in _PRIVATE_BETA_ARRAY_KEYS:
        items = value[key]
        if (
            not isinstance(items, list)
            or len(items) > _MAX_ARRAY_ITEMS
            or any(
                type(item) is not str
                or not item
                or len(item) > _MAX_VALUE_LENGTH
                or "\x00" in item
                for item in items
            )
            or items != sorted(items)
            or len({item.casefold() for item in items}) != len(items)
        ):
            raise ProfileViolation("PROFILE_ARRAY_INVALID")
    for key in _COMMON_PATH_ARRAY_KEYS | {"package_input_paths"}:
        if any(not _safe_relative_pattern(item) for item in value[key]):
            raise ProfileViolation("PROFILE_PATH_INVALID")
    if any(
        value[key] != expected for key, expected in _PRIVATE_BETA_IDENTITY.items()
    ):
        raise ProfileViolation("PROFILE_IDENTITY_INVALID")


def verify_profile(
    project_root: str | Path, snapshot: ProfileSnapshot
) -> dict[str, str]:
    if not isinstance(snapshot, ProfileSnapshot):
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    root = _resolved_project_root(project_root)
    profile = snapshot.profile

    for relative, _ in _walk_project(root):
        if _matches_any(relative, profile["forbidden_source_globs"]):
            raise ProfileViolation("PROFILE_SOURCE_FORBIDDEN")
    for relative in profile["required_source_paths"]:
        if not _required_file(root, relative):
            raise ProfileViolation("PROFILE_REQUIRED_SOURCE_MISSING")
    for relative in profile["package_input_paths"]:
        if not _required_path(root, relative):
            raise ProfileViolation("PROFILE_PACKAGE_INPUT_MISSING")

    _verify_runtime(root, profile)
    _verify_workflows(root, profile["forbidden_workflow_tokens"])
    _verify_documents(root, profile)
    return {"profile": profile["name"], "status": "pass"}


def verify_payload(bundle_root: str | Path, snapshot: ProfileSnapshot) -> None:
    if not isinstance(snapshot, ProfileSnapshot):
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    root = Path(bundle_root).absolute()
    if _has_reparse_component(root):
        raise ProfileViolation("PROFILE_PAYLOAD_INVALID")
    try:
        root = root.resolve(strict=True)
    except OSError:
        raise ProfileViolation("PROFILE_PAYLOAD_INVALID") from None
    if not root.is_dir():
        raise ProfileViolation("PROFILE_PAYLOAD_INVALID")
    for relative, _ in _walk(
        root,
        root,
        invalid_code="PROFILE_PAYLOAD_INVALID",
        limit_code="PROFILE_PAYLOAD_TRAVERSAL_LIMIT",
    ):
        if _matches_any(relative, snapshot.profile["forbidden_payload_globs"]):
            raise ProfileViolation("PROFILE_PAYLOAD_FORBIDDEN")


def _verify_runtime(root: Path, profile: Mapping[str, Any]) -> None:
    source_root = root / "src" / "agentguardian"
    modules: list[str] = []
    aggregate_bytes = 0
    for relative, path in _walk_project(source_root, root):
        if not path.is_file() or path.suffix.casefold() != ".py":
            continue
        try:
            source = _read_bounded(
                path, MAX_RUNTIME_SOURCE_BYTES, "PROFILE_RUNTIME_ANALYSIS_LIMIT"
            )
            aggregate_bytes += len(source)
            if aggregate_bytes > _MAX_RUNTIME_AGGREGATE_BYTES:
                raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")
            tree = ast.parse(source)
        except (RecursionError, MemoryError, OverflowError, SystemError):
            raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT") from None
        except ProfileViolation:
            raise
        except (SyntaxError, ValueError):
            raise ProfileViolation("PROFILE_RUNTIME_SYNTAX_INVALID") from None
        try:
            imports = _scan_runtime(tree, profile)
        except (RecursionError, MemoryError, OverflowError, SystemError):
            raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT") from None
        if any(
            _module_matches(name, profile["network_import_families"])
            for name in imports
        ):
            modules.append(relative)
    if tuple(sorted(modules)) != profile["declared_network_modules"]:
        raise ProfileViolation("PROFILE_NETWORK_SET_INVALID")


def _verify_workflows(root: Path, forbidden_tokens: tuple[str, ...]) -> None:
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return
    aggregate_bytes = 0
    for _, path in _walk_project(workflow_root, root):
        if not path.is_file() or path.suffix.casefold() not in {".yaml", ".yml"}:
            continue
        try:
            raw = _read_bounded(
                path, _MAX_WORKFLOW_FILE_BYTES, "PROFILE_WORKFLOW_INVALID"
            )
            aggregate_bytes += len(raw)
            if aggregate_bytes > _MAX_WORKFLOW_AGGREGATE_BYTES:
                raise ProfileViolation("PROFILE_WORKFLOW_INVALID")
            text = raw.decode("utf-8")
        except ProfileViolation:
            raise
        except UnicodeError:
            raise ProfileViolation("PROFILE_WORKFLOW_INVALID") from None
        folded = text.casefold()
        if any(token.casefold() in folded for token in forbidden_tokens):
            raise ProfileViolation("PROFILE_WORKFLOW_FORBIDDEN")


def _verify_documents(root: Path, profile: Mapping[str, Any]) -> None:
    patterns = profile["active_document_paths"]
    matched_patterns: set[str] = set()
    found_markers: set[str] = set()
    aggregate_bytes = 0
    for relative, path in _walk_project(root):
        matching = tuple(pattern for pattern in patterns if _glob_matches(relative, pattern))
        if not matching or not path.is_file():
            continue
        try:
            raw = _read_bounded(
                path, _MAX_DOCUMENT_FILE_BYTES, "PROFILE_DOCUMENT_INVALID"
            )
            aggregate_bytes += len(raw)
            if aggregate_bytes > _MAX_DOCUMENT_AGGREGATE_BYTES:
                raise ProfileViolation("PROFILE_DOCUMENT_INVALID")
            folded = raw.decode("utf-8").casefold()
        except ProfileViolation:
            raise
        except UnicodeError:
            raise ProfileViolation("PROFILE_DOCUMENT_INVALID") from None
        matched_patterns.update(matching)
        if any(
            fragment.casefold() in folded
            for fragment in profile["forbidden_document_promises"]
        ):
            raise ProfileViolation("PROFILE_DOCUMENT_FORBIDDEN")
        found_markers.update(
            marker
            for marker in profile["required_document_markers"]
            if marker.casefold() in folded
        )
    if len(matched_patterns) != len(patterns):
        raise ProfileViolation("PROFILE_DOCUMENT_INVALID")
    if len(found_markers) != len(profile["required_document_markers"]):
        raise ProfileViolation("PROFILE_DOCUMENT_BOUNDARY_MISSING")


# This policy matches explicit AST names/members; it does not evaluate Python.
def _scan_runtime(tree: ast.AST, profile: Mapping[str, Any]) -> tuple[str, ...]:
    imports: list[str] = []
    forbidden_names = {v.casefold() for v in profile["forbidden_runtime_names"]}
    forbidden_members = {v.casefold() for v in profile["forbidden_runtime_members"]}
    forbidden_prefixes = tuple(
        v.casefold() for v in profile["forbidden_runtime_member_prefixes"]
    )
    forbidden_symbols = {v.casefold() for v in profile["forbidden_runtime_symbols"]}

    for node_count, node in enumerate(ast.walk(tree), 1):
        if node_count > _MAX_RUNTIME_AST_NODES:
            raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")

        if isinstance(node, ast.Import):
            for item in node.names:
                imports.append(item.name)
                if _has_forbidden_symbol_part(item.name, forbidden_symbols):
                    raise ProfileViolation("PROFILE_RUNTIME_SYMBOL_FORBIDDEN")
                if _module_matches(item.name, profile["forbidden_runtime_imports"]):
                    raise ProfileViolation("PROFILE_RUNTIME_IMPORT_FORBIDDEN")
        elif isinstance(node, ast.ImportFrom):
            if any(item.name == "*" for item in node.names):
                raise ProfileViolation("PROFILE_RUNTIME_WILDCARD_IMPORT_FORBIDDEN")
            module = node.module or ""
            if module:
                imports.append(module)
                if _has_forbidden_symbol_part(module, forbidden_symbols):
                    raise ProfileViolation("PROFILE_RUNTIME_SYMBOL_FORBIDDEN")
                if _module_matches(module, profile["forbidden_runtime_imports"]):
                    raise ProfileViolation("PROFILE_RUNTIME_IMPORT_FORBIDDEN")
            for item in node.names:
                qualified = f"{module}.{item.name}" if module else item.name
                imports.append(qualified)
                if _module_matches(qualified, profile["forbidden_runtime_imports"]):
                    raise ProfileViolation("PROFILE_RUNTIME_IMPORT_FORBIDDEN")
                if (
                    item.name.casefold() in forbidden_names
                    or _forbidden_member(
                        item.name, forbidden_members, forbidden_prefixes
                    )
                ):
                    raise ProfileViolation("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")

        symbol: str | None = None
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            symbol = node.name
        elif isinstance(node, ast.Name):
            symbol = node.id
            if isinstance(node.ctx, ast.Load) and node.id.casefold() in forbidden_names:
                raise ProfileViolation("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
            if _forbidden_member(node.attr, forbidden_members, forbidden_prefixes):
                raise ProfileViolation("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        elif isinstance(node, ast.Call):
            member = _literal_getattr_member(node)
            if member is not None and _forbidden_member(
                member, forbidden_members, forbidden_prefixes
            ):
                raise ProfileViolation("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        if symbol is not None and symbol.casefold() in forbidden_symbols:
            raise ProfileViolation("PROFILE_RUNTIME_SYMBOL_FORBIDDEN")
    return tuple(imports)


def _forbidden_member(
    member: str, forbidden: set[str], prefixes: tuple[str, ...]
) -> bool:
    folded = member.casefold()
    if folded in forbidden:
        return True
    # ``sys.executable`` is a path lookup, not process creation. Keep the
    # prefix rule focused on execution APIs while retaining explicit members.
    if folded == "executable":
        return False
    # The exec prefix denotes process APIs; SQLite execute/execute* is retained.
    return any(
        folded != prefix
        and not (prefix == "exec" and folded.startswith("execute"))
        and folded.startswith(prefix)
        for prefix in prefixes
    )


def _literal_getattr_member(node: ast.Call) -> str | None:
    if (
        not isinstance(node.func, ast.Name)
        or node.func.id != "getattr"
        or len(node.args) < 2
        or not isinstance(node.args[1], ast.Constant)
        or not isinstance(node.args[1].value, str)
    ):
        return None
    return node.args[1].value


def _has_forbidden_symbol_part(name: str, forbidden: set[str]) -> bool:
    return any(part.casefold() in forbidden for part in name.split("."))


def _module_matches(name: str, families: Iterable[str]) -> bool:
    folded = name.casefold()
    return any(
        folded == family.casefold() or folded.startswith(family.casefold() + ".")
        for family in families
    )


def _walk_project(start: Path, root: Path | None = None) -> Iterator[tuple[str, Path]]:
    project_root = root or start
    return _walk(
        start,
        project_root,
        invalid_code="PROFILE_PROJECT_INVALID",
        limit_code="PROFILE_PROJECT_TRAVERSAL_LIMIT",
        excluded_root_directories=(
            _ROOT_PROJECT_EXCLUSIONS if start == project_root else frozenset()
        ),
    )


def _walk(
    start: Path,
    root: Path,
    *,
    invalid_code: str,
    limit_code: str,
    excluded_root_directories: frozenset[str] = frozenset(),
) -> Iterator[tuple[str, Path]]:
    if _is_reparse_point(start):
        raise ProfileViolation("PROFILE_REPARSE_POINT")
    stack = [(start, len(start.relative_to(root).parts))]
    seen: set[str] = set()
    entry_count = 0
    while stack:
        path, depth = stack.pop()
        if _is_reparse_point(path):
            raise ProfileViolation("PROFILE_REPARSE_POINT")
        relative = path.relative_to(root).as_posix()
        if relative != ".":
            if any(":" in part for part in relative.split("/")):
                raise ProfileViolation(invalid_code)
            folded = relative.casefold()
            if folded in seen:
                raise ProfileViolation(invalid_code)
            seen.add(folded)
            entry_count += 1
            if entry_count > _MAX_TRAVERSAL_ENTRIES:
                raise ProfileViolation(limit_code)
            yield relative, path
        try:
            if not path.is_dir():
                continue
            children: list[Path] = []
            for child in path.iterdir():
                if _is_reparse_point(child):
                    raise ProfileViolation("PROFILE_REPARSE_POINT")
                if (
                    path == root
                    and child.name.casefold() in excluded_root_directories
                    and child.is_dir()
                ):
                    continue
                children.append(child)
                if entry_count + len(children) > _MAX_TRAVERSAL_ENTRIES:
                    raise ProfileViolation(limit_code)
            if children and depth >= _MAX_TRAVERSAL_DEPTH:
                raise ProfileViolation(limit_code)
        except ProfileViolation:
            raise
        except OSError:
            raise ProfileViolation(invalid_code) from None
        stack.extend(
            (child, depth + 1)
            for child in sorted(
                children,
                key=lambda item: (item.name.casefold(), item.name),
                reverse=True,
            )
        )


def _required_file(root: Path, relative: str) -> bool:
    path = root.joinpath(*relative.split("/"))
    return _required_path(root, relative) and path.is_file()


def _required_path(root: Path, relative: str) -> bool:
    parts = relative.split("/")
    path = root.joinpath(*parts)
    current = root
    for part in parts:
        current = current / part
        if _is_reparse_point(current):
            raise ProfileViolation("PROFILE_REPARSE_POINT")
    return path.exists()


def _safe_relative_pattern(value: str) -> bool:
    if (
        not value
        or "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
    ):
        return False
    parts = value.split("/")
    return (
        all(part not in {"", ".", ".."} for part in parts)
        and all(":" not in part for part in parts)
        and not any(left == right == "**" for left, right in zip(parts, parts[1:]))
    )


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(_glob_matches(path, pattern) for pattern in patterns)


def _glob_matches(path: str, pattern: str) -> bool:
    path_parts = tuple(part.casefold() for part in path.split("/"))
    pattern_parts = tuple(part.casefold() for part in pattern.split("/"))

    @lru_cache(maxsize=None)
    def match(pattern_index: int, path_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        if pattern_parts[pattern_index] == "**":
            return match(pattern_index + 1, path_index) or (
                path_index < len(path_parts) and match(pattern_index, path_index + 1)
            )
        return (
            path_index < len(path_parts)
            and fnmatchcase(path_parts[path_index], pattern_parts[pattern_index])
            and match(pattern_index + 1, path_index + 1)
        )

    return match(0, 0)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ProfileViolation("PROFILE_JSON_INVALID")
        value[key] = item
    return value


def _unique_status_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ProfileViolation("STATUS_JSON_INVALID")
        value[key] = item
    return value


def _resolved_project_root(project_root: str | Path) -> Path:
    path = Path(project_root).absolute()
    if _has_reparse_component(path):
        raise ProfileViolation("PROFILE_PROJECT_INVALID")
    try:
        path = path.resolve(strict=True)
    except OSError:
        raise ProfileViolation("PROFILE_PROJECT_INVALID") from None
    if not path.is_dir():
        raise ProfileViolation("PROFILE_PROJECT_INVALID")
    return path


def _resolved_profile_path(root: Path, profile_path: str | Path) -> Path:
    lexical = Path(profile_path)
    if lexical.is_absolute():
        if any(":" in part for part in lexical.parts[1:]):
            raise ProfileViolation("PROFILE_PATH_INVALID")
        candidate = lexical
    elif isinstance(profile_path, Path):
        parts = lexical.parts
        if (
            lexical.drive
            or lexical.root
            or not parts
            or any(part in {"", ".", ".."} or ":" in part for part in parts)
        ):
            raise ProfileViolation("PROFILE_PATH_INVALID")
        candidate = root.joinpath(*parts)
    else:
        value = str(profile_path)
        if not _safe_relative_pattern(value):
            raise ProfileViolation("PROFILE_PATH_INVALID")
        candidate = root.joinpath(*value.split("/"))
    candidate = candidate.absolute()
    if _has_reparse_component(candidate):
        raise ProfileViolation("PROFILE_REPARSE_POINT")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        raise ProfileViolation("PROFILE_PATH_INVALID") from None
    if not resolved.is_file():
        raise ProfileViolation("PROFILE_PATH_INVALID")
    return resolved


def _read_bounded(path: Path, limit: int, code: str) -> bytes:
    try:
        with path.open("rb") as source:
            value = source.read(limit + 1)
    except (OSError, MemoryError, OverflowError):
        raise ProfileViolation(code) from None
    if len(value) > limit:
        raise ProfileViolation(code)
    return value


def _has_reparse_component(path: Path) -> bool:
    current = path
    while True:
        if current.exists() or current.is_symlink():
            if _is_reparse_point(current):
                return True
        if current.parent == current:
            return False
        current = current.parent


def _is_reparse_point(path: Path) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise ProfileViolation("PROFILE_REPARSE_POINT") from None
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    arguments = parser.parse_args()
    try:
        snapshot = load_profile_snapshot(arguments.project_root, arguments.profile)
        result = verify_profile(arguments.project_root, snapshot)
    except ProfileViolation as error:
        sys.stderr.buffer.write(canonical_json_bytes({"error": error.code, "status": "fail"}))
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
