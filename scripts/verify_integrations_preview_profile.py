"""Verify the bounded AgentGuardian 0.3 integrations-preview contract."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
from pathlib import Path
import stat
import sys
from types import MappingProxyType
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.verify_personal_release_profile import (
    ProfileSnapshot,
    ProfileViolation,
    canonical_json_bytes,
)


MAX_PROFILE_BYTES = 256 * 1024
MAX_RUNTIME_SOURCE_BYTES = 256 * 1024
MAX_RUNTIME_AGGREGATE_BYTES = 8 * 1024 * 1024
MAX_DOCUMENT_BYTES = 512 * 1024
MAX_DOCUMENT_AGGREGATE_BYTES = 4 * 1024 * 1024
MAX_TRAVERSAL_ENTRIES = 20_000
MAX_TRAVERSAL_DEPTH = 64
MAX_ARRAY_ITEMS = 256
MAX_VALUE_LENGTH = 512
MAX_RUNTIME_AST_NODES = 16_384

_ROOT_EXCLUSIONS = frozenset(
    {
        ".analysis",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "venv",
    }
)

_PROFILE_KEYS = frozenset(
    {
        "active_document_paths",
        "architecture",
        "backup_path",
        "channel",
        "codex_approval_contract",
        "config_path",
        "declared_network_modules",
        "forbidden_document_promises",
        "forbidden_installer_capabilities",
        "forbidden_payload_globs",
        "forbidden_runtime_capabilities",
        "forbidden_runtime_imports",
        "forbidden_runtime_member_prefixes",
        "forbidden_runtime_members",
        "forbidden_runtime_names",
        "forbidden_runtime_symbols",
        "forbidden_source_globs",
        "forbidden_workflow_tokens",
        "inno_setup_asset",
        "inno_setup_iscc_sha256",
        "inno_setup_release_tag",
        "inno_setup_script",
        "inno_setup_sha256",
        "inno_setup_version",
        "install_directory",
        "installer_app_id",
        "installer_filename",
        "installer_tasks",
        "launcher_inventory",
        "manifest_path",
        "mcp_command_args",
        "mcp_config_table",
        "mcp_sdk",
        "mcp_tools",
        "name",
        "network_import_families",
        "ownership_paths",
        "package_input_paths",
        "pending_path",
        "product_version",
        "pyinstaller_spec",
        "python_package_version",
        "required_document_markers",
        "required_source_paths",
        "schema",
        "skill_files",
        "skill_path",
        "skill_version",
        "status",
        "supported_operations",
        "transport",
        "windows_file_version",
    }
)

_IDENTITY = {
    "architecture": "x64",
    "channel": "integrations_preview",
    "inno_setup_asset": "innosetup-7.0.2-x64.exe",
    "inno_setup_iscc_sha256": (
        "0ff6140d641f84b64204a2c4d52207c6fc437c9f4db8779c83083d84f7e3d70d"
    ),
    "inno_setup_release_tag": "is-7_0_2",
    "inno_setup_sha256": (
        "5ad54ca3def786f8f4212552e54cc6d8d61329e2d24a1cfee0571d42c2684ff1"
    ),
    "inno_setup_version": "7.0.2",
    "install_directory": (
        r"{localappdata}\Programs\AgentGuardian Integrations Preview"
    ),
    "installer_app_id": "{A64DBF23-FE14-4E04-89AE-0924666A03DE}",
    "installer_filename": "AgentGuardian-Setup-0.3.0-preview.1-x64.exe",
    "name": "integrations_preview",
    "product_version": "0.3.0-preview.1",
    "python_package_version": "0.3.0a1",
    "schema": 1,
    "skill_version": "0.1.0",
    "status": "INTEGRATIONS-PREVIEW-NOT-READY",
    "windows_file_version": "0.3.0.1",
}

_PATH_ARRAY_KEYS = frozenset(
    {
        "active_document_paths",
        "declared_network_modules",
        "forbidden_payload_globs",
        "forbidden_source_globs",
        "package_input_paths",
        "required_source_paths",
    }
)
_STRING_ARRAY_KEYS = frozenset(
    {
        "active_document_paths",
        "declared_network_modules",
        "forbidden_document_promises",
        "forbidden_installer_capabilities",
        "forbidden_payload_globs",
        "forbidden_runtime_capabilities",
        "forbidden_runtime_imports",
        "forbidden_runtime_member_prefixes",
        "forbidden_runtime_members",
        "forbidden_runtime_names",
        "forbidden_runtime_symbols",
        "forbidden_source_globs",
        "forbidden_workflow_tokens",
        "network_import_families",
        "ownership_paths",
        "package_input_paths",
        "required_document_markers",
        "required_source_paths",
        "skill_files",
        "supported_operations",
    }
)
_NETWORK_MODULES = frozenset(
    {
        "aiohttp",
        "ftplib",
        "http",
        "httpx",
        "imaplib",
        "poplib",
        "requests",
        "smtplib",
        "socket",
        "telnetlib",
        "urllib",
        "urllib3",
        "websocket",
        "websockets",
        "xmlrpc.client",
        "PySide6.QtNetwork",
        "PySide6.QtWebEngine",
    }
)


def _fail(code: str) -> None:
    raise ProfileViolation(code)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _fail("PROFILE_JSON_INVALID")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    _fail("PROFILE_JSON_INVALID")


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def canonical_profile_bytes(value: object) -> bytes:
    """Expose the shared canonical JSON routine for callers and tests."""
    return canonical_json_bytes(value)


def profile_snapshot_from_bytes(raw: bytes) -> ProfileSnapshot:
    if type(raw) is not bytes:
        _fail("PROFILE_JSON_INVALID")
    if len(raw) > MAX_PROFILE_BYTES:
        _fail("PROFILE_JSON_TOO_LARGE")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ProfileViolation:
        raise
    except (MemoryError, UnicodeError, json.JSONDecodeError, ValueError):
        _fail("PROFILE_JSON_INVALID")
    if not isinstance(value, dict):
        _fail("PROFILE_SCHEMA_INVALID")
    if raw != canonical_json_bytes(value):
        _fail("PROFILE_JSON_INVALID")
    _validate_profile(value)
    return ProfileSnapshot(raw, _freeze(value), hashlib.sha256(raw).hexdigest())


def load_profile_snapshot(
    project_root: str | Path, profile_path: str | Path
) -> ProfileSnapshot:
    root = _resolved_project_root(project_root)
    path = _resolved_profile_path(root, profile_path)
    return profile_snapshot_from_bytes(
        _read_bounded(path, MAX_PROFILE_BYTES, "PROFILE_JSON_TOO_LARGE")
    )


def _validate_profile(value: dict[str, Any]) -> None:
    if set(value) != _PROFILE_KEYS:
        _fail("PROFILE_SCHEMA_INVALID")
    if any(value.get(key) != expected for key, expected in _IDENTITY.items()):
        _fail("PROFILE_IDENTITY_INVALID")
    for key in _STRING_ARRAY_KEYS:
        items = value[key]
        if (
            type(items) is not list
            or len(items) > MAX_ARRAY_ITEMS
            or any(
                type(item) is not str
                or not item
                or len(item) > MAX_VALUE_LENGTH
                or "\x00" in item
                for item in items
            )
            or items != sorted(items)
            or len({item.casefold() for item in items}) != len(items)
        ):
            _fail("PROFILE_ARRAY_INVALID")
    for key in _PATH_ARRAY_KEYS:
        if any(not _safe_relative_pattern(item) for item in value[key]):
            _fail("PROFILE_PATH_INVALID")
    for key in ("skill_path", "config_path", "backup_path", "manifest_path", "pending_path"):
        if type(value[key]) is not str or not value[key] or len(value[key]) > MAX_VALUE_LENGTH:
            _fail("PROFILE_IDENTITY_INVALID")
    if ".codex\\skills" in value["skill_path"].casefold():
        _fail("PROFILE_IDENTITY_INVALID")
    if value["mcp_tools"] != ["prepare_audit", "run_prepared_audit"]:
        _fail("PROFILE_TOOL_SET_INVALID")
    if value["mcp_command_args"] != ["--stdio-mcp"]:
        _fail("PROFILE_IDENTITY_INVALID")
    if value["supported_operations"] != ["browser", "clipboard", "files", "public_share"]:
        _fail("PROFILE_IDENTITY_INVALID")
    if value["skill_files"] != ["LICENSE", "README.md", "SKILL.md"]:
        _fail("PROFILE_IDENTITY_INVALID")
    if value["launcher_inventory"] != [
        {"console": False, "name": "AgentGuardian.exe"},
        {"console": True, "name": "AgentGuardianMcp.exe"},
    ]:
        _fail("PROFILE_LAUNCHER_SET_INVALID")
    expected_tasks = [
        {
            "default_selected": False,
            "name": "codexskill",
            "target": r"%USERPROFILE%\.agents\skills\agentguardian",
        },
        {
            "default_selected": False,
            "name": "codexmcp",
            "target": r"%USERPROFILE%\.codex\config.toml",
        },
        {
            "default_selected": False,
            "name": "desktopicon",
            "target": "desktop",
        },
    ]
    tasks = value["installer_tasks"]
    if type(tasks) is not list or tasks != expected_tasks:
        if isinstance(tasks, list) and any(
            isinstance(task, dict) and task.get("default_selected") is True
            for task in tasks
        ):
            _fail("PROFILE_TASK_DEFAULT_INVALID")
        _fail("PROFILE_TASK_SET_INVALID")
    if value["codex_approval_contract"] != {
        "prepare_audit": "auto",
        "run_prepared_audit": "prompt",
    }:
        _fail("PROFILE_APPROVAL_CONTRACT_INVALID")


def verify_profile(
    project_root: str | Path, snapshot: ProfileSnapshot
) -> dict[str, str]:
    if not isinstance(snapshot, ProfileSnapshot):
        _fail("PROFILE_SCHEMA_INVALID")
    root = _resolved_project_root(project_root)
    profile = snapshot.profile
    for relative, _ in _walk(root, root, excluded_root_directories=_ROOT_EXCLUSIONS):
        if _matches_any(relative, profile["forbidden_source_globs"]):
            _fail("PROFILE_SOURCE_FORBIDDEN")
    for relative in profile["required_source_paths"]:
        if not _required_path(root, relative):
            _fail("PROFILE_REQUIRED_SOURCE_MISSING")
    for relative in profile["package_input_paths"]:
        if not _required_path(root, relative):
            _fail("PROFILE_PACKAGE_INPUT_MISSING")
    _verify_runtime(root, profile)
    _verify_workflows(root, profile["forbidden_workflow_tokens"])
    _verify_documents(root, profile)
    if not (root / "src" / "agentguardian" / "mcp_server.py").is_file():
        _fail("PROFILE_REQUIRED_SOURCE_MISSING")
    _verify_static_contracts(root, profile)
    return {"profile": "integrations_preview", "status": "pass"}


def verify_payload(bundle_root: str | Path, snapshot: ProfileSnapshot) -> None:
    """Check only the profile-owned forbidden payload paths."""
    if not isinstance(snapshot, ProfileSnapshot):
        _fail("PROFILE_SCHEMA_INVALID")
    root = Path(bundle_root).absolute()
    if _has_reparse_component(root) or not root.is_dir():
        _fail("PROFILE_PAYLOAD_INVALID")
    skill = root / "agentguardian_skill"
    if (
        not skill.is_dir()
        or _has_reparse_component(skill)
        or tuple(sorted(path.name for path in skill.iterdir()))
        != ("LICENSE", "README.md", "SKILL.md")
    ):
        _fail("PROFILE_SKILL_INVALID")
    for relative, path in _walk(root, root):
        if path.is_file() and _matches_any(relative, snapshot.profile["forbidden_payload_globs"]):
            _fail("PROFILE_PAYLOAD_FORBIDDEN")


def verify_profile_evidence(
    bundle_root: str | Path,
    snapshot: ProfileSnapshot,
    source_commit: str,
) -> None:
    if (
        not isinstance(snapshot, ProfileSnapshot)
        or len(source_commit) != 40
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        _fail("PROFILE_PAYLOAD_IDENTITY_INVALID")
    path = Path(bundle_root).absolute() / "INTEGRATIONS-PREVIEW-PROFILE.json"
    try:
        raw = _read_bounded(path, MAX_DOCUMENT_BYTES, "PROFILE_PAYLOAD_IDENTITY_INVALID")
        value = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, ValueError, TypeError):
        _fail("PROFILE_PAYLOAD_IDENTITY_INVALID")
    expected = {
        "profile": "integrations_preview",
        "profile_sha256": snapshot.sha256,
        "schema": 1,
        "source_sha": source_commit,
        "status": "pass",
    }
    if raw != canonical_json_bytes(value) or value != expected:
        _fail("PROFILE_PAYLOAD_IDENTITY_INVALID")


def _verify_runtime(root: Path, profile: Mapping[str, Any]) -> None:
    source_root = root / "src" / "agentguardian"
    if not source_root.is_dir():
        _fail("PROFILE_RUNTIME_ANALYSIS_LIMIT")
    aggregate = 0
    network_paths: list[str] = []
    for path in sorted(source_root.rglob("*.py"), key=lambda item: item.as_posix().casefold()):
        if _has_reparse_component(path):
            _fail("PROFILE_REPARSE_POINT")
        raw = _read_bounded(path, MAX_RUNTIME_SOURCE_BYTES, "PROFILE_RUNTIME_ANALYSIS_LIMIT")
        aggregate += len(raw)
        if aggregate > MAX_RUNTIME_AGGREGATE_BYTES:
            _fail("PROFILE_RUNTIME_ANALYSIS_LIMIT")
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=str(path))
        except (UnicodeError, SyntaxError, ValueError):
            _fail("PROFILE_RUNTIME_SYNTAX_INVALID")
        imports = _scan_runtime(tree, profile)
        if any(_module_matches(name, profile["network_import_families"]) for name in imports):
            network_paths.append(path.relative_to(root).as_posix())
    if tuple(sorted(network_paths)) != tuple(profile["declared_network_modules"]):
        _fail("PROFILE_NETWORK_SET_INVALID")


def _scan_runtime(tree: ast.AST, profile: Mapping[str, Any]) -> tuple[str, ...]:
    imports: list[str] = []
    forbidden_names = {item.casefold() for item in profile["forbidden_runtime_names"]}
    forbidden_members = {item.casefold() for item in profile["forbidden_runtime_members"]}
    prefixes = tuple(item.casefold() for item in profile["forbidden_runtime_member_prefixes"])
    symbols = {item.casefold() for item in profile["forbidden_runtime_symbols"]}
    for count, node in enumerate(ast.walk(tree), 1):
        if count > MAX_RUNTIME_AST_NODES:
            _fail("PROFILE_RUNTIME_ANALYSIS_LIMIT")
        if isinstance(node, ast.Import):
            for item in node.names:
                imports.append(item.name)
                _check_import(item.name, profile)
        elif isinstance(node, ast.ImportFrom):
            if any(item.name == "*" for item in node.names):
                _fail("PROFILE_RUNTIME_WILDCARD_IMPORT_FORBIDDEN")
            module = node.module or ""
            if module:
                imports.append(module)
                _check_import(module, profile)
            for item in node.names:
                qualified = f"{module}.{item.name}" if module else item.name
                imports.append(qualified)
                _check_import(qualified, profile)
                if item.name.casefold() in forbidden_names or _forbidden_member(item.name, forbidden_members, prefixes):
                    _fail("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        symbol: str | None = None
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = node.name
        elif isinstance(node, ast.Name):
            symbol = node.id
            if isinstance(node.ctx, ast.Load) and node.id.casefold() in forbidden_names:
                _fail("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        elif isinstance(node, ast.Attribute):
            symbol = node.attr
            if _forbidden_member(node.attr, forbidden_members, prefixes):
                _fail("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        elif isinstance(node, ast.Call):
            member = _literal_getattr_member(node)
            if member is not None and _forbidden_member(member, forbidden_members, prefixes):
                _fail("PROFILE_RUNTIME_REFERENCE_FORBIDDEN")
        if symbol is not None and symbol.casefold() in symbols:
            _fail("PROFILE_RUNTIME_SYMBOL_FORBIDDEN")
    return tuple(imports)


def _check_import(name: str, profile: Mapping[str, Any]) -> None:
    if _module_matches(name, profile["forbidden_runtime_imports"]):
        _fail("PROFILE_RUNTIME_IMPORT_FORBIDDEN")
    if any(part.casefold() in {item.casefold() for item in profile["forbidden_runtime_symbols"]} for part in name.split(".")):
        _fail("PROFILE_RUNTIME_SYMBOL_FORBIDDEN")


def _verify_static_contracts(root: Path, profile: Mapping[str, Any]) -> None:
    package = root / "src" / "agentguardian"
    pyproject = _read_text(root / "pyproject.toml", MAX_DOCUMENT_BYTES, "PROFILE_PACKAGE_INPUT_INVALID")
    if 'version = "0.3.0a1"' not in pyproject or 'mcp==2.0.0' not in pyproject:
        _fail("PROFILE_VERSION_IDENTITY_INVALID")
    for relative in ("requirements-build.lock", "requirements-dev.lock"):
        text = _read_text(root / relative, MAX_DOCUMENT_BYTES, "PROFILE_PACKAGE_INPUT_INVALID")
        if "mcp==2.0.0" not in text or "--hash=sha256:" not in text:
            _fail("PROFILE_LOCK_INVALID")
    policy_path = package / "source_policy.json"
    try:
        policy = json.loads(_read_bounded(policy_path, MAX_DOCUMENT_BYTES, "PROFILE_SOURCE_POLICY_INVALID").decode("ascii"))
        modules = policy["modules"]
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        _fail("PROFILE_SOURCE_POLICY_INVALID")
    if set(modules) != {path.name for path in package.glob("*.py")}:
        _fail("PROFILE_SOURCE_POLICY_INVALID")
    for name, expected in modules.items():
        if hashlib.sha256((package / name).read_bytes()).hexdigest() != expected:
            _fail("PROFILE_SOURCE_POLICY_INVALID")
    skill = root / "skills" / "agentguardian"
    if tuple(sorted(path.name for path in skill.iterdir())) != ("LICENSE", "README.md", "SKILL.md"):
        _fail("PROFILE_SKILL_INVALID")
    skill_text = _read_text(skill / "SKILL.md", MAX_DOCUMENT_BYTES, "PROFILE_SKILL_INVALID")
    if "name: agentguardian" not in skill_text or 'version: "0.1.0"' not in skill_text:
        _fail("PROFILE_SKILL_INVALID")
    spec = _read_text(root / profile["pyinstaller_spec"], MAX_DOCUMENT_BYTES, "PROFILE_PACKAGING_INVALID")
    if spec.count("Analysis(") != 1 or spec.count("PYZ(") != 1 or spec.count("COLLECT(") != 1:
        _fail("PROFILE_PACKAGING_INVALID")
    if "name='AgentGuardian'" not in spec or "name='AgentGuardianMcp'" not in spec:
        _fail("PROFILE_PACKAGING_INVALID")
    iss = _read_text(root / profile["inno_setup_script"], MAX_DOCUMENT_BYTES, "PROFILE_PACKAGING_INVALID").casefold()
    for token in ("privilegesrequired=lowest", "setuparchitecture=x64", "flags: unchecked", "preparetoinstall", "--remove-codex-integration"):
        if token not in iss:
            _fail("PROFILE_PACKAGING_INVALID")
    mcp = _read_text(package / "mcp_server.py", MAX_RUNTIME_SOURCE_BYTES, "PROFILE_RUNTIME_SYNTAX_INVALID")
    _verify_mcp_ast(mcp)
    integration = _read_text(package / "codex_integration.py", MAX_RUNTIME_SOURCE_BYTES, "PROFILE_RUNTIME_SYNTAX_INVALID")
    if 'args = ["--stdio-mcp"]' not in integration or "default_tools_approval_mode = \"prompt\"" not in integration:
        _fail("PROFILE_INTEGRATION_CONTRACT_INVALID")


def _verify_mcp_ast(source: str) -> None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        _fail("PROFILE_RUNTIME_SYNTAX_INVALID")
    tools: list[str] = []
    resources = prompts = runs = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "server"
                ):
                    if decorator.func.attr == "tool":
                        tools.append(node.name)
                    elif decorator.func.attr == "resource":
                        resources += 1
                    elif decorator.func.attr == "prompt":
                        prompts += 1
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "server" and node.func.attr == "run":
                runs += 1
                if node.args or node.keywords:
                    _fail("PROFILE_MCP_TRANSPORT_INVALID")
    if sorted(tools) != ["prepare_audit", "run_prepared_audit"] or resources or prompts or runs != 1:
        _fail("PROFILE_MCP_TOOL_SET_INVALID")


def _verify_workflows(root: Path, tokens: Iterable[str]) -> None:
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return
    for path in workflow_root.glob("*.y*ml"):
        text = _read_text(path, MAX_DOCUMENT_BYTES, "PROFILE_WORKFLOW_INVALID").casefold()
        if any(token.casefold() in text for token in tokens):
            _fail("PROFILE_WORKFLOW_FORBIDDEN")


def _verify_documents(root: Path, profile: Mapping[str, Any]) -> None:
    paths = tuple(profile["active_document_paths"])
    if not paths:
        return
    aggregate = 0
    texts: list[str] = []
    for relative in paths:
        path = root.joinpath(*relative.split("/"))
        if not _required_file(root, relative):
            _fail("PROFILE_DOCUMENT_INVALID")
        raw = _read_bounded(path, MAX_DOCUMENT_BYTES, "PROFILE_DOCUMENT_INVALID")
        aggregate += len(raw)
        if aggregate > MAX_DOCUMENT_AGGREGATE_BYTES:
            _fail("PROFILE_DOCUMENT_INVALID")
    try:
        texts.append(raw.decode("utf-8").casefold())
    except UnicodeError:
        _fail("PROFILE_DOCUMENT_INVALID")
    status_relative = "docs/security/integrations-preview-status.json"
    if status_relative in paths:
        try:
            status_bytes = _read_bounded(
                root / status_relative, MAX_DOCUMENT_BYTES, "PROFILE_DOCUMENT_STATUS_INVALID"
            )
            status_value = json.loads(status_bytes.decode("ascii"))
        except (OSError, UnicodeError, ValueError, TypeError):
            _fail("PROFILE_DOCUMENT_STATUS_INVALID")
        expected = {
            "gates": {
                "clean_machine_lifecycle": "pending",
                "codex_cli_stdio": "pending",
                "codex_desktop_stdio": "pending",
                "github_ci": "pending",
                "independent_security_review": "pending",
                "license_and_marketplace_review": "pending",
                "local_verification": "pending",
                "windows_integrations_workflow": "pending",
            },
            "schema": 1,
            "status": "INTEGRATIONS-PREVIEW-NOT-READY",
        }
        if status_bytes != canonical_json_bytes(status_value) or status_value != expected:
            _fail("PROFILE_DOCUMENT_STATUS_INVALID")
    combined = "\n".join(texts)
    if any(marker.casefold() not in combined for marker in profile["required_document_markers"]):
        _fail("PROFILE_DOCUMENT_BOUNDARY_MISSING")
    if any(marker.casefold() in combined for marker in profile["forbidden_document_promises"]):
        _fail("PROFILE_DOCUMENT_FORBIDDEN")


def _read_text(path: Path, limit: int, code: str) -> str:
    try:
        return _read_bounded(path, limit, code).decode("utf-8")
    except UnicodeError:
        _fail(code)
    return ""


def _read_bounded(path: Path, limit: int, code: str) -> bytes:
    try:
        with path.open("rb") as stream:
            value = stream.read(limit + 1)
    except (OSError, MemoryError, OverflowError):
        _fail(code)
    if len(value) > limit:
        _fail(code)
    return value


def _required_path(root: Path, relative: str) -> bool:
    path = root.joinpath(*relative.split("/"))
    current = root
    for part in relative.split("/"):
        current /= part
        if _is_reparse_point(current):
            _fail("PROFILE_REPARSE_POINT")
    return path.exists()


def _required_file(root: Path, relative: str) -> bool:
    return _required_path(root, relative) and root.joinpath(*relative.split("/")).is_file()


def _resolved_project_root(project_root: str | Path) -> Path:
    path = Path(project_root).absolute()
    if _has_reparse_component(path):
        _fail("PROFILE_PROJECT_INVALID")
    try:
        path = path.resolve(strict=True)
    except OSError:
        _fail("PROFILE_PROJECT_INVALID")
    if not path.is_dir():
        _fail("PROFILE_PROJECT_INVALID")
    return path


def _resolved_profile_path(root: Path, profile_path: str | Path) -> Path:
    candidate = Path(profile_path)
    if not candidate.is_absolute():
        if not candidate.parts or any(part in {"", ".", ".."} or ":" in part for part in candidate.parts):
            _fail("PROFILE_PATH_INVALID")
        candidate = root.joinpath(*candidate.parts)
    candidate = candidate.absolute()
    if _has_reparse_component(candidate):
        _fail("PROFILE_REPARSE_POINT")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _fail("PROFILE_PATH_INVALID")
    if not resolved.is_file():
        _fail("PROFILE_PATH_INVALID")
    return resolved


def _walk(
    start: Path,
    root: Path,
    *,
    excluded_root_directories: frozenset[str] = frozenset(),
) -> Iterable[tuple[str, Path]]:
    if _is_reparse_point(start):
        _fail("PROFILE_REPARSE_POINT")
    stack = [(start, 0)]
    seen: set[str] = set()
    entries = 0
    while stack:
        path, depth = stack.pop()
        if _is_reparse_point(path):
            _fail("PROFILE_REPARSE_POINT")
        relative = path.relative_to(root).as_posix()
        if relative != ".":
            folded = relative.casefold()
            if folded in seen or any(":" in part for part in relative.split("/")):
                _fail("PROFILE_PROJECT_INVALID")
            seen.add(folded)
            entries += 1
            if entries > MAX_TRAVERSAL_ENTRIES:
                _fail("PROFILE_PROJECT_TRAVERSAL_LIMIT")
            yield relative, path
        if not path.is_dir():
            continue
        if depth >= MAX_TRAVERSAL_DEPTH:
            _fail("PROFILE_PROJECT_TRAVERSAL_LIMIT")
        try:
            children = []
            for child in path.iterdir():
                if path == root and child.name.casefold() in excluded_root_directories and child.is_dir():
                    continue
                if _is_reparse_point(child):
                    _fail("PROFILE_REPARSE_POINT")
                children.append(child)
        except ProfileViolation:
            raise
        except OSError:
            _fail("PROFILE_PROJECT_INVALID")
        stack.extend((child, depth + 1) for child in sorted(children, key=lambda item: item.name.casefold(), reverse=True))


def _safe_relative_pattern(value: str) -> bool:
    if not value or "\\" in value or value.startswith("/") or value.endswith("/") or "//" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} and ":" not in part for part in parts)


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    path_parts = tuple(part.casefold() for part in path.split("/"))
    for pattern in patterns:
        pattern_parts = tuple(part.casefold() for part in pattern.split("/"))
        if _glob_match(path_parts, pattern_parts):
            return True
    return False


def _glob_match(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    if not pattern:
        return not path
    if pattern[0] == "**":
        return _glob_match(path, pattern[1:]) or bool(path) and _glob_match(path[1:], pattern)
    return bool(path) and fnmatch.fnmatchcase(path[0], pattern[0]) and _glob_match(path[1:], pattern[1:])


def _module_matches(name: str, families: Iterable[str]) -> bool:
    folded = name.casefold()
    return any(folded == family.casefold() or folded.startswith(family.casefold() + ".") for family in families)


def _forbidden_member(member: str, forbidden: set[str], prefixes: tuple[str, ...]) -> bool:
    folded = member.casefold()
    if folded in forbidden:
        return True
    return any(
        folded != prefix
        and not (
            prefix == "exec"
            and (folded.startswith("execute") or folded == "executable")
        )
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


def _is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        _fail("PROFILE_REPARSE_POINT")
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _has_reparse_component(path: Path) -> bool:
    current = path
    while True:
        if current.exists() or current.is_symlink():
            if _is_reparse_point(current):
                return True
        if current.parent == current:
            return False
        current = current.parent


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
