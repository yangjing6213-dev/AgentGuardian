from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import secrets
import stat
import sys
import tomllib

from . import __version__
from .windows_dpapi import DpapiError, protect_bytes, unprotect_bytes


CONFIG_RELATIVE = Path(".codex/config.toml")
SKILL_RELATIVE = Path(".agents/skills/agentguardian")
BACKUP_RELATIVE = Path("AgentGuardian/codex-config-backup-v1.bin")
MANIFEST_RELATIVE = Path("AgentGuardian/codex-integration-v1.json")
PENDING_RELATIVE = Path("AgentGuardian/codex-uninstall-v1.json")
CONFIG_LIMIT = 512 * 1024
MANIFEST_LIMIT = 64 * 1024

BEGIN_MARKER = "# >>> AgentGuardian managed Codex integration v1 >>>"
END_MARKER = "# <<< AgentGuardian managed Codex integration v1 <<<"
SKILL_FILES = ("LICENSE", "README.md", "SKILL.md")
SKILL_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "skills" / "agentguardian"
_HASH_LENGTH = 64
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_BACKUP_MAGIC = b"AG-CODEX-BACKUP-V1\n"
_MAX_BACKUP_BYTES = 1024 * 1024


class IntegrationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class IntegrationNotPresent(IntegrationError):
    def __init__(self) -> None:
        super().__init__("INTEGRATION_NOT_PRESENT")


@dataclass(frozen=True, slots=True, repr=False)
class _IntegrationPaths:
    root: Path
    state_root: Path
    config: Path
    skill: Path
    backup: Path
    manifest: Path
    pending: Path


@dataclass(frozen=True, slots=True, repr=False)
class _FileState:
    existed: bool
    data: bytes = b""


@dataclass(frozen=True, slots=True, repr=False)
class _InstallTransaction:
    paths: _IntegrationPaths
    requested_skill: bool
    requested_mcp: bool
    install_skill: bool
    enable_mcp: bool
    executable: Path | None
    config_before: _FileState
    config_candidate: bytes | None
    existing_managed_block: bytes | None
    managed_block: bytes
    skill_source: tuple[tuple[str, bytes], ...]
    skill_before: tuple[tuple[str, _FileState], ...]
    backup_before: _FileState
    manifest_before: _FileState
    previous_manifest: dict[str, object] | None
    created_dirs: list[Path] = field(default_factory=list, repr=False, compare=False)
    superseded_backup: list[Path] = field(default_factory=list, repr=False, compare=False)
    manifest_after: bytes | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class _UninstallTransaction:
    paths: _IntegrationPaths
    manifest: dict[str, object]
    config: _FileState
    managed_block: bytes | None
    skill_files: tuple[tuple[str, str], ...]
    backup: _FileState
    pending: _FileState
    manifest_present: bool
    backup_expected_existed: bool
    backup_expected_sha256: str
    mcp_removed: bool = field(default=False, repr=False, compare=False)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_unc_path(value: str | Path) -> bool:
    text = os.fspath(value)
    if text.startswith(("\\\\", "//")):
        return True
    try:
        return PureWindowsPath(text).drive.startswith("\\\\")
    except (TypeError, ValueError):
        return True


def _is_reparse(path: str | Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _path_parts_are_safe(relative: Path) -> bool:
    return (
        not relative.is_absolute()
        and not _is_unc_path(relative)
        and all(part not in {"", ".", ".."} for part in relative.parts)
    )


def _check_existing_chain(root: Path, target: Path) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError:
        raise IntegrationError("INTEGRATION_PATH_INVALID") from None
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError:
            raise IntegrationError("INTEGRATION_PATH_INVALID") from None
        if _is_reparse(current):
            raise IntegrationError("INTEGRATION_PATH_INVALID")
        if current != target and not stat.S_ISDIR(info.st_mode):
            raise IntegrationError("INTEGRATION_PATH_INVALID")


def _user_paths(environ: Mapping[str, str]) -> _IntegrationPaths:
    try:
        value = environ.get("USERPROFILE")
    except Exception:
        value = None
    if type(value) is not str or not value:
        raise IntegrationError("INTEGRATION_USERPROFILE_INVALID")
    root = Path(value)
    if (
        not root.is_absolute()
        or _is_unc_path(value)
        or any(part == ".." for part in root.parts)
        or _is_reparse(root)
        or _has_reparse_ancestor(root)
        or not root.is_dir()
    ):
        raise IntegrationError("INTEGRATION_USERPROFILE_INVALID")
    _check_existing_chain(root, root)
    try:
        local_app_data = environ.get("LOCALAPPDATA")
    except Exception:
        local_app_data = None
    if type(local_app_data) is not str or not local_app_data:
        raise IntegrationError("INTEGRATION_LOCALAPPDATA_INVALID")
    state_root = Path(local_app_data)
    if (
        not state_root.is_absolute()
        or _is_unc_path(local_app_data)
        or any(part == ".." for part in state_root.parts)
        or _is_reparse(state_root)
        or _has_reparse_ancestor(state_root)
        or not state_root.is_dir()
    ):
        raise IntegrationError("INTEGRATION_LOCALAPPDATA_INVALID")
    paths = _IntegrationPaths(
        root=root,
        state_root=state_root,
        config=root / CONFIG_RELATIVE,
        skill=root / SKILL_RELATIVE,
        backup=state_root / BACKUP_RELATIVE,
        manifest=state_root / MANIFEST_RELATIVE,
        pending=state_root / PENDING_RELATIVE,
    )
    for path, base in (
        (paths.config, root),
        (paths.skill, root),
        (paths.backup, state_root),
        (paths.manifest, state_root),
        (paths.pending, state_root),
    ):
        relative = path.relative_to(base)
        if not _path_parts_are_safe(relative):
            raise IntegrationError("INTEGRATION_PATH_INVALID")
        _check_existing_chain(base, path.parent)
        if _is_reparse(path):
            raise IntegrationError("INTEGRATION_PATH_INVALID")
    return paths


def _ensure_directory(path: Path, root: Path, created: list[Path]) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise IntegrationError("INTEGRATION_PATH_INVALID") from None
    if not _path_parts_are_safe(relative):
        raise IntegrationError("INTEGRATION_PATH_INVALID")
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            try:
                current.mkdir()
            except OSError:
                raise IntegrationError("INTEGRATION_TEMP_WRITE_FAILED") from None
            created.append(current)
            continue
        except OSError:
            raise IntegrationError("INTEGRATION_PATH_INVALID") from None
        if _is_reparse(current) or not stat.S_ISDIR(info.st_mode):
            raise IntegrationError("INTEGRATION_PATH_INVALID")


def _read_file(
    path: Path,
    limit: int,
    missing_ok: bool = True,
    too_large_code: str = "INTEGRATION_STATE_TOO_LARGE",
) -> _FileState:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return _FileState(False)
        raise IntegrationError("INTEGRATION_PATH_INVALID") from None
    except OSError:
        raise IntegrationError("INTEGRATION_READ_FAILED") from None
    if _is_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise IntegrationError("INTEGRATION_PATH_INVALID")
    if info.st_size > limit:
        raise IntegrationError(too_large_code)
    try:
        data = path.read_bytes()
        after = os.lstat(path)
    except OSError:
        raise IntegrationError("INTEGRATION_READ_FAILED") from None
    if (
        _is_reparse(path)
        or not stat.S_ISREG(after.st_mode)
        or after.st_size != len(data)
        or len(data) > limit
    ):
        raise IntegrationError("INTEGRATION_PATH_INVALID")
    return _FileState(True, data)


def _atomic_write(path: Path, data: bytes, root: Path, created: list[Path]) -> None:
    if type(data) is not bytes or len(data) > _MAX_BACKUP_BYTES:
        raise IntegrationError("INTEGRATION_TEMP_WRITE_FAILED")
    parent = path.parent
    _ensure_directory(parent, root, created)
    _check_existing_chain(root, parent)
    if _is_reparse(path):
        raise IntegrationError("INTEGRATION_PATH_INVALID")
    temporary: Path | None = None
    try:
        temporary = parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
        with open(temporary, "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _check_existing_chain(root, parent)
        if _is_reparse(path) or _is_reparse(temporary):
            raise OSError
        os.replace(temporary, path)
        temporary = None
    except IntegrationError:
        raise
    except Exception:
        raise IntegrationError("INTEGRATION_TEMP_WRITE_FAILED") from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _remove_file(path: Path, root: Path, code: str) -> None:
    _check_existing_chain(root, path.parent)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        raise IntegrationError(code) from None
    if _is_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise IntegrationError(code)
    try:
        path.unlink()
    except OSError:
        raise IntegrationError(code) from None


def _restore_file(
    path: Path,
    state: _FileState,
    root: Path,
    created: list[Path],
) -> None:
    if state.existed:
        _atomic_write(path, state.data, root, created)
    else:
        _remove_file(path, root, "INTEGRATION_ROLLBACK_FAILED")


def _skill_source() -> tuple[tuple[str, bytes], ...]:
    candidates = [SKILL_SOURCE_ROOT]
    bundle_root = getattr(sys, "_MEIPASS", None)
    if isinstance(bundle_root, str):
        candidates.append(Path(bundle_root) / "skills" / "agentguardian")
    candidates.append(Path(sys.executable).resolve().parent / "skills" / "agentguardian")
    source: Path | None = next(
        (candidate for candidate in candidates if candidate.is_dir()), None
    )
    if source is None:
        raise IntegrationError("SKILL_SOURCE_UNAVAILABLE")
    values: list[tuple[str, bytes]] = []
    for name in SKILL_FILES:
        path = source / name
        state = _read_file(path, 256 * 1024, missing_ok=False)
        values.append((name, state.data))
    return tuple(values)


def _validate_skill_tree(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise IntegrationError("SKILL_CONFLICT") from None
    if _is_reparse(path) or not stat.S_ISDIR(info.st_mode):
        raise IntegrationError("SKILL_CONFLICT")
    pending = [path]
    count = 0
    has_entries = False
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            raise IntegrationError("SKILL_CONFLICT") from None
        count += len(entries)
        has_entries = has_entries or bool(entries)
        if count > 1024:
            raise IntegrationError("SKILL_CONFLICT")
        for entry in entries:
            child = Path(entry.path)
            if _is_reparse(child):
                raise IntegrationError("SKILL_CONFLICT")
            try:
                child_info = entry.stat(follow_symlinks=False)
            except OSError:
                raise IntegrationError("SKILL_CONFLICT") from None
            if stat.S_ISDIR(child_info.st_mode):
                pending.append(child)
            elif not stat.S_ISREG(child_info.st_mode):
                raise IntegrationError("SKILL_CONFLICT")
    return has_entries


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _valid_hash(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _HASH_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_manifest(state: _FileState) -> dict[str, object] | None:
    if not state.existed:
        return None
    if len(state.data) > MANIFEST_LIMIT:
        raise IntegrationError("INTEGRATION_MANIFEST_INVALID")
    try:
        data = json.loads(
            state.data.decode("utf-8"), object_pairs_hook=_unique_object
        )
        expected_keys = {
            "schema",
            "integration_version",
            "install_skill",
            "enable_mcp",
            "config_before_sha256",
            "managed_block_sha256",
            "skill_files",
        }
        if type(data) is not dict or set(data) != expected_keys:
            raise ValueError
        if (
            type(data["schema"]) is not int
            or data["schema"] != 1
            or type(data["integration_version"]) is not str
            or data["integration_version"] != __version__
        ):
            raise ValueError
        if type(data["install_skill"]) is not bool or type(data["enable_mcp"]) is not bool:
            raise ValueError
        if not _valid_hash(data["config_before_sha256"]) or not _valid_hash(
            data["managed_block_sha256"]
        ):
            raise ValueError
        entries = data["skill_files"]
        if type(entries) is not list:
            raise ValueError
        names: list[str] = []
        for item in entries:
            if type(item) is not dict or set(item) != {"path", "sha256"}:
                raise ValueError
            name = item["path"]
            if (
                type(name) is not str
                or name not in SKILL_FILES
                or not _valid_hash(item["sha256"])
            ):
                raise ValueError
            names.append(name)
        if names != sorted(set(names)):
            raise ValueError
        if _canonical_json_bytes(data) != state.data:
            raise ValueError
        return data
    except IntegrationError:
        raise
    except Exception:
        raise IntegrationError("INTEGRATION_MANIFEST_INVALID") from None


def _pending_bytes(manifest: dict[str, object], backup: _FileState) -> bytes:
    manifest_bytes = _canonical_json_bytes(manifest)
    data = {
        "backup_existed": backup.existed,
        "backup_sha256": _sha256(backup.data),
        "integration_version": __version__,
        "manifest_b64": base64.b64encode(manifest_bytes).decode("ascii"),
        "manifest_sha256": _sha256(manifest_bytes),
        "schema": 1,
    }
    rendered = _canonical_json_bytes(data)
    if len(rendered) > MANIFEST_LIMIT:
        raise IntegrationError("INTEGRATION_MANIFEST_INVALID")
    return rendered


def _load_pending(
    state: _FileState,
) -> tuple[dict[str, object], str, bool, str] | None:
    if not state.existed:
        return None
    try:
        data = json.loads(
            state.data.decode("ascii"), object_pairs_hook=_unique_object
        )
        if type(data) is not dict or set(data) != {
            "backup_existed",
            "backup_sha256",
            "integration_version",
            "manifest_b64",
            "manifest_sha256",
            "schema",
        }:
            raise ValueError
        if (
            type(data["schema"]) is not int
            or data["schema"] != 1
            or type(data["integration_version"]) is not str
            or data["integration_version"] != __version__
            or type(data["backup_existed"]) is not bool
            or not _valid_hash(data["backup_sha256"])
            or not _valid_hash(data["manifest_sha256"])
            or type(data["manifest_b64"]) is not str
        ):
            raise ValueError
        manifest_bytes = base64.b64decode(data["manifest_b64"], validate=True)
        if (
            type(manifest_bytes) is not bytes
            or not manifest_bytes
            or len(manifest_bytes) > MANIFEST_LIMIT
            or _sha256(manifest_bytes) != data["manifest_sha256"]
        ):
            raise ValueError
        if not data["backup_existed"] and data["backup_sha256"] != _sha256(b""):
            raise ValueError
        manifest = _load_manifest(_FileState(True, manifest_bytes))
        if manifest is None or _canonical_json_bytes(data) != state.data:
            raise ValueError
        return (
            manifest,
            data["manifest_sha256"],
            data["backup_existed"],
            data["backup_sha256"],
        )
    except IntegrationError:
        raise
    except Exception:
        raise IntegrationError("INTEGRATION_MANIFEST_INVALID") from None


def _skill_snapshot(path: Path) -> tuple[tuple[str, _FileState], ...]:
    _validate_skill_tree(path)
    return tuple(
        (name, _read_file(path / name, 256 * 1024)) for name in SKILL_FILES
    )


def _config_text(state: _FileState) -> str:
    if not state.existed:
        return ""
    try:
        return state.data.decode("utf-8")
    except UnicodeError:
        raise IntegrationError("CODEX_CONFIG_INVALID") from None


def _parse_config(data: bytes) -> dict[str, object]:
    if len(data) > CONFIG_LIMIT:
        raise IntegrationError("CODEX_CONFIG_TOO_LARGE")
    try:
        text = data.decode("utf-8")
        parsed = tomllib.loads(text)
    except UnicodeError:
        raise IntegrationError("CODEX_CONFIG_INVALID") from None
    except Exception:
        raise IntegrationError("CODEX_CONFIG_INVALID") from None
    if type(parsed) is not dict:
        raise IntegrationError("CODEX_CONFIG_INVALID")
    return parsed


def _server_from_config(parsed: dict[str, object]) -> dict[str, object] | None:
    servers = parsed.get("mcp_servers")
    if servers is None:
        return None
    if type(servers) is not dict:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    value = servers.get("agentguardian")
    if value is None:
        return None
    if type(value) is not dict:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    return value


def _managed_block(executable: Path) -> bytes:
    command = json.dumps(os.fspath(executable), ensure_ascii=True)
    return (
        f"{BEGIN_MARKER}\n"
        "[mcp_servers.agentguardian]\n"
        f"command = {command}\n"
        'args = ["--stdio-mcp"]\n'
        "enabled = true\n"
        'enabled_tools = ["prepare_audit", "run_prepared_audit"]\n'
        'default_tools_approval_mode = "prompt"\n\n'
        "[mcp_servers.agentguardian.tools.prepare_audit]\n"
        'approval_mode = "auto"\n\n'
        "[mcp_servers.agentguardian.tools.run_prepared_audit]\n"
        'approval_mode = "prompt"\n'
        f"{END_MARKER}\n"
    ).encode("utf-8")


def _backup_envelope(original: bytes, existed: bool) -> bytes:
    value = {
        "content_b64": base64.b64encode(original).decode("ascii"),
        "existed": existed,
        "schema": 1,
        "sha256": _sha256(original),
    }
    return _BACKUP_MAGIC + _canonical_json_bytes(value)


def _decode_backup(data: bytes) -> tuple[bytes, bool]:
    if type(data) is not bytes or not data or len(data) > _MAX_BACKUP_BYTES:
        raise IntegrationError("INTEGRATION_BACKUP_INVALID")
    if not data.startswith(_BACKUP_MAGIC):
        raise IntegrationError("INTEGRATION_BACKUP_INVALID")
    try:
        value = json.loads(
            data[len(_BACKUP_MAGIC) :].decode("ascii"),
            object_pairs_hook=_unique_object,
        )
        if type(value) is not dict or set(value) != {
            "content_b64",
            "existed",
            "schema",
            "sha256",
        }:
            raise ValueError
        if (
            type(value["schema"]) is not int
            or value["schema"] != 1
            or type(value["existed"]) is not bool
        ):
            raise ValueError
        if not _valid_hash(value["sha256"]):
            raise ValueError
        original = base64.b64decode(value["content_b64"], validate=True)
        if type(original) is not bytes or len(original) > CONFIG_LIMIT:
            raise ValueError
        if _sha256(original) != value["sha256"]:
            raise ValueError
        if not value["existed"] and original:
            raise ValueError
        if _backup_envelope(original, value["existed"]) != data:
            raise ValueError
        return original, value["existed"]
    except IntegrationError:
        raise
    except Exception:
        raise IntegrationError("INTEGRATION_BACKUP_INVALID") from None


def _marker_range(data: bytes) -> tuple[int, int, bytes] | None:
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise IntegrationError("CODEX_CONFIG_INVALID") from None
    begin_count = text.count(BEGIN_MARKER)
    end_count = text.count(END_MARKER)
    if begin_count == 0 and end_count == 0:
        return None
    if begin_count != 1 or end_count != 1:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    begin = text.index(BEGIN_MARKER)
    end_marker = text.index(END_MARKER)
    if end_marker <= begin:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    start_char = text.rfind("\n", 0, begin) + 1
    end_char = text.find("\n", end_marker)
    end_char = len(text) if end_char < 0 else end_char + 1
    start = len(text[:start_char].encode("utf-8"))
    end = len(text[:end_char].encode("utf-8"))
    block = data[start:end]
    _validate_managed_block(block)
    return start, end, block


def _validate_managed_block(block: bytes) -> dict[str, object]:
    try:
        text = block.decode("utf-8")
    except UnicodeError:
        raise IntegrationError("CODEX_CONFIG_CONFLICT") from None
    lines = text.splitlines()
    if len(lines) < 3 or lines[0] != BEGIN_MARKER or lines[-1] != END_MARKER:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    inner = "\n".join(lines[1:-1]) + "\n"
    try:
        parsed = tomllib.loads(inner)
    except Exception:
        raise IntegrationError("CODEX_CONFIG_CONFLICT") from None
    server = _server_from_config(parsed)
    if set(parsed) != {"mcp_servers"} or server is None or set(server) != {
        "command",
        "args",
        "enabled",
        "enabled_tools",
        "default_tools_approval_mode",
        "tools",
    }:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    if (
        type(server["command"]) is not str
        or server["args"] != ["--stdio-mcp"]
        or server["enabled"] is not True
        or server["enabled_tools"] != ["prepare_audit", "run_prepared_audit"]
        or server["default_tools_approval_mode"] != "prompt"
        or server["tools"]
        != {
            "prepare_audit": {"approval_mode": "auto"},
            "run_prepared_audit": {"approval_mode": "prompt"},
        }
    ):
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    return server


def _config_candidate(
    state: _FileState,
    executable: Path,
) -> tuple[bytes, bytes | None]:
    markers = _marker_range(state.data)
    parsed = _parse_config(state.data)
    if markers is None and _server_from_config(parsed) is not None:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    base = state.data
    existing: bytes | None = None
    if markers is not None:
        start, end, existing = markers
        base = state.data[:start] + state.data[end:]
        if _server_from_config(_parse_config(base)) is not None:
            raise IntegrationError("CODEX_CONFIG_CONFLICT")
    block = _managed_block(executable)
    if markers is not None:
        start, end, _ = markers
        candidate = state.data[:start] + block + state.data[end:]
    else:
        separator = b"" if not base or base.endswith((b"\n", b"\r")) else b"\n"
        candidate = base + separator + block
    parsed_candidate = _parse_config(candidate)
    server = _server_from_config(parsed_candidate)
    expected_server = _validate_managed_block(block)
    if server != expected_server:
        raise IntegrationError("CODEX_CONFIG_INVALID")
    return candidate, existing


def _resolve_executable(executable: Path | None) -> Path:
    value = Path(sys.executable).with_name("AgentGuardianMcp.exe") if executable is None else Path(executable)
    if (
        not value.is_absolute()
        or _is_unc_path(value)
        or any(part == ".." for part in value.parts)
        or value.name != "AgentGuardianMcp.exe"
        or _is_reparse(value)
        or _is_reparse(value.parent)
        or _has_reparse_ancestor(value.parent)
    ):
        raise IntegrationError("INTEGRATION_PATH_INVALID")
    try:
        info = os.lstat(value)
        sibling = value.with_name("AgentGuardian.exe")
        sibling_info = os.lstat(sibling)
    except (FileNotFoundError, OSError):
        raise IntegrationError("INTEGRATION_PATH_INVALID") from None
    if (
        _is_reparse(value)
        or _is_reparse(sibling)
        or not stat.S_ISREG(info.st_mode)
        or not stat.S_ISREG(sibling_info.st_mode)
        or value.parent != sibling.parent
    ):
        raise IntegrationError("INTEGRATION_PATH_INVALID")
    return value


def _has_reparse_ancestor(path: Path) -> bool:
    current = path
    while True:
        if _is_reparse(current):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _skill_hashes(source: tuple[tuple[str, bytes], ...]) -> list[dict[str, str]]:
    return [{"path": name, "sha256": _sha256(data)} for name, data in source]


def _manifest_bytes(
    *,
    install_skill: bool,
    enable_mcp: bool,
    config_before: bytes,
    managed_block: bytes,
    skill_files: list[dict[str, str]],
    config_before_sha256: str | None = None,
    managed_block_sha256: str | None = None,
) -> bytes:
    data = {
        "schema": 1,
        "integration_version": __version__,
        "install_skill": install_skill,
        "enable_mcp": enable_mcp,
        "config_before_sha256": config_before_sha256 or _sha256(config_before),
        "managed_block_sha256": managed_block_sha256 or _sha256(managed_block),
        "skill_files": skill_files,
    }
    rendered = _canonical_json_bytes(data)
    if len(rendered) > MANIFEST_LIMIT:
        raise IntegrationError("INTEGRATION_MANIFEST_INVALID")
    return rendered


def _manifest_skill_map(manifest: dict[str, object] | None) -> dict[str, str]:
    if manifest is None:
        return {}
    return {
        item["path"]: item["sha256"]
        for item in manifest["skill_files"]  # type: ignore[union-attr]
    }


def _prepare_install_transaction(
    *,
    install_skill: bool,
    enable_mcp: bool,
    mcp_executable: Path | None,
    environ: Mapping[str, str],
) -> _InstallTransaction:
    paths = _user_paths(environ)
    pending_before = _read_file(
        paths.pending,
        MANIFEST_LIMIT,
        too_large_code="INTEGRATION_MANIFEST_INVALID",
    )
    if pending_before.existed:
        raise IntegrationError("INTEGRATION_CLEANUP_REQUIRED")
    config_before = _read_file(
        paths.config, CONFIG_LIMIT, too_large_code="CODEX_CONFIG_TOO_LARGE"
    )
    backup_before = _read_file(paths.backup, _MAX_BACKUP_BYTES)
    manifest_before = _read_file(
        paths.manifest,
        MANIFEST_LIMIT,
        too_large_code="INTEGRATION_MANIFEST_INVALID",
    )
    previous = _load_manifest(manifest_before)
    skill_before = _skill_snapshot(paths.skill)
    skill_has_entries = _validate_skill_tree(paths.skill)
    existing_markers = _marker_range(config_before.data)
    _parse_config(config_before.data)
    existing_block = existing_markers[2] if existing_markers is not None else None

    if previous is None:
        if existing_block is not None:
            raise IntegrationError("CODEX_CONFIG_CONFLICT")
        if backup_before.existed:
            raise IntegrationError("INTEGRATION_OWNERSHIP_CONFLICT")
        if install_skill and skill_has_entries:
            raise IntegrationError("SKILL_CONFLICT")
        previous_skill = {}
    else:
        previous_skill = _manifest_skill_map(previous)
        if previous["enable_mcp"] is True:
            if existing_block is None:
                raise IntegrationError("CODEX_CONFIG_CONFLICT")
            if _sha256(existing_block) != previous["managed_block_sha256"]:
                raise IntegrationError("CODEX_CONFIG_CONFLICT")
            if not backup_before.existed:
                raise IntegrationError("INTEGRATION_BACKUP_INVALID")
        elif existing_block is not None:
            raise IntegrationError("CODEX_CONFIG_CONFLICT")
        elif backup_before.existed:
            raise IntegrationError("INTEGRATION_OWNERSHIP_CONFLICT")

    requested_skill = install_skill
    requested_mcp = enable_mcp
    if install_skill:
        source = _skill_source()
        source_names = {name for name, _ in source}
        if skill_has_entries and not previous_skill:
            raise IntegrationError("SKILL_CONFLICT")
        for name, state in skill_before:
            if state.existed and name not in previous_skill:
                raise IntegrationError("SKILL_CONFLICT")
            if (
                state.existed
                and name in previous_skill
                and _sha256(state.data) != previous_skill[name]
            ):
                raise IntegrationError("SKILL_CONFLICT")
        if source_names != set(SKILL_FILES):
            raise IntegrationError("SKILL_SOURCE_UNAVAILABLE")
    else:
        source = ()

    executable = _resolve_executable(mcp_executable) if enable_mcp else None
    candidate: bytes | None = None
    new_block = existing_block or b""
    if enable_mcp:
        assert executable is not None
        candidate, old_block = _config_candidate(config_before, executable)
        existing_block = old_block or existing_block
        new_block = _managed_block(executable)
    elif existing_block is not None:
        _validate_managed_block(existing_block)

    effective_skill = bool(previous and previous["install_skill"]) or install_skill
    effective_mcp = bool(previous and previous["enable_mcp"]) or enable_mcp
    if effective_mcp and not new_block:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    if effective_mcp and not backup_before.existed and not enable_mcp:
        raise IntegrationError("INTEGRATION_BACKUP_INVALID")
    if not effective_skill:
        skill_manifest = []
    elif install_skill:
        skill_manifest = _skill_hashes(source)
    else:
        skill_manifest = [
            {"path": name, "sha256": digest}
            for name, digest in sorted(previous_skill.items())
        ]
    return _InstallTransaction(
        paths=paths,
        requested_skill=requested_skill,
        requested_mcp=requested_mcp,
        install_skill=effective_skill,
        enable_mcp=effective_mcp,
        executable=executable,
        config_before=config_before,
        config_candidate=candidate,
        existing_managed_block=existing_block,
        managed_block=new_block,
        skill_source=source,
        skill_before=skill_before,
        backup_before=backup_before,
        manifest_before=manifest_before,
        previous_manifest=previous,
    )


def _install_managed_mcp(
    transaction: _InstallTransaction,
    *,
    protect: Callable[[bytes], bytes],
) -> None:
    if not transaction.requested_mcp:
        return
    try:
        encrypted = protect(
            _backup_envelope(
                transaction.config_before.data,
                transaction.config_before.existed,
            )
        )
    except DpapiError as error:
        code = (
            "INTEGRATION_DPAPI_UNAVAILABLE"
            if str(error) == "DPAPI_UNAVAILABLE"
            else "INTEGRATION_DPAPI_FAILED"
        )
        raise IntegrationError(code) from None
    except Exception:
        raise IntegrationError("INTEGRATION_DPAPI_FAILED") from None
    if type(encrypted) is not bytes or not encrypted or len(encrypted) > _MAX_BACKUP_BYTES:
        raise IntegrationError("INTEGRATION_DPAPI_FAILED")
    _ensure_directory(
        transaction.paths.backup.parent,
        transaction.paths.state_root,
        transaction.created_dirs,
    )
    if transaction.backup_before.existed:
        temporary: Path | None = None
        try:
            if _is_reparse(transaction.paths.backup):
                raise OSError
            temporary = transaction.paths.backup.parent / (
                f".{transaction.paths.backup.name}.superseded.{secrets.token_hex(12)}"
            )
            os.replace(transaction.paths.backup, temporary)
            transaction.superseded_backup.append(temporary)
        except Exception:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            raise IntegrationError("INTEGRATION_BACKUP_DISCARD_FAILED") from None
    _atomic_write(
        transaction.paths.backup,
        encrypted,
        transaction.paths.state_root,
        transaction.created_dirs,
    )
    if transaction.config_candidate is None:
        raise IntegrationError("CODEX_CONFIG_INVALID")
    _atomic_write(
        transaction.paths.config,
        transaction.config_candidate,
        transaction.paths.root,
        transaction.created_dirs,
    )


def _install_managed_skill(transaction: _InstallTransaction) -> None:
    if not transaction.requested_skill:
        return
    _ensure_directory(transaction.paths.skill, transaction.paths.root, transaction.created_dirs)
    previous = _manifest_skill_map(transaction.previous_manifest)
    for name, data in transaction.skill_source:
        target = transaction.paths.skill / name
        current = _read_file(target, 256 * 1024)
        if current.existed and name not in previous:
            raise IntegrationError("SKILL_CONFLICT")
        if current.existed and _sha256(current.data) != previous.get(name):
            raise IntegrationError("SKILL_CONFLICT")
        _atomic_write(
            target,
            data,
            transaction.paths.root,
            transaction.created_dirs,
        )


def _commit_ownership_manifest(transaction: _InstallTransaction) -> None:
    previous = transaction.previous_manifest
    if previous is not None and not transaction.requested_skill:
        skill_files = [
            {"path": name, "sha256": digest}
            for name, digest in sorted(_manifest_skill_map(previous).items())
        ]
    elif transaction.install_skill:
        skill_files = _skill_hashes(transaction.skill_source)
    else:
        skill_files = []
    if previous is not None and not transaction.requested_mcp:
        block = transaction.existing_managed_block or b""
        config_before = transaction.config_before.data
        config_hash = previous["config_before_sha256"]
        block_hash = previous["managed_block_sha256"]
    else:
        block = transaction.managed_block if transaction.enable_mcp else b""
        config_before = transaction.config_before.data
        config_hash = None
        block_hash = None
    rendered = _manifest_bytes(
        install_skill=transaction.install_skill,
        enable_mcp=transaction.enable_mcp,
        config_before=config_before,
        managed_block=block,
        skill_files=skill_files,
        config_before_sha256=config_hash,
        managed_block_sha256=block_hash,
    )
    _atomic_write(
        transaction.paths.manifest,
        rendered,
        transaction.paths.state_root,
        transaction.created_dirs,
    )


def _discard_superseded_backup(transaction: _InstallTransaction) -> None:
    for path in tuple(transaction.superseded_backup):
        try:
            _remove_file(
                path,
                transaction.paths.state_root,
                "INTEGRATION_BACKUP_DISCARD_FAILED",
            )
        except IntegrationError:
            raise IntegrationError("INTEGRATION_BACKUP_DISCARD_FAILED") from None
        transaction.superseded_backup.remove(path)


def _rollback_install(transaction: _InstallTransaction) -> bool:
    success = True
    try:
        _restore_file(
            transaction.paths.config,
            transaction.config_before,
            transaction.paths.root,
            transaction.created_dirs,
        )
    except Exception:
        success = False
    for name, state in transaction.skill_before:
        try:
            _restore_file(
                transaction.paths.skill / name,
                state,
                transaction.paths.root,
                transaction.created_dirs,
            )
        except Exception:
            success = False
    try:
        _restore_file(
            transaction.paths.backup,
            transaction.backup_before,
            transaction.paths.state_root,
            transaction.created_dirs,
        )
    except Exception:
        success = False
    try:
        _restore_file(
            transaction.paths.manifest,
            transaction.manifest_before,
            transaction.paths.state_root,
            transaction.created_dirs,
        )
    except Exception:
        success = False
    if success:
        for path in tuple(transaction.superseded_backup):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                success = False
    for directory in sorted(transaction.created_dirs, key=lambda item: len(item.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass
    return success


def _prepare_uninstall_transaction(
    *, environ: Mapping[str, str]
) -> _UninstallTransaction:
    paths = _user_paths(environ)
    pending_state = _read_file(
        paths.pending,
        MANIFEST_LIMIT,
        too_large_code="INTEGRATION_MANIFEST_INVALID",
    )
    pending = _load_pending(pending_state)
    manifest_state = _read_file(
        paths.manifest,
        MANIFEST_LIMIT,
        too_large_code="INTEGRATION_MANIFEST_INVALID",
    )
    manifest = _load_manifest(manifest_state)
    config = _read_file(
        paths.config, CONFIG_LIMIT, too_large_code="CODEX_CONFIG_TOO_LARGE"
    )
    markers = _marker_range(config.data)
    backup = _read_file(paths.backup, _MAX_BACKUP_BYTES)
    skill_state = _skill_snapshot(paths.skill)
    known_skill = any(state.existed for _, state in skill_state)
    if pending is None:
        if manifest is None:
            if markers is not None:
                raise IntegrationError("CODEX_CONFIG_CONFLICT")
            if backup.existed or known_skill:
                raise IntegrationError("INTEGRATION_OWNERSHIP_CONFLICT")
            raise IntegrationNotPresent
        manifest_present = True
        backup_expected_existed = backup.existed
        backup_expected_sha256 = _sha256(backup.data)
        if manifest["enable_mcp"] is True:
            if markers is None:
                raise IntegrationError("CODEX_CONFIG_CONFLICT")
            if _sha256(markers[2]) != manifest["managed_block_sha256"]:
                raise IntegrationError("CODEX_CONFIG_CONFLICT")
            if not backup.existed:
                raise IntegrationError("INTEGRATION_BACKUP_INVALID")
        elif markers is not None:
            raise IntegrationError("CODEX_CONFIG_CONFLICT")
        elif backup.existed:
            raise IntegrationError("INTEGRATION_OWNERSHIP_CONFLICT")
    else:
        pending_manifest, pending_manifest_sha256, backup_expected_existed, backup_expected_sha256 = pending
        if manifest_state.existed:
            if _sha256(manifest_state.data) != pending_manifest_sha256:
                raise IntegrationError("INTEGRATION_MANIFEST_INVALID")
            if manifest != pending_manifest:
                raise IntegrationError("INTEGRATION_MANIFEST_INVALID")
            manifest_present = True
        else:
            manifest = pending_manifest
            manifest_present = False
        if backup.existed:
            if not backup_expected_existed:
                raise IntegrationError("INTEGRATION_OWNERSHIP_CONFLICT")
            if _sha256(backup.data) != backup_expected_sha256:
                raise IntegrationError("INTEGRATION_BACKUP_INVALID")
        elif backup_expected_existed and manifest_present:
            raise IntegrationError("INTEGRATION_BACKUP_INVALID")
        if manifest["enable_mcp"] is True:
            if markers is not None:
                if _sha256(markers[2]) != manifest["managed_block_sha256"]:
                    raise IntegrationError("CODEX_CONFIG_CONFLICT")
                if not backup.existed:
                    raise IntegrationError("INTEGRATION_BACKUP_INVALID")
        elif markers is not None:
            raise IntegrationError("CODEX_CONFIG_CONFLICT")
        elif backup.existed:
            raise IntegrationError("INTEGRATION_OWNERSHIP_CONFLICT")
    assert manifest is not None
    return _UninstallTransaction(
        paths=paths,
        manifest=manifest,
        config=config,
        managed_block=markers[2] if markers is not None else None,
        skill_files=tuple(
            (item["path"], item["sha256"]) for item in manifest["skill_files"]
        ),
        backup=backup,
        pending=pending_state,
        manifest_present=manifest_present,
        backup_expected_existed=backup_expected_existed,
        backup_expected_sha256=backup_expected_sha256,
    )


def _remove_managed_mcp(
    transaction: _UninstallTransaction,
    *,
    unprotect: Callable[[bytes], bytes],
) -> None:
    if transaction.manifest["enable_mcp"] is not True:
        return
    if transaction.managed_block is None:
        if transaction.pending.existed:
            return
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    try:
        plaintext = unprotect(transaction.backup.data)
        original, existed = _decode_backup(plaintext)
        if (
            _sha256(original) != transaction.manifest["config_before_sha256"]
            or type(existed) is not bool
        ):
            raise IntegrationError("INTEGRATION_BACKUP_INVALID")
    except DpapiError as error:
        code = (
            "INTEGRATION_DPAPI_UNAVAILABLE"
            if str(error) == "DPAPI_UNAVAILABLE"
            else "INTEGRATION_BACKUP_INVALID"
        )
        raise IntegrationError(code) from None
    except IntegrationError:
        raise
    except Exception:
        raise IntegrationError("INTEGRATION_BACKUP_INVALID") from None
    markers = _marker_range(transaction.config.data)
    if markers is None or markers[2] != transaction.managed_block:
        raise IntegrationError("CODEX_CONFIG_CONFLICT")
    remaining = transaction.config.data[: markers[0]] + transaction.config.data[markers[1] :]
    _parse_config(remaining)
    if remaining or existed:
        _atomic_write(
            transaction.paths.config,
            remaining,
            transaction.paths.root,
            [],
        )
    else:
        _remove_file(
            transaction.paths.config,
            transaction.paths.root,
            "INTEGRATION_CLEANUP_REQUIRED",
        )


def _remove_unchanged_skill_files(transaction: _UninstallTransaction) -> bool:
    clean = True
    for name, expected in transaction.skill_files:
        target = transaction.paths.skill / name
        state = _read_file(target, 256 * 1024)
        if not state.existed:
            continue
        if _sha256(state.data) != expected:
            clean = False
            continue
        try:
            _remove_file(target, transaction.paths.root, "INTEGRATION_CLEANUP_REQUIRED")
        except IntegrationError:
            raise
    return clean


def _skill_has_unowned_entries(
    path: Path, expected: set[str]
) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise IntegrationError("INTEGRATION_CLEANUP_REQUIRED") from None
    if _is_reparse(path) or not stat.S_ISDIR(info.st_mode):
        raise IntegrationError("INTEGRATION_CLEANUP_REQUIRED")
    _validate_skill_tree(path)
    try:
        entries = list(os.scandir(path))
    except OSError:
        raise IntegrationError("INTEGRATION_CLEANUP_REQUIRED") from None
    return any(entry.name not in expected for entry in entries)


def _skill_files_are_unchanged(transaction: _UninstallTransaction) -> bool:
    if _skill_has_unowned_entries(
        transaction.paths.skill,
        {name for name, _ in transaction.skill_files},
    ):
        return False
    for name, expected in transaction.skill_files:
        state = _read_file(transaction.paths.skill / name, 256 * 1024)
        if state.existed and _sha256(state.data) != expected:
            return False
    return True


def _begin_uninstall(transaction: _UninstallTransaction) -> None:
    if transaction.pending.existed:
        return
    _atomic_write(
        transaction.paths.pending,
        _pending_bytes(transaction.manifest, transaction.backup),
        transaction.paths.state_root,
        [],
    )


def _remove_recovery_and_manifest(transaction: _UninstallTransaction) -> None:
    if transaction.manifest_present:
        _remove_file(
            transaction.paths.manifest,
            transaction.paths.state_root,
            "INTEGRATION_CLEANUP_REQUIRED",
        )
    if transaction.manifest["enable_mcp"] is True and transaction.backup.existed:
        _remove_file(
            transaction.paths.backup,
            transaction.paths.state_root,
            "INTEGRATION_CLEANUP_REQUIRED",
        )
    _remove_file(
        transaction.paths.pending,
        transaction.paths.state_root,
        "INTEGRATION_CLEANUP_REQUIRED",
    )


def install_integration(
    *,
    install_skill: bool,
    enable_mcp: bool,
    mcp_executable: Path | None = None,
    environ: Mapping[str, str] = os.environ,
    protect: Callable[[bytes], bytes] = protect_bytes,
) -> str:
    if type(install_skill) is not bool or type(enable_mcp) is not bool:
        return "INTEGRATION_INPUT_INVALID"
    if not install_skill and not enable_mcp:
        return "INTEGRATION_INPUT_INVALID"
    transaction: _InstallTransaction | None = None
    try:
        transaction = _prepare_install_transaction(
            install_skill=install_skill,
            enable_mcp=enable_mcp,
            mcp_executable=mcp_executable,
            environ=environ,
        )
        if enable_mcp:
            _install_managed_mcp(transaction, protect=protect)
        if install_skill:
            _install_managed_skill(transaction)
        _commit_ownership_manifest(transaction)
        _discard_superseded_backup(transaction)
        return "INTEGRATION_INSTALLED"
    except IntegrationError as error:
        if transaction is not None and not _rollback_install(transaction):
            return "INTEGRATION_ROLLBACK_FAILED"
        return error.code
    except Exception:
        if transaction is not None and not _rollback_install(transaction):
            return "INTEGRATION_ROLLBACK_FAILED"
        return "INTEGRATION_INSTALL_FAILED"


def uninstall_integration(
    *,
    environ: Mapping[str, str] = os.environ,
    unprotect: Callable[[bytes], bytes] = unprotect_bytes,
) -> str:
    try:
        transaction = _prepare_uninstall_transaction(environ=environ)
    except IntegrationNotPresent:
        return "INTEGRATION_NOT_PRESENT"
    except IntegrationError as error:
        return error.code
    try:
        _begin_uninstall(transaction)
        if not _skill_files_are_unchanged(transaction):
            return "INTEGRATION_CLEANUP_REQUIRED"
        _remove_managed_mcp(transaction, unprotect=unprotect)
        if not _remove_unchanged_skill_files(transaction):
            return "INTEGRATION_CLEANUP_REQUIRED"
        _remove_recovery_and_manifest(transaction)
        return "INTEGRATION_REMOVED"
    except IntegrationError as error:
        return error.code
    except Exception:
        return "INTEGRATION_CLEANUP_REQUIRED"
