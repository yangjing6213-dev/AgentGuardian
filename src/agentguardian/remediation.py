from dataclasses import dataclass
from enum import Enum
import hashlib
import os
import pathlib
import re
import stat

from .discovery import _has_reparse_component


ACTION_REPLACE_FIXED_FILE = "replace_fixed_file"
MAX_REMEDIATION_BYTES = 2 * 1024 * 1024
_SHA256_LENGTH = 64
_OPENAI_BASE_URL = "https://api.openai.com/v1"
_OPENAI_BASE_URL_LINE = re.compile(
    r"(?im)^(?P<prefix>[ \t]*(?:export[ \t]+)?"
    r"(?:OPENAI_BASE_URL|openai_base_url)[ \t]*[:=][ \t]*[\"']?)"
    r"https?://[^\s\"'#]+"
    r"(?P<suffix>[\"']?[^\r\n]*)$"
)


class RemediationStatus(str, Enum):
    DRY_RUN = "dry_run"
    NOT_PERFORMED = "not_performed"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True, slots=True)
class RemediationPreview:
    action_id: str
    status: RemediationStatus
    target_name: str
    target_sha256: str
    replacement_sha256: str
    backup_name: str
    limits: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RemediationResult:
    action_id: str
    status: RemediationStatus
    target_name: str
    original_sha256: str | None
    resulting_sha256: str | None
    backup_name: str
    limits: tuple[str, ...]


def preview_fixed_replacement(
    path: pathlib.Path,
    *,
    expected_sha256: str,
    replacement: bytes,
    action_id: str = ACTION_REPLACE_FIXED_FILE,
) -> RemediationPreview:
    _validate_action(action_id, expected_sha256, replacement)
    target, current = _read_target(path)
    actual_sha256 = _sha256(current)
    if actual_sha256 != expected_sha256:
        raise ValueError("TARGET_HASH_MISMATCH")
    return RemediationPreview(
        action_id=action_id,
        status=RemediationStatus.DRY_RUN,
        target_name=target.name,
        target_sha256=actual_sha256,
        replacement_sha256=_sha256(replacement),
        backup_name=_backup_name(target),
        limits=(),
    )


def build_openai_base_url_replacement(
    content: bytes,
    *,
    action_id: str = ACTION_REPLACE_FIXED_FILE,
) -> bytes:
    """Build the only endpoint replacement currently allowed by the product."""
    _validate_action_id(action_id)
    if type(content) is not bytes:
        raise ValueError("TARGET_INVALID")
    if len(content) > MAX_REMEDIATION_BYTES:
        raise ValueError("TARGET_SIZE_LIMIT")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("TARGET_ENCODING_UNSUPPORTED") from None
    replacement, matches = _OPENAI_BASE_URL_LINE.subn(
        lambda match: f"{match.group('prefix')}{_OPENAI_BASE_URL}{match.group('suffix')}",
        text,
    )
    if matches == 0:
        raise ValueError("FIXED_TARGET_NOT_MATCHED")
    return replacement.encode("utf-8")


def preview_openai_base_url_replacement(
    path: pathlib.Path,
) -> RemediationPreview:
    target, current = _read_target(path)
    replacement = build_openai_base_url_replacement(current)
    return preview_fixed_replacement(
        target,
        expected_sha256=_sha256(current),
        replacement=replacement,
    )


def apply_openai_base_url_replacement(
    path: pathlib.Path,
    *,
    expected_sha256: str,
    confirmed: bool,
) -> RemediationResult:
    target = pathlib.Path(path)
    backup_name = _backup_name(target)
    try:
        target, current = _read_target(target)
        replacement = build_openai_base_url_replacement(current)
    except (OSError, ValueError) as error:
        return _not_performed(target, backup_name, (_limit_from_error(error),))
    return apply_fixed_replacement(
        target,
        expected_sha256=expected_sha256,
        replacement=replacement,
        confirmed=confirmed,
    )


def apply_fixed_replacement(
    path: pathlib.Path,
    *,
    expected_sha256: str,
    replacement: bytes,
    confirmed: bool,
    action_id: str = ACTION_REPLACE_FIXED_FILE,
) -> RemediationResult:
    _validate_action(action_id, expected_sha256, replacement)
    target = pathlib.Path(path)
    backup_name = _backup_name(target)
    if type(confirmed) is not bool:
        raise ValueError("CONFIRMATION_INVALID")
    if not confirmed:
        return _not_performed(target, backup_name, ("confirmation_required",))

    try:
        target, current = _read_target(target)
    except ValueError as error:
        return _not_performed(target, backup_name, (_limit_from_error(error),))
    original_sha256 = _sha256(current)
    if original_sha256 != expected_sha256:
        return _not_performed(target, backup_name, ("target_changed",))

    backup = target.with_name(backup_name)
    if backup.exists() or backup.is_symlink():
        return _not_performed(target, backup_name, ("backup_exists",))
    try:
        _validate_target(target)
        latest_target, latest = _read_target(target)
        if latest_target != target or _sha256(latest) != expected_sha256:
            return _not_performed(target, backup_name, ("target_changed",))
        _write_new_file(backup, latest, target.stat().st_mode)
        _validate_target(target)
        latest_target, latest = _read_target(target)
        if latest_target != target or _sha256(latest) != expected_sha256:
            return RemediationResult(
                action_id=action_id,
                status=RemediationStatus.NOT_PERFORMED,
                target_name=target.name,
                original_sha256=original_sha256,
                resulting_sha256=None,
                backup_name=backup_name,
                limits=("target_changed", "backup_retained"),
            )
        _write_replacement_atomically(target, replacement, target.stat().st_mode)
    except (OSError, ValueError) as error:
        return RemediationResult(
            action_id=action_id,
            status=RemediationStatus.NOT_PERFORMED,
            target_name=target.name,
            original_sha256=original_sha256,
            resulting_sha256=None,
            backup_name=backup_name,
            limits=(_limit_from_error(error), "backup_retained"),
        )
    return RemediationResult(
        action_id=action_id,
        status=RemediationStatus.APPLIED,
        target_name=target.name,
        original_sha256=original_sha256,
        resulting_sha256=_sha256(replacement),
        backup_name=backup_name,
        limits=(),
    )


def rollback_fixed_replacement(
    path: pathlib.Path,
    *,
    expected_replacement_sha256: str,
    action_id: str = ACTION_REPLACE_FIXED_FILE,
) -> RemediationResult:
    _validate_action_id(action_id)
    _validate_sha256(expected_replacement_sha256, "expected_replacement_sha256")
    target = pathlib.Path(path)
    backup_name = _backup_name(target)
    try:
        target, current = _read_target(target)
        backup = target.with_name(backup_name)
        _validate_target(backup)
        original = backup.read_bytes()
    except (OSError, ValueError) as error:
        return _not_performed(target, backup_name, (_limit_from_error(error),))
    if _sha256(current) != expected_replacement_sha256:
        return _not_performed(target, backup_name, ("target_changed",))
    if len(original) > MAX_REMEDIATION_BYTES:
        return _not_performed(target, backup_name, ("backup_size_limit",))
    try:
        _write_replacement_atomically(target, original, target.stat().st_mode)
        backup.unlink()
    except (OSError, ValueError) as error:
        return RemediationResult(
            action_id=action_id,
            status=RemediationStatus.NOT_PERFORMED,
            target_name=target.name,
            original_sha256=_sha256(original),
            resulting_sha256=None,
            backup_name=backup_name,
            limits=(_limit_from_error(error), "backup_retained"),
        )
    return RemediationResult(
        action_id=action_id,
        status=RemediationStatus.ROLLED_BACK,
        target_name=target.name,
        original_sha256=_sha256(original),
        resulting_sha256=_sha256(original),
        backup_name=backup_name,
        limits=(),
    )


def _validate_action(action_id: str, expected_sha256: str, replacement: bytes) -> None:
    _validate_action_id(action_id)
    _validate_sha256(expected_sha256, "expected_sha256")
    if type(replacement) is not bytes:
        raise ValueError("REPLACEMENT_INVALID")
    if len(replacement) > MAX_REMEDIATION_BYTES:
        raise ValueError("REPLACEMENT_SIZE_LIMIT")


def _validate_action_id(action_id: str) -> None:
    if action_id != ACTION_REPLACE_FIXED_FILE:
        raise ValueError("ACTION_NOT_ALLOWED")


def _validate_sha256(value: str, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name.upper()}_INVALID")


def _read_target(path: pathlib.Path) -> tuple[pathlib.Path, bytes]:
    target = pathlib.Path(path)
    _validate_target(target)
    data = target.read_bytes()
    if len(data) > MAX_REMEDIATION_BYTES:
        raise ValueError("TARGET_SIZE_LIMIT")
    _validate_target(target)
    return target, data


def _validate_target(path: pathlib.Path) -> None:
    if not isinstance(path, pathlib.Path):
        raise ValueError("TARGET_INVALID")
    if _is_unc(path):
        raise ValueError("UNC_TARGET_REJECTED")
    if _has_reparse_component(path):
        raise ValueError("REPARSE_TARGET_REJECTED")
    try:
        target_stat = os.lstat(path)
    except OSError:
        raise ValueError("TARGET_UNAVAILABLE") from None
    if not stat.S_ISREG(target_stat.st_mode):
        raise ValueError("TARGET_NOT_REGULAR")


def _is_unc(path: pathlib.Path) -> bool:
    value = os.fspath(path)
    return value.startswith(("\\\\", "//"))


def _backup_name(target: pathlib.Path) -> str:
    return f"{target.name}.agentguardian.bak"


def _write_new_file(path: pathlib.Path, data: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("BACKUP_EXISTS")
    path.write_bytes(data)
    os.chmod(path, stat.S_IMODE(mode))


def _write_replacement_atomically(path: pathlib.Path, data: bytes, mode: int) -> None:
    temporary = path.with_name(f".{path.name}.agentguardian.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("TEMP_EXISTS")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(mode))
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _limit_from_error(error: BaseException) -> str:
    message = str(error)
    return message.lower() if message.isascii() and message else "remediation_failed"


def _not_performed(
    target: pathlib.Path,
    backup_name: str,
    limits: tuple[str, ...],
) -> RemediationResult:
    return RemediationResult(
        action_id=ACTION_REPLACE_FIXED_FILE,
        status=RemediationStatus.NOT_PERFORMED,
        target_name=target.name,
        original_sha256=None,
        resulting_sha256=None,
        backup_name=backup_name,
        limits=limits,
    )
