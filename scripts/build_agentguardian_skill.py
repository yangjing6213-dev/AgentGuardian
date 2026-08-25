from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import stat
import sys
import tempfile
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agentguardian.domain import _UNMASKED_SECRET_PATTERNS  # noqa: E402


SKILL_VERSION = "0.1.0"
ALLOWED_FILES = ("LICENSE", "README.md", "SKILL.md")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 512 * 1024

_EXPECTED_FRONTMATTER = (
    "---\n"
    "name: agentguardian\n"
    "description: Use AgentGuardian to audit one bounded local AI configuration scope, browser history database aggregate, current clipboard value, or public share URL. Requires the local AgentGuardian MCP tools and must not be used for regulated or highly sensitive data.\n"
    "metadata:\n"
    '  version: "0.1.0"\n'
    '  requires-agentguardian: ">=0.3.0a1,<0.4"\n'
    "---\n"
)
_README_REQUIREMENTS = (
    "version",
    "Apache-2.0",
    "%USERPROFILE%\\.agents\\skills\\agentguardian",
    "prepare_audit",
    "run_prepared_audit",
    "personal_non_regulated",
    "Codex model context",
    "not production-safe",
)
_DOWNLOADER_MARKERS = (
    "curl ",
    "wget ",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr ",
    "bitsadmin",
    "certutil -urlcache",
)
_EXECUTABLE_HEADERS = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _fixed_error(message: str) -> ValueError:
    return ValueError(message)


def _is_reparse_or_link(path: Path, metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _same_file_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        first.st_size,
        first.st_mtime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_size,
        second.st_mtime_ns,
    )


def _read_checked_file(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if _is_reparse_or_link(path, before) or not stat.S_ISREG(before.st_mode):
            raise _fixed_error("skill source entry is invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(os.fspath(path), flags)
        opened = os.fstat(descriptor)
        if _is_reparse_or_link(path, opened) or not _same_file_snapshot(before, opened):
            raise _fixed_error("skill source entry changed")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if _is_reparse_or_link(path, after) or not _same_file_snapshot(opened, after):
            raise _fixed_error("skill source entry changed")
        return b"".join(chunks)
    except ValueError:
        raise
    except OSError:
        raise _fixed_error("skill source entry is unreadable") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _validate_directory_parents(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    try:
        for parent in absolute.parents:
            if not os.path.lexists(parent):
                continue
            metadata = os.lstat(parent)
            if _is_reparse_or_link(parent, metadata) or not stat.S_ISDIR(metadata.st_mode):
                raise _fixed_error("skill path is invalid")
    except ValueError:
        raise
    except OSError:
        raise _fixed_error("skill path is invalid") from None


def _validate_bytes(name: str, data: bytes) -> str:
    if len(data) > MAX_FILE_BYTES:
        raise _fixed_error("skill file is too large")
    if b"\x00" in data or any(data.startswith(header) for header in _EXECUTABLE_HEADERS):
        raise _fixed_error("skill file contains a forbidden binary marker")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _fixed_error("skill file is not valid UTF-8") from None
    folded = text.casefold()
    if any(marker in folded for marker in _DOWNLOADER_MARKERS):
        raise _fixed_error("skill file contains a downloader command")
    if any(pattern.search(text) for pattern in _UNMASKED_SECRET_PATTERNS):
        raise _fixed_error("skill file contains a secret pattern")
    if name == "SKILL.md" and not text.startswith(_EXPECTED_FRONTMATTER):
        raise _fixed_error("skill frontmatter is invalid")
    if name == "README.md" and any(value not in text for value in _README_REQUIREMENTS):
        raise _fixed_error("skill README is incomplete")
    return text


def _validated_source(source_root: Path) -> dict[str, bytes]:
    _validate_directory_parents(source_root)
    try:
        source_metadata = os.lstat(source_root)
        if _is_reparse_or_link(source_root, source_metadata):
            raise _fixed_error("skill source is invalid")
        root = source_root.resolve(strict=True)
        root_metadata = os.lstat(root)
    except (OSError, RuntimeError):
        raise _fixed_error("skill source is invalid") from None
    if not stat.S_ISDIR(root_metadata.st_mode) or _is_reparse_or_link(root, root_metadata):
        raise _fixed_error("skill source is invalid")

    try:
        entries = list(os.scandir(root))
    except OSError:
        raise _fixed_error("skill source is unreadable") from None
    names = sorted(entry.name for entry in entries)
    if names != sorted(ALLOWED_FILES) or any(not name.isascii() for name in names):
        raise _fixed_error("skill source contains unexpected entries")

    files: dict[str, bytes] = {}
    total = 0
    for name in ALLOWED_FILES:
        path = root / name
        try:
            metadata = os.lstat(path)
            if _is_reparse_or_link(path, metadata) or not stat.S_ISREG(metadata.st_mode):
                raise _fixed_error("skill source entry is invalid")
        except ValueError:
            raise
        except OSError:
            raise _fixed_error("skill source entry is unreadable") from None
        data = _read_checked_file(path)
        _validate_bytes(name, data)
        files[name] = data
        total += len(data)
    if total > MAX_TOTAL_BYTES:
        raise _fixed_error("skill source is too large")
    if files["LICENSE"] != _read_checked_file(PROJECT_ROOT / "LICENSE"):
        raise _fixed_error("skill license does not match project license")
    return files


def _new_local_output(output_root: Path) -> Path:
    _validate_directory_parents(output_root)
    try:
        if os.path.lexists(output_root):
            existing = os.lstat(output_root)
            if _is_reparse_or_link(output_root, existing):
                raise _fixed_error("skill output is invalid")
        else:
            output_root.mkdir(parents=True, exist_ok=True)
        metadata = os.lstat(output_root)
    except ValueError:
        raise
    except OSError:
        raise _fixed_error("skill output is invalid") from None
    if _is_reparse_or_link(output_root, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise _fixed_error("skill output is invalid")
    return output_root


def _write_temporary_bytes(output: Path, data: bytes, suffix: str) -> Path:
    descriptor: int | None = None
    name: str | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=".agentguardian-skill-",
            suffix=suffix,
            dir=os.fspath(output),
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return Path(name)
    except (OSError, ValueError):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass
        raise _fixed_error("skill build failed") from None


def _remove_file(path: Path) -> None:
    try:
        if os.path.lexists(path):
            os.unlink(path)
    except OSError:
        pass


def _existing_regular_bytes(path: Path) -> bytes | None:
    if not os.path.lexists(path):
        return None
    return _read_checked_file(path)


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in ALLOWED_FILES:
            info = zipfile.ZipInfo(f"agentguardian/{name}", ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, files[name])
    return buffer.getvalue()


def _rollback_artifacts(
    target: Path,
    checksum: Path,
    target_backup: Path | None,
    checksum_backup: Path | None,
    target_installed: bool,
    checksum_installed: bool,
) -> None:
    if target_installed:
        _remove_file(target)
    if checksum_installed:
        _remove_file(checksum)
    for backup, destination in (
        (target_backup, target),
        (checksum_backup, checksum),
    ):
        if backup is None:
            continue
        try:
            if os.path.lexists(backup):
                os.replace(os.fspath(backup), os.fspath(destination))
        except OSError:
            pass


def build_skill(source_root: Path, output_root: Path) -> tuple[Path, str]:
    files = _validated_source(source_root)
    output = _new_local_output(output_root)
    target = output / f"AgentGuardian-Skill-{SKILL_VERSION}.zip"
    checksum = output / f"{target.name}.sha256"
    old_target = _existing_regular_bytes(target)
    old_checksum = _existing_regular_bytes(checksum)
    zip_data = _zip_bytes(files)
    digest = hashlib.sha256(zip_data).hexdigest()
    checksum_data = f"{digest} *{target.name}\n".encode("ascii")
    zip_temp: Path | None = None
    checksum_temp: Path | None = None
    target_backup: Path | None = None
    checksum_backup: Path | None = None
    target_installed = False
    checksum_installed = False
    try:
        zip_temp = _write_temporary_bytes(output, zip_data, ".zip.tmp")
        checksum_temp = _write_temporary_bytes(output, checksum_data, ".sha256.tmp")
        if old_target is not None:
            target_backup = _write_temporary_bytes(output, old_target, ".zip.backup")
            os.replace(os.fspath(target), os.fspath(target_backup))
        if old_checksum is not None:
            checksum_backup = _write_temporary_bytes(output, old_checksum, ".sha256.backup")
            os.replace(os.fspath(checksum), os.fspath(checksum_backup))
        os.replace(os.fspath(zip_temp), os.fspath(target))
        zip_temp = None
        target_installed = True
        os.replace(os.fspath(checksum_temp), os.fspath(checksum))
        checksum_temp = None
        checksum_installed = True
    except ValueError:
        _rollback_artifacts(
            target,
            checksum,
            target_backup,
            checksum_backup,
            target_installed,
            checksum_installed,
        )
        raise
    except Exception:
        _rollback_artifacts(
            target,
            checksum,
            target_backup,
            checksum_backup,
            target_installed,
            checksum_installed,
        )
        raise _fixed_error("skill build failed") from None
    finally:
        for temporary in (zip_temp, checksum_temp, target_backup, checksum_backup):
            if temporary is not None:
                _remove_file(temporary)
    return target, digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the AgentGuardian Codex Skill ZIP")
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT / ".analysis" / "skill-build")
    arguments = parser.parse_args()
    target, digest = build_skill(PROJECT_ROOT / "skills" / "agentguardian", arguments.output_root)
    print(f"{target}\n{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
