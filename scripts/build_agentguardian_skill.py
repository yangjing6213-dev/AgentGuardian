from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
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
            data = path.read_bytes()
        except ValueError:
            raise
        except OSError:
            raise _fixed_error("skill source entry is unreadable") from None
        _validate_bytes(name, data)
        files[name] = data
        total += len(data)
    if total > MAX_TOTAL_BYTES:
        raise _fixed_error("skill source is too large")
    if files["LICENSE"] != (PROJECT_ROOT / "LICENSE").read_bytes():
        raise _fixed_error("skill license does not match project license")
    return files


def _new_local_output(output_root: Path) -> Path:
    try:
        output_root.mkdir(parents=True, exist_ok=True)
        metadata = os.lstat(output_root)
    except OSError:
        raise _fixed_error("skill output is invalid") from None
    if _is_reparse_or_link(output_root, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise _fixed_error("skill output is invalid")
    return output_root


def build_skill(source_root: Path, output_root: Path) -> tuple[Path, str]:
    files = _validated_source(source_root)
    output = _new_local_output(output_root)
    target = output / f"AgentGuardian-Skill-{SKILL_VERSION}.zip"
    try:
        if target.exists() and _is_reparse_or_link(target, os.lstat(target)):
            raise _fixed_error("skill output is invalid")
    except OSError:
        raise _fixed_error("skill output is invalid") from None
    with zipfile.ZipFile(
        target,
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
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (output / f"{target.name}.sha256").write_text(
        f"{digest} *{target.name}\n",
        encoding="ascii",
        newline="\n",
    )
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
