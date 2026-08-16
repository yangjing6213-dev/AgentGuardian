"""Validate bounded WACK XML evidence without claiming Store acceptance.

Microsoft requires WACK command-line runs to execute in an active user session.
Whether a hosted CI runner provides that capability is deliberately unverified.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import zipfile

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MSIX_BYTES = 512 * 1024 * 1024
WACK_COMMAND_TIMEOUT_SECONDS = 60 * 60
_WTS_ACTIVE = 0
_WTS_CONNECT_STATE = 8


class WackEvidenceError(ValueError):
    """Fixed-code failure for untrusted WACK inputs or report content."""


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def validate_wack_tool_path(value: str | Path) -> Path:
    path = Path(value)
    program_files = os.environ.get("ProgramFiles(x86)")
    if not program_files or not path.is_absolute() or path.anchor.startswith("\\\\"):
        raise WackEvidenceError("WACK_TOOL_PATH_INVALID")
    expected = (
        Path(program_files)
        / "Windows Kits"
        / "10"
        / "App Certification Kit"
        / "appcert.exe"
    )
    try:
        if (
            path.resolve(strict=True) != expected.resolve(strict=True)
            or not _regular_file(path)
            or _has_reparse_component(path)
        ):
            raise WackEvidenceError("WACK_TOOL_PATH_INVALID")
    except (OSError, RuntimeError):
        raise WackEvidenceError("WACK_TOOL_PATH_INVALID") from None
    return path.resolve()


def wack_commands(
    tool_path: Path, package_path: Path, report_path: Path
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        (str(tool_path), "reset"),
        (
            str(tool_path),
            "test",
            "-appxpackagepath",
            str(package_path),
            "-reportoutputpath",
            str(report_path),
        ),
    )


def current_wack_session_state() -> str:
    if _query_wts_connect_state() != _WTS_ACTIVE:
        raise WackEvidenceError("WACK_SESSION_NOT_ACTIVE")
    return "active"


def run_wack_tool(
    tool_value: str | Path,
    package_value: str | Path,
    report_value: str | Path,
    evidence_root: str | Path,
    *,
    source_commit: str,
) -> dict[str, object]:
    current_wack_session_state()
    tool = validate_wack_tool_path(tool_value)
    package = _bounded_package_path(package_value)
    report = _new_report_path(report_value, evidence_root)
    if not _lower_sha(source_commit):
        raise WackEvidenceError("WACK_SOURCE_COMMIT_INVALID")
    package_sha_before = _sha256_file(package, "WACK_PACKAGE_INVALID")
    started = _utc_now()
    started_at = _format_utc(started)
    try:
        for command in wack_commands(tool, package, report):
            completed = subprocess.run(
                command,
                check=False,
                timeout=WACK_COMMAND_TIMEOUT_SECONDS,
            )
            if completed.returncode != 0:
                raise WackEvidenceError("WACK_TOOL_EXECUTION_FAILED")
    except WackEvidenceError:
        raise
    except (OSError, subprocess.SubprocessError):
        raise WackEvidenceError("WACK_TOOL_EXECUTION_FAILED") from None

    package_sha_after = _sha256_file(package, "WACK_PACKAGE_INVALID")
    if package_sha_after != package_sha_before:
        raise WackEvidenceError("WACK_PACKAGE_CHANGED")
    bounded_report = _bounded_report_path(report, evidence_root)
    try:
        report_stat = bounded_report.stat(follow_symlinks=False)
    except OSError:
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID") from None
    started_ns = int(started.timestamp() * 1_000_000_000)
    if report_stat.st_mtime_ns < started_ns or report_stat.st_ctime_ns < started_ns:
        raise WackEvidenceError("WACK_REPORT_NOT_NEW")
    completed_at = _utc_now()
    if completed_at < started:
        raise WackEvidenceError("WACK_REPORT_NOT_NEW")
    generated_at = _format_utc(completed_at)
    result = verify_wack_report(
        bounded_report,
        evidence_root,
        package_path=package,
        source_commit=source_commit,
        generated_at=generated_at,
    )
    if result["package_sha256"] != package_sha_after:
        raise WackEvidenceError("WACK_PACKAGE_CHANGED")
    result["invocation"] = {
        "binding_mode": "same_process_invocation",
        "package_sha_after": package_sha_after,
        "package_sha_before": package_sha_before,
        "report_created_after_start": True,
        "started_at": started_at,
    }
    return result


def verify_wack_report(
    report_path: str | Path,
    evidence_root: str | Path,
    *,
    package_path: str | Path,
    source_commit: str,
    generated_at: str,
) -> dict[str, object]:
    report = _bounded_report_path(report_path, evidence_root)
    if not _lower_sha(source_commit):
        raise WackEvidenceError("WACK_SOURCE_COMMIT_INVALID")
    _utc_seconds(generated_at)
    package, package_identity = read_msix_identity(package_path)
    try:
        raw = report.read_bytes()
    except OSError:
        raise WackEvidenceError("WACK_REPORT_READ_FAILED") from None
    try:
        root = ET.fromstring(
            raw,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException:
        raise WackEvidenceError("WACK_XML_DTD_FORBIDDEN") from None
    except (ET.ParseError, MemoryError, RecursionError):
        raise WackEvidenceError("WACK_XML_INVALID") from None
    if root.tag != "REPORT":
        raise WackEvidenceError("WACK_REPORT_SCHEMA_UNSUPPORTED")
    if root.get("OVERALL_RESULT") != "PASS":
        raise WackEvidenceError("WACK_RESULT_FAILED")
    if root.get("PARTIAL_RUN") == "TRUE":
        raise WackEvidenceError("WACK_PARTIAL_RUN")
    if root.get("PARTIAL_RUN") != "FALSE":
        raise WackEvidenceError("WACK_REPORT_SCHEMA_UNSUPPORTED")

    tool_version = root.get("VERSION")
    app_name = root.get("APP_NAME")
    app_version = root.get("APP_VERSION")
    report_id = root.get("ID")
    publisher_display_name = root.get("PUBLISHER_DISPLAY_NAME")
    if not all(
        _printable(value)
        for value in (
            tool_version,
            app_name,
            app_version,
            report_id,
            publisher_display_name,
        )
    ):
        raise WackEvidenceError("WACK_REPORT_SCHEMA_UNSUPPORTED")
    if app_version != package_identity["version"]:
        raise WackEvidenceError("WACK_PACKAGE_VERSION_MISMATCH")

    requirements = tuple(root.iter("REQUIREMENT"))
    tests = tuple(root.iter("TEST"))
    if not requirements or not tests:
        raise WackEvidenceError("WACK_REPORT_SCHEMA_UNSUPPORTED")
    results: list[str] = []
    for element in (*requirements, *tests):
        attribute_result = element.get("RESULT")
        direct_results = element.findall("RESULT")
        if attribute_result is not None:
            results.append(attribute_result.strip())
        if element.tag == "TEST" and len(direct_results) != 1:
            raise WackEvidenceError("WACK_REPORT_SCHEMA_UNSUPPORTED")
        for result in direct_results:
            results.append((result.text or "").strip())
    if any(result == "FAIL" for result in results):
        raise WackEvidenceError("WACK_RESULT_FAILED")
    if len(results) != len(tests) or any(result != "PASS" for result in results):
        raise WackEvidenceError("WACK_REPORT_SCHEMA_UNSUPPORTED")
    failed = sum(result == "FAIL" for result in results)
    return {
        "generated_at": generated_at,
        "overall_result": "PASS",
        "package_identity": package_identity,
        "package_sha256": _sha256_file(package, "WACK_PACKAGE_INVALID"),
        "report_fields": {
            "app_name": app_name,
            "app_version": app_version,
            "id": report_id,
            "id_semantics": "unverified",
            "publisher_display_name": publisher_display_name,
        },
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "schema": 2,
        "source_commit": source_commit,
        "source_commit_origin": "candidate_input",
        "test_counts": {
            "failed": failed,
            "passed": len(results) - failed,
            "requirements": len(requirements),
            "tests": len(tests),
            "total": len(results),
        },
        "tool_version": tool_version,
    }


def read_msix_identity(package_value: str | Path) -> tuple[Path, dict[str, str]]:
    package = _bounded_package_path(package_value)
    try:
        with zipfile.ZipFile(package) as archive:
            manifests = [
                info
                for info in archive.infolist()
                if info.filename.casefold() == "appxmanifest.xml"
            ]
            if (
                len(manifests) != 1
                or manifests[0].filename != "AppxManifest.xml"
                or manifests[0].is_dir()
                or manifests[0].flag_bits & 1
                or manifests[0].file_size > MAX_MANIFEST_BYTES
            ):
                raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID")
            manifest_raw = archive.read(manifests[0])
    except WackEvidenceError:
        raise
    except (OSError, KeyError, MemoryError, RuntimeError, zipfile.BadZipFile):
        raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID") from None
    try:
        root = ET.fromstring(
            manifest_raw,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedXmlException, ET.ParseError, MemoryError, RecursionError):
        raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID") from None
    if _local_name(root.tag) != "Package":
        raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID")
    identities = [element for element in root if _local_name(element.tag) == "Identity"]
    if len(identities) != 1:
        raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID")
    identity = identities[0]
    values = {
        "name": identity.get("Name"),
        "publisher": identity.get("Publisher"),
        "version": identity.get("Version"),
        "processor_architecture": identity.get("ProcessorArchitecture"),
    }
    if (
        not all(_printable(value) for value in values.values())
        or values["processor_architecture"] != "x64"
    ):
        raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID")
    return package, values


def _bounded_package_path(package_value: str | Path) -> Path:
    package = Path(package_value)
    if (
        not package.is_absolute()
        or package.anchor.startswith("\\\\")
        or package.suffix.casefold() != ".msix"
        or _has_reparse_component(package)
    ):
        raise WackEvidenceError("WACK_PACKAGE_INVALID")
    try:
        resolved = package.resolve(strict=True)
        size = resolved.stat(follow_symlinks=False).st_size
    except (OSError, RuntimeError):
        raise WackEvidenceError("WACK_PACKAGE_INVALID") from None
    if not _regular_file(resolved) or size <= 0 or size > MAX_MSIX_BYTES:
        raise WackEvidenceError("WACK_PACKAGE_INVALID")
    return resolved


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _sha256_file(path: Path, code: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise WackEvidenceError(code) from None
    return digest.hexdigest()


def _bounded_report_path(report_value: str | Path, root_value: str | Path) -> Path:
    report = Path(report_value)
    root = Path(root_value)
    if (
        not report.is_absolute()
        or not root.is_absolute()
        or report.anchor.startswith("\\\\")
        or root.anchor.startswith("\\\\")
        or _has_reparse_component(report)
        or _has_reparse_component(root)
    ):
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_report = report.resolve(strict=True)
        size = resolved_report.stat(follow_symlinks=False).st_size
    except (OSError, RuntimeError):
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID") from None
    if (
        not resolved_root.is_dir()
        or not resolved_report.is_relative_to(resolved_root)
        or not _regular_file(resolved_report)
        or size > MAX_REPORT_BYTES
    ):
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID")
    return resolved_report


def _new_report_path(report_value: str | Path, root_value: str | Path) -> Path:
    report = Path(report_value)
    root = Path(root_value)
    if (
        not report.is_absolute()
        or not root.is_absolute()
        or report.anchor.startswith("\\\\")
        or root.anchor.startswith("\\\\")
        or os.path.lexists(report)
        or _has_reparse_component(root)
    ):
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID")
    try:
        resolved_root = root.resolve(strict=True)
        resolved_parent = report.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID") from None
    if (
        not resolved_root.is_dir()
        or resolved_parent != resolved_root
        or report.name != "wack-report.xml"
        or _has_reparse_component(resolved_parent)
    ):
        raise WackEvidenceError("WACK_REPORT_PATH_INVALID")
    return resolved_parent / report.name


def _query_wts_connect_state() -> int:
    if os.name != "nt":
        raise WackEvidenceError("WACK_SESSION_QUERY_FAILED")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    session_id = wintypes.DWORD()
    kernel32.GetCurrentProcessId.argtypes = ()
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    kernel32.ProcessIdToSessionId.argtypes = (
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    process_id = kernel32.GetCurrentProcessId()
    if not kernel32.ProcessIdToSessionId(process_id, ctypes.byref(session_id)):
        raise WackEvidenceError("WACK_SESSION_QUERY_FAILED")

    buffer = ctypes.c_void_p()
    returned = wintypes.DWORD()
    wtsapi32.WTSQuerySessionInformationW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    wtsapi32.WTSQuerySessionInformationW.restype = wintypes.BOOL
    wtsapi32.WTSFreeMemory.argtypes = (ctypes.c_void_p,)
    wtsapi32.WTSFreeMemory.restype = None
    if not wtsapi32.WTSQuerySessionInformationW(
        None,
        session_id.value,
        _WTS_CONNECT_STATE,
        ctypes.byref(buffer),
        ctypes.byref(returned),
    ):
        raise WackEvidenceError("WACK_SESSION_QUERY_FAILED")
    try:
        if returned.value != ctypes.sizeof(wintypes.DWORD) or not buffer.value:
            raise WackEvidenceError("WACK_SESSION_QUERY_FAILED")
        return ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    finally:
        wtsapi32.WTSFreeMemory(buffer)


def _has_reparse_component(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            attributes = getattr(
                current.stat(follow_symlinks=False), "st_file_attributes", 0
            )
        except OSError:
            return True
        if current.is_symlink() or attributes & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        ):
            return True
    return False


def _regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except OSError:
        return False


def _lower_sha(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _printable(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and len(value) <= 256
        and all(ord(character) >= 32 for character in value)
    )


def _utc_seconds(value: str) -> None:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        raise WackEvidenceError("WACK_GENERATED_AT_INVALID") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise WackEvidenceError("WACK_GENERATED_AT_INVALID")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-tool-path", type=Path)
    parser.add_argument("--check-active-session", action="store_true")
    parser.add_argument("--run-tool", action="store_true")
    parser.add_argument("--tool", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.validate_tool_path is not None:
            if any(
                value is not None
                for value in (
                    args.report,
                    args.evidence_root,
                    args.package,
                    args.source_commit,
                    args.output,
                    args.tool,
                )
            ) or args.check_active_session or args.run_tool:
                parser.error("tool validation cannot be combined with report validation")
            print(validate_wack_tool_path(args.validate_tool_path))
            return 0
        if args.check_active_session:
            if any(
                value is not None
                for value in (
                    args.tool,
                    args.report,
                    args.evidence_root,
                    args.package,
                    args.source_commit,
                    args.output,
                )
            ) or args.run_tool:
                parser.error("session validation cannot be combined")
            print(current_wack_session_state())
            return 0
        if not args.run_tool:
            parser.error("one WACK operation is required")
        if any(
            value is None
            for value in (
                args.tool,
                args.report,
                args.evidence_root,
                args.package,
                args.source_commit,
                args.output,
            )
        ):
            parser.error("all WACK run arguments are required")
        result = run_wack_tool(
            args.tool,
            args.package,
            args.report,
            args.evidence_root,
            source_commit=args.source_commit,
        )
        output = args.output
        if (
            not output.is_absolute()
            or output.anchor.startswith("\\\\")
            or output.suffix.casefold() != ".json"
            or output.exists()
            or not output.parent.is_dir()
            or _has_reparse_component(output.parent)
        ):
            raise WackEvidenceError("WACK_OUTPUT_PATH_INVALID")
        output.write_bytes(canonical_json_bytes(result))
    except WackEvidenceError as error:
        parser.error(str(error))
    print(canonical_json_bytes(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
