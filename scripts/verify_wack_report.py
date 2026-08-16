"""Validate bounded WACK XML evidence without claiming Store acceptance.

Microsoft requires WACK command-line runs to execute in an active user session.
Whether a hosted CI runner provides that capability is deliberately unverified.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import xml.etree.ElementTree as ET
import zipfile


MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024


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
    folded = raw.upper()
    if b"<!DOCTYPE" in folded or b"<!ENTITY" in folded:
        raise WackEvidenceError("WACK_XML_DTD_FORBIDDEN")
    try:
        root = ET.fromstring(raw)
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
    if b"<!DOCTYPE" in manifest_raw.upper() or b"<!ENTITY" in manifest_raw.upper():
        raise WackEvidenceError("WACK_PACKAGE_MANIFEST_INVALID")
    try:
        root = ET.fromstring(manifest_raw)
    except (ET.ParseError, MemoryError, RecursionError):
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
    except (OSError, RuntimeError):
        raise WackEvidenceError("WACK_PACKAGE_INVALID") from None
    if not _regular_file(resolved):
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-tool-path", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--generated-at")
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
                    args.generated_at,
                    args.output,
                )
            ):
                parser.error("tool validation cannot be combined with report validation")
            print(validate_wack_tool_path(args.validate_tool_path))
            return 0
        if any(
            value is None
            for value in (
                args.report,
                args.evidence_root,
                args.package,
                args.source_commit,
                args.generated_at,
                args.output,
            )
        ):
            parser.error("all report validation arguments are required")
        result = verify_wack_report(
            args.report,
            args.evidence_root,
            package_path=args.package,
            source_commit=args.source_commit,
            generated_at=args.generated_at,
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
