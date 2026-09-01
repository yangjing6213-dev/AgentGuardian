"""Verify bounded machine-neutral Windows installer lifecycle evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_EVIDENCE_BYTES = 4096
_ERROR_CODE = re.compile(r"^[A-Z0-9_]{1,64}$")
_FAIL_KEYS = frozenset({"error", "schema", "status"})
_PASS_MARKERS = frozenset(
    {
        "base_install",
        "deleted_state",
        "downgrade_rejected",
        "launch_smoke",
        "no_system_integration",
        "retained_state",
        "start_menu",
        "uninstall_residue",
        "upgrade",
        "user_report_preserved",
    }
)
_PASS_KEYS = _PASS_MARKERS | frozenset(
    {"base_version", "candidate_version", "schema", "status"}
)


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def _without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _load_evidence(path: Path) -> dict[str, object]:
    if not path.is_absolute():
        raise ValueError("path is not absolute")
    metadata = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if not stat.S_ISREG(metadata.st_mode) or attributes & reparse_flag:
        raise ValueError("evidence is not a regular file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence size is invalid")
    with path.open("rb") as source:
        contents = source.read(MAX_EVIDENCE_BYTES + 1)
    if len(contents) != metadata.st_size or contents.startswith(b"\xef\xbb\xbf"):
        raise ValueError("evidence bytes are invalid")
    value = json.loads(
        contents.decode("utf-8", errors="strict"),
        object_pairs_hook=_without_duplicate_keys,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )
    if not isinstance(value, dict) or canonical_json_bytes(value) != contents:
        raise ValueError("evidence is not canonical")
    return value


def _invalid(code: str = "LIFECYCLE_EVIDENCE_INVALID") -> dict[str, str]:
    return {"error": code, "status": "fail"}


def verify_lifecycle_evidence(
    path: Path,
    lifecycle_exit_code: int,
    *,
    base_version: str,
    candidate_version: str,
) -> dict[str, str]:
    try:
        evidence = _load_evidence(path)
    except FileNotFoundError:
        return _invalid("LIFECYCLE_EVIDENCE_MISSING")
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return _invalid()

    if lifecycle_exit_code != 0:
        if (
            frozenset(evidence) != _FAIL_KEYS
            or type(evidence.get("schema")) is not int
            or evidence["schema"] != 1
            or evidence.get("status") != "fail"
            or not isinstance(evidence.get("error"), str)
            or _ERROR_CODE.fullmatch(evidence["error"]) is None
        ):
            return _invalid()
        return _invalid(evidence["error"])

    if (
        frozenset(evidence) != _PASS_KEYS
        or type(evidence.get("schema")) is not int
        or evidence["schema"] != 1
        or evidence.get("status") != "pass"
        or evidence.get("base_version") != base_version
        or evidence.get("candidate_version") != candidate_version
        or any(evidence.get(name) != "pass" for name in _PASS_MARKERS)
    ):
        return _invalid()
    return {"error": "", "status": "pass"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-path", type=Path, required=True)
    parser.add_argument("--lifecycle-exit-code", type=int, required=True)
    parser.add_argument("--base-version", required=True)
    parser.add_argument("--candidate-version", required=True)
    arguments = parser.parse_args()
    decision = verify_lifecycle_evidence(
        arguments.evidence_path,
        arguments.lifecycle_exit_code,
        base_version=arguments.base_version,
        candidate_version=arguments.candidate_version,
    )
    sys.stdout.buffer.write(canonical_json_bytes(decision))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
