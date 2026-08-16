"""Verify the bounded Personal Store source and payload release profile."""

from __future__ import annotations

import argparse
import ast
from functools import lru_cache
from fnmatch import fnmatchcase
import json
from pathlib import Path, PurePosixPath
import stat
import sys
from typing import Any


MAX_PROFILE_BYTES = 64 * 1024
MAX_RUNTIME_SOURCE_BYTES = 256 * 1024
_MAX_ARRAY_ITEMS = 128
_MAX_VALUE_LENGTH = 256
_MAX_RUNTIME_AST_NODES = 16_384
_PROFILE_KEYS = frozenset(
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
_ARRAY_KEYS = _PROFILE_KEYS - {"name", "schema"}
_PATH_ARRAY_KEYS = frozenset(
    {
        "active_document_paths",
        "declared_network_modules",
        "forbidden_payload_globs",
        "forbidden_source_globs",
        "required_source_paths",
    }
)


class ProfileViolation(ValueError):
    """A fixed-code release-profile failure with no private context."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def load_profile(profile_path: str | Path) -> dict[str, Any]:
    path = Path(profile_path).absolute()
    if _has_reparse_component(path):
        raise ProfileViolation("PROFILE_REPARSE_POINT")
    try:
        if not path.is_file():
            raise ProfileViolation("PROFILE_JSON_INVALID")
        size = path.stat().st_size
        if size > MAX_PROFILE_BYTES:
            raise ProfileViolation("PROFILE_JSON_TOO_LARGE")
        raw = path.read_bytes()
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except ProfileViolation:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ProfileViolation("PROFILE_JSON_INVALID") from None
    if not isinstance(value, dict) or set(value) != _PROFILE_KEYS:
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    if raw != canonical_json_bytes(value):
        raise ProfileViolation("PROFILE_JSON_INVALID")
    _validate_profile_value(value)
    return value


def _validate_profile_value(value: dict[str, Any]) -> None:
    if set(value) != _PROFILE_KEYS:
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    if value["name"] != "personal_store_release":
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    for key in _ARRAY_KEYS:
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
    for key in _PATH_ARRAY_KEYS:
        if any(not _safe_relative_pattern(item) for item in value[key]):
            raise ProfileViolation("PROFILE_PATH_INVALID")


def verify_profile(
    project_root: str | Path, profile_path: str | Path
) -> dict[str, str]:
    root = Path(project_root).absolute()
    if not root.is_dir() or _has_reparse_component(root):
        raise ProfileViolation("PROFILE_PROJECT_INVALID")
    candidate = Path(profile_path)
    candidate = candidate.absolute() if candidate.is_absolute() else (root / candidate).absolute()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ProfileViolation("PROFILE_PATH_INVALID") from None
    profile = load_profile(candidate)

    source_entries = _project_entries(root, profile["forbidden_source_globs"])
    if any(
        _matches_any(relative, profile["forbidden_source_globs"])
        for relative, _ in source_entries
    ):
        raise ProfileViolation("PROFILE_SOURCE_FORBIDDEN")
    for relative in profile["required_source_paths"]:
        if not _required_file(root, relative):
            raise ProfileViolation("PROFILE_REQUIRED_SOURCE_MISSING")

    _verify_runtime(root, profile)
    _verify_workflows(root, profile["forbidden_workflow_tokens"])
    _verify_documents(root, profile)
    return {"profile": "personal_store_release", "status": "pass"}


def verify_payload(bundle_root: str | Path, profile: dict[str, Any]) -> None:
    if not isinstance(profile, dict):
        raise ProfileViolation("PROFILE_SCHEMA_INVALID")
    _validate_profile_value(profile)
    root = Path(bundle_root).absolute()
    if not root.is_dir() or _has_reparse_component(root):
        raise ProfileViolation("PROFILE_PAYLOAD_INVALID")
    for relative, _ in _walk(root, root):
        if _matches_any(relative, profile["forbidden_payload_globs"]):
            raise ProfileViolation("PROFILE_PAYLOAD_FORBIDDEN")


def _verify_runtime(root: Path, profile: dict[str, Any]) -> None:
    source_root = root / "src" / "agentguardian"
    modules: list[str] = []
    for relative, path in _walk(source_root, root):
        if not path.is_file() or path.suffix.casefold() != ".py":
            continue
        try:
            with path.open("rb") as source_file:
                source = source_file.read(MAX_RUNTIME_SOURCE_BYTES + 1)
            if len(source) > MAX_RUNTIME_SOURCE_BYTES:
                raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")
            tree = ast.parse(source)
        except ProfileViolation:
            raise
        except (OSError, SyntaxError, ValueError):
            raise ProfileViolation("PROFILE_RUNTIME_SYNTAX_INVALID") from None
        imports = _scan_runtime(tree, profile)
        if any(
            _module_matches(name, profile["network_import_families"])
            for name in imports
        ):
            modules.append(relative)
    if sorted(modules) != profile["declared_network_modules"]:
        raise ProfileViolation("PROFILE_NETWORK_SET_INVALID")


def _verify_workflows(root: Path, forbidden_tokens: list[str]) -> None:
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return
    for _, path in _walk(workflow_root, root):
        if not path.is_file() or path.suffix.casefold() not in {".yaml", ".yml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise ProfileViolation("PROFILE_WORKFLOW_INVALID") from None
        folded = text.casefold()
        if any(token.casefold() in folded for token in forbidden_tokens):
            raise ProfileViolation("PROFILE_WORKFLOW_FORBIDDEN")


def _verify_documents(root: Path, profile: dict[str, Any]) -> None:
    entries = _project_entries(root, profile["active_document_paths"])
    documents = [
        path
        for relative, path in entries
        if path.is_file() and _matches_any(relative, profile["active_document_paths"])
    ]
    for pattern in profile["active_document_paths"]:
        if not any(_glob_matches(path.relative_to(root).as_posix(), pattern) for path in documents):
            raise ProfileViolation("PROFILE_DOCUMENT_INVALID")
    try:
        corpus = "\n".join(path.read_text(encoding="utf-8") for path in documents)
    except (OSError, UnicodeError):
        raise ProfileViolation("PROFILE_DOCUMENT_INVALID") from None
    folded = corpus.casefold()
    if any(fragment.casefold() in folded for fragment in profile["forbidden_document_promises"]):
        raise ProfileViolation("PROFILE_DOCUMENT_FORBIDDEN")
    if any(marker.casefold() not in folded for marker in profile["required_document_markers"]):
        raise ProfileViolation("PROFILE_DOCUMENT_BOUNDARY_MISSING")


# This policy matches explicit AST names/members; it does not evaluate Python.
def _scan_runtime(tree: ast.AST, profile: dict[str, Any]) -> tuple[str, ...]:
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


def _module_matches(name: str, families: list[str]) -> bool:
    folded = name.casefold()
    return any(
        folded == family.casefold() or folded.startswith(family.casefold() + ".")
        for family in families
    )


def _project_entries(root: Path, patterns: list[str]) -> tuple[tuple[str, Path], ...]:
    heads = {pattern.split("/", 1)[0].casefold() for pattern in patterns}
    entries: list[tuple[str, Path]] = []
    try:
        children = sorted(root.iterdir(), key=lambda path: (path.name.casefold(), path.name))
    except OSError:
        raise ProfileViolation("PROFILE_PROJECT_INVALID") from None
    for child in children:
        if child.name.casefold() in heads:
            entries.extend(_walk(child, root))
    return tuple(entries)


def _walk(start: Path, root: Path) -> tuple[tuple[str, Path], ...]:
    if _is_reparse_point(start):
        raise ProfileViolation("PROFILE_REPARSE_POINT")
    entries = [(start.relative_to(root).as_posix(), start)]
    if not start.is_dir():
        return tuple(entries)
    try:
        children = sorted(start.iterdir(), key=lambda path: (path.name.casefold(), path.name))
    except OSError:
        raise ProfileViolation("PROFILE_PROJECT_INVALID") from None
    for child in children:
        entries.extend(_walk(child, root))
    return tuple(entries)


def _required_file(root: Path, relative: str) -> bool:
    path = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if _is_reparse_point(current):
            raise ProfileViolation("PROFILE_REPARSE_POINT")
    return path.is_file()


def _safe_relative_pattern(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and "\\" not in value
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and ":" not in path.parts[0]
    )


def _matches_any(path: str, patterns: list[str]) -> bool:
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
    parser.add_argument("--profile", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = verify_profile(arguments.project_root, arguments.profile)
    except ProfileViolation as error:
        sys.stderr.buffer.write(canonical_json_bytes({"error": error.code, "status": "fail"}))
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
