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
_MAX_ARRAY_ITEMS = 128
_MAX_VALUE_LENGTH = 256
_MAX_ALIAS_DEPTH = 64
_MAX_SIMPLE_ASSIGNMENTS = 512
_MAX_ALIAS_VALUES = 128
_PROFILE_KEYS = frozenset(
    {
        "active_document_paths",
        "declared_network_modules",
        "forbidden_document_promises",
        "forbidden_payload_globs",
        "forbidden_runtime_calls",
        "forbidden_runtime_imports",
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
            tree = ast.parse(path.read_bytes())
        except (OSError, SyntaxError, ValueError):
            raise ProfileViolation("PROFILE_RUNTIME_SYNTAX_INVALID") from None
        imports, aliases = _imports_and_aliases(tree)
        if _has_forbidden_call(tree, aliases, profile["forbidden_runtime_calls"]):
            raise ProfileViolation("PROFILE_RUNTIME_CALL_FORBIDDEN")
        if any(
            _module_matches(name, profile["forbidden_runtime_imports"])
            for name in imports
        ):
            raise ProfileViolation("PROFILE_RUNTIME_IMPORT_FORBIDDEN")
        if _has_forbidden_symbol(tree, imports, profile["forbidden_runtime_symbols"]):
            raise ProfileViolation("PROFILE_RUNTIME_SYMBOL_FORBIDDEN")
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


def _imports_and_aliases(
    tree: ast.AST,
) -> tuple[
    tuple[str, ...],
    tuple[dict[str, frozenset[str]], dict[str, tuple[ast.AST, ...]]],
]:
    imports: list[str] = []
    aliases: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                imports.append(item.name)
                bound = item.asname or item.name.split(".", 1)[0]
                resolved = item.name if item.asname else bound
                aliases.setdefault(bound, set()).add(resolved)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                imports.append(module)
            for item in node.names:
                qualified = f"{module}.{item.name}" if module else item.name
                imports.append(qualified)
                aliases.setdefault(item.asname or item.name, set()).add(qualified)

    assignments = _simple_assignments(tree)
    if len(assignments) > _MAX_SIMPLE_ASSIGNMENTS:
        raise ProfileViolation("PROFILE_RUNTIME_CALL_FORBIDDEN")
    assignment_map: dict[str, list[ast.AST]] = {}
    for target, source in assignments:
        assignment_map.setdefault(target, []).append(source)
    return tuple(imports), (
        {key: frozenset(values) for key, values in aliases.items()},
        {key: tuple(values) for key, values in assignment_map.items()},
    )


def _simple_assignments(tree: ast.AST) -> tuple[tuple[str, ast.AST], ...]:
    assignments: list[tuple[int, int, str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Name, ast.Attribute)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.append((node.lineno, node.col_offset, target.id, node.value))
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and isinstance(node.value, (ast.Name, ast.Attribute))
        ):
            assignments.append((node.lineno, node.col_offset, node.target.id, node.value))
    assignments.sort(key=lambda value: (value[0], value[1], value[2]))
    return tuple((target, source) for _, _, target, source in assignments)


def _has_forbidden_call(
    tree: ast.AST,
    aliases: tuple[dict[str, frozenset[str]], dict[str, tuple[ast.AST, ...]]],
    patterns: list[str],
) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for name in _resolved_names(node.func, *aliases):
            candidates = {name}
            if name.casefold().startswith("builtins."):
                candidates.add(name.rsplit(".", 1)[-1])
            if any(
                fnmatchcase(candidate.casefold(), pattern.casefold())
                for candidate in candidates
                for pattern in patterns
            ):
                return True
    return False


def _has_forbidden_symbol(
    tree: ast.AST, imports: tuple[str, ...], symbols: list[str]
) -> bool:
    forbidden = {value.casefold() for value in symbols}
    if any(part.casefold() in forbidden for name in imports for part in name.split(".")):
        return True
    for node in ast.walk(tree):
        name: str | None = None
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Name)):
            name = node.name if hasattr(node, "name") else node.id
        elif isinstance(node, ast.Attribute):
            name = node.attr
        if name is not None and name.casefold() in forbidden:
            return True
    return False


def _resolved_names(
    node: ast.AST,
    aliases: dict[str, frozenset[str]],
    assignments: dict[str, tuple[ast.AST, ...]],
    *,
    stack: frozenset[str] = frozenset(),
    depth: int = 0,
) -> frozenset[str]:
    if depth > _MAX_ALIAS_DEPTH:
        raise ProfileViolation("PROFILE_RUNTIME_CALL_FORBIDDEN")
    if isinstance(node, ast.Name):
        if node.id in stack:
            return aliases.get(node.id, frozenset())
        resolved = set(aliases.get(node.id, ()))
        sources = assignments.get(node.id, ())
        for source in sources:
            resolved.update(
                _resolved_names(
                    source,
                    aliases,
                    assignments,
                    stack=stack | {node.id},
                    depth=depth + 1,
                )
            )
        if not resolved and not sources:
            resolved.add(node.id)
        if len(resolved) > _MAX_ALIAS_VALUES:
            raise ProfileViolation("PROFILE_RUNTIME_CALL_FORBIDDEN")
        return frozenset(resolved)
    if isinstance(node, ast.Attribute):
        resolved = frozenset(
            f"{parent}.{node.attr}"
            for parent in _resolved_names(
                node.value,
                aliases,
                assignments,
                stack=stack,
                depth=depth + 1,
            )
        )
        if len(resolved) > _MAX_ALIAS_VALUES:
            raise ProfileViolation("PROFILE_RUNTIME_CALL_FORBIDDEN")
        return resolved
    return frozenset()


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
