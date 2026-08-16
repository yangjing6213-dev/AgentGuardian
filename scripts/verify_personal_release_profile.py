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
_MAX_ALIAS_VALUES = 128
_MAX_REFERENCE_PARTS = 64
_MAX_RUNTIME_OPERATIONS = 4096
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
        imports = _RuntimeAnalyzer(profile["forbidden_runtime_calls"]).analyze(tree)
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


class _RuntimeAnalyzer:
    """Bounded, statement-ordered alias analysis with isolated lexical scopes."""

    def __init__(self, forbidden_calls: list[str]) -> None:
        self._forbidden_calls = tuple(pattern.casefold() for pattern in forbidden_calls)
        self._imports: list[str] = []
        self._operations = 0

    def analyze(self, tree: ast.Module) -> tuple[str, ...]:
        self._statements(tree.body, {})
        return tuple(self._imports)

    def _spend(self, count: int = 1) -> None:
        self._operations += count
        if self._operations > _MAX_RUNTIME_OPERATIONS:
            raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")

    def _statements(
        self,
        statements: list[ast.stmt],
        env: dict[str, frozenset[str]],
        *,
        function_parent: dict[str, frozenset[str]] | None = None,
        depth: int = 0,
    ) -> None:
        if depth > _MAX_REFERENCE_PARTS:
            raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")
        for statement in statements:
            self._statement(statement, env, function_parent, depth)

    def _statement(
        self,
        node: ast.stmt,
        env: dict[str, frozenset[str]],
        function_parent: dict[str, frozenset[str]] | None,
        depth: int,
    ) -> None:
        if isinstance(node, ast.Import):
            for item in node.names:
                self._spend()
                self._imports.append(item.name)
                bound = item.asname or item.name.split(".", 1)[0]
                env[bound] = frozenset({item.name if item.asname else bound})
            return
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                self._imports.append(module)
            for item in node.names:
                self._spend()
                qualified = f"{module}.{item.name}" if module else item.name
                self._imports.append(qualified)
                env[item.asname or item.name] = frozenset({qualified})
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is not None:
                self._expression(value, env, function_parent, depth)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                self._expression(target, env, function_parent, depth)
                self._assign(target, value, env)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function_expressions(node, env, function_parent, depth)
            self._spend()
            env[node.name] = frozenset({node.name})
            parent = function_parent if function_parent is not None else env
            child = dict(parent)
            self._shadow_parameters(node.args, child)
            self._statements(node.body, child, depth=depth + 1)
            return
        if isinstance(node, ast.ClassDef):
            for expression in (*node.decorator_list, *node.bases, *node.keywords):
                value = expression.value if isinstance(expression, ast.keyword) else expression
                self._expression(value, env, function_parent, depth)
            self._spend()
            env[node.name] = frozenset({node.name})
            outer = function_parent if function_parent is not None else env
            self._statements(
                node.body,
                dict(env),
                function_parent=dict(outer),
                depth=depth + 1,
            )
            return
        if isinstance(node, ast.If):
            self._expression(node.test, env, function_parent, depth)
            body_env = dict(env)
            else_env = dict(env)
            self._statements(
                node.body, body_env, function_parent=function_parent, depth=depth + 1
            )
            self._statements(
                node.orelse, else_env, function_parent=function_parent, depth=depth + 1
            )
            self._replace_with_merge(env, (body_env, else_env))
            return
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            if isinstance(node, (ast.For, ast.AsyncFor)):
                self._expression(node.iter, env, function_parent, depth)
                body_env = dict(env)
                self._assign(node.target, None, body_env)
            else:
                self._expression(node.test, env, function_parent, depth)
                body_env = dict(env)
            self._statements(
                node.body, body_env, function_parent=function_parent, depth=depth + 1
            )
            else_env = self._merged(env, (dict(env), body_env))
            self._statements(
                node.orelse, else_env, function_parent=function_parent, depth=depth + 1
            )
            self._replace_with_merge(env, (dict(env), body_env, else_env))
            return
        if isinstance(node, (ast.Try, ast.TryStar)):
            body_env = dict(env)
            self._statements(
                node.body, body_env, function_parent=function_parent, depth=depth + 1
            )
            success_env = dict(body_env)
            self._statements(
                node.orelse,
                success_env,
                function_parent=function_parent,
                depth=depth + 1,
            )
            outcomes = [success_env]
            for handler in node.handlers:
                handler_env = dict(env)
                if handler.type is not None:
                    self._expression(handler.type, handler_env, function_parent, depth)
                if handler.name:
                    handler_env[handler.name] = frozenset({handler.name})
                self._statements(
                    handler.body,
                    handler_env,
                    function_parent=function_parent,
                    depth=depth + 1,
                )
                outcomes.append(handler_env)
            merged = self._merged(env, tuple(outcomes))
            self._statements(
                node.finalbody,
                merged,
                function_parent=function_parent,
                depth=depth + 1,
            )
            env.clear()
            env.update(merged)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._expression(item.context_expr, env, function_parent, depth)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, None, env)
            self._statements(
                node.body, env, function_parent=function_parent, depth=depth + 1
            )
            return
        if isinstance(node, ast.Match):
            self._expression(node.subject, env, function_parent, depth)
            outcomes: list[dict[str, frozenset[str]]] = [dict(env)]
            for case in node.cases:
                case_env = dict(env)
                if case.guard is not None:
                    self._expression(case.guard, case_env, function_parent, depth)
                self._statements(
                    case.body,
                    case_env,
                    function_parent=function_parent,
                    depth=depth + 1,
                )
                outcomes.append(case_env)
            self._replace_with_merge(env, tuple(outcomes))
            return

        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._expression(child, env, function_parent, depth)
        if isinstance(node, (ast.AugAssign, ast.Delete)):
            targets = [node.target] if isinstance(node, ast.AugAssign) else node.targets
            for target in targets:
                self._assign(target, None, env)

    def _expression(
        self,
        node: ast.AST,
        env: dict[str, frozenset[str]],
        function_parent: dict[str, frozenset[str]] | None,
        depth: int,
    ) -> None:
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Lambda):
                for default in (*current.args.defaults, *current.args.kw_defaults):
                    if default is not None:
                        self._expression(default, env, function_parent, depth)
                child = dict(function_parent if function_parent is not None else env)
                self._shadow_parameters(current.args, child)
                self._expression(current.body, child, None, depth + 1)
                continue
            if isinstance(current, ast.NamedExpr):
                self._expression(current.value, env, function_parent, depth)
                self._assign(current.target, current.value, env)
                continue
            if isinstance(current, ast.Call):
                for name in self._reference(current.func, env):
                    candidates = {name}
                    if name.casefold().startswith("builtins."):
                        candidates.add(name.rsplit(".", 1)[-1])
                    if any(
                        fnmatchcase(candidate.casefold(), pattern)
                        for candidate in candidates
                        for pattern in self._forbidden_calls
                    ):
                        raise ProfileViolation("PROFILE_RUNTIME_CALL_FORBIDDEN")
            stack.extend(ast.iter_child_nodes(current))

    def _assign(
        self,
        target: ast.AST,
        value: ast.AST | None,
        env: dict[str, frozenset[str]],
    ) -> None:
        if isinstance(target, ast.Name):
            self._spend()
            env[target.id] = (
                self._reference(value, env)
                if isinstance(value, (ast.Name, ast.Attribute))
                else frozenset({target.id})
            )
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, None, env)

    def _reference(
        self, node: ast.AST, env: dict[str, frozenset[str]]
    ) -> frozenset[str]:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            if len(parts) > _MAX_REFERENCE_PARTS:
                raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")
            node = node.value
        if not isinstance(node, ast.Name):
            return frozenset()
        parents = env.get(node.id, frozenset({node.id}))
        self._spend(1 + len(parents))
        suffix = ".".join(reversed(parts))
        resolved = frozenset(
            f"{parent}.{suffix}" if suffix else parent for parent in parents
        )
        if len(resolved) > _MAX_ALIAS_VALUES:
            raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")
        return resolved

    def _shadow_parameters(
        self, arguments: ast.arguments, env: dict[str, frozenset[str]]
    ) -> None:
        parameters = [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ]
        if arguments.vararg is not None:
            parameters.append(arguments.vararg)
        if arguments.kwarg is not None:
            parameters.append(arguments.kwarg)
        for parameter in parameters:
            self._spend()
            env[parameter.arg] = frozenset({parameter.arg})

    def _function_expressions(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        env: dict[str, frozenset[str]],
        function_parent: dict[str, frozenset[str]] | None,
        depth: int,
    ) -> None:
        expressions: list[ast.expr] = [*node.decorator_list, *node.args.defaults]
        expressions.extend(value for value in node.args.kw_defaults if value is not None)
        expressions.extend(
            argument.annotation
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if argument.annotation is not None
        )
        if node.args.vararg is not None and node.args.vararg.annotation is not None:
            expressions.append(node.args.vararg.annotation)
        if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
            expressions.append(node.args.kwarg.annotation)
        if node.returns is not None:
            expressions.append(node.returns)
        for expression in expressions:
            self._expression(expression, env, function_parent, depth)

    def _merged(
        self,
        base: dict[str, frozenset[str]],
        outcomes: tuple[dict[str, frozenset[str]], ...],
    ) -> dict[str, frozenset[str]]:
        merged = dict(base)
        keys = set().union(*(outcome.keys() for outcome in outcomes))
        for key in keys:
            values_by_path = [outcome.get(key, frozenset({key})) for outcome in outcomes]
            if all(values == values_by_path[0] for values in values_by_path[1:]):
                merged[key] = values_by_path[0]
                continue
            values = frozenset().union(*values_by_path)
            self._spend(1 + len(values))
            if len(values) > _MAX_ALIAS_VALUES:
                raise ProfileViolation("PROFILE_RUNTIME_ANALYSIS_LIMIT")
            merged[key] = values
        return merged

    def _replace_with_merge(
        self,
        env: dict[str, frozenset[str]],
        outcomes: tuple[dict[str, frozenset[str]], ...],
    ) -> None:
        merged = self._merged(env, outcomes)
        env.clear()
        env.update(merged)


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
