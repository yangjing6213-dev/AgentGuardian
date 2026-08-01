import ast
import ctypes
import hashlib
import sys
from pathlib import Path

from . import __version__

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "default.json"

_NETWORK_MODULES = {
    "aiohttp",
    "ftplib",
    "http",
    "httpx",
    "requests",
    "smtplib",
    "socket",
    "urllib",
    "websockets",
}
_CLIPBOARD_MODULES = {"pyperclip", "win32clipboard"}
_TELEMETRY_MODULES = {
    "analytics",
    "datadog",
    "newrelic",
    "opentelemetry",
    "sentry_sdk",
    "telemetry",
}
_LLM_MODULES = {
    "anthropic",
    "cohere",
    "google.generativeai",
    "mistralai",
    "openai",
}
_RESTRICTED_BINDINGS = {
    "Path",
    "__import__",
    "asyncio",
    "builtins",
    "os",
    "pathlib",
    "shutil",
    "tkinter",
}
_WRITE_ATTRIBUTE_MEMBERS = {
    "mkdir",
    "open",
    "rename",
    "replace",
    "rmdir",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}


def collect_self_audit() -> dict[str, object]:
    findings = static_capability_findings()
    return {
        "version": __version__,
        "executable_path": sys.executable,
        "rules_sha256": _rules_sha256(),
        "local_only": False,
        "network_capability": _network_capability(findings),
        "ordinary_user_mode": _ordinary_user_mode(),
        "alpha_status": "Founder Alpha",
        "findings": list(findings),
        "scope": {
            "capabilities": "package_source_policy",
            "semantic_analysis": "not_performed",
            "dependencies": "not_scanned",
            "binaries": "not_scanned",
            "mapped_network_drives": "not_reliably_detected",
        },
    }


def _ordinary_user_mode() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return not bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - privilege probes fail closed.
        return False


def _network_capability(findings: tuple[str, ...]) -> str:
    if {"NETWORK_MODULE_IMPORT", "NETWORK_CAPABILITY"} & set(findings):
        return "detected"
    return "unverified" if findings else "not_detected"


def _rules_sha256() -> str:
    try:
        rules = DEFAULT_RULES_PATH.read_bytes()
    except OSError:
        raise RuntimeError("SELF_AUDIT_READ_ERROR") from None
    return hashlib.sha256(rules).hexdigest()


def static_capability_findings(
    package_root: str | Path | None = None,
) -> tuple[str, ...]:
    root = _package_root(package_root)
    if not root.is_dir():
        return ("SOURCE_SCAN_ERROR",)
    findings: set[str] = set()
    try:
        modules = sorted(root.rglob("*.py"), key=lambda path: _module_key(root, path))
    except OSError:
        return ("SOURCE_SCAN_ERROR",)
    for module in modules:
        try:
            tree = ast.parse(module.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            findings.add("SOURCE_SCAN_ERROR")
            continue
        _scan_module(module.relative_to(root).as_posix(), tree, findings)
    return tuple(sorted(findings))


def _package_root(package_root: str | Path | None) -> Path:
    if package_root is None:
        return Path(__file__).resolve().parent
    root = Path(package_root)
    if (root / "src" / "agentguardian").is_dir():
        return root / "src" / "agentguardian"
    if (root / "agentguardian").is_dir():
        return root / "agentguardian"
    return root


def _module_key(root: Path, module: Path) -> tuple[str, str]:
    relative = module.relative_to(root).as_posix()
    return relative.casefold(), relative


def _scan_module(relative_path: str, tree: ast.Module, findings: set[str]) -> None:
    allow_ctypes = _allowed_ctypes_usage(relative_path, tree)
    allowed_report_call = _allowed_report_export_call(relative_path, tree)
    allowed_user_data_calls = _allowed_state_store_write_calls(relative_path, tree)
    if allowed_report_call is not None:
        allowed_user_data_calls.add(allowed_report_call)
    imported_bindings: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                binding = alias.asname or alias.name.split(".", 1)[0]
                imported_bindings.add(binding)
                findings.update(_import_findings(alias.name))
                root = alias.name.split(".", 1)[0]
                if alias.asname and root in {"os", "pathlib"}:
                    findings.add("SOURCE_POLICY_VIOLATION")
                if root == "ctypes" and not allow_ctypes:
                    findings.add("NATIVE_CAPABILITY")
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                imported_bindings.add(alias.asname or alias.name)
                findings.update(_import_findings(node.module, alias.name))
                if node.module == "builtins" and alias.name in {"getattr", "vars"}:
                    findings.add("USER_DATA_WRITE")
                if alias.asname and node.module.split(".", 1)[0] in {
                    "os",
                    "pathlib",
                }:
                    findings.add("SOURCE_POLICY_VIOLATION")
                if node.module.split(".", 1)[0] == "ctypes" and not allow_ctypes:
                    findings.add("NATIVE_CAPABILITY")

    rebound = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Store)
        and node.id in imported_bindings
    }
    rebound.update(
        node.arg
        for node in ast.walk(tree)
        if isinstance(node, ast.arg) and node.arg in imported_bindings
    )
    if rebound & _RESTRICTED_BINDINGS:
        findings.add("SOURCE_POLICY_VIOLATION")

    dynamic_lookup_references = {
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id in {"getattr", "vars"}
    }
    allowed_dynamic_lookup_references = {
        node.func
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"getattr", "vars"}
    }
    if dynamic_lookup_references != allowed_dynamic_lookup_references:
        findings.add("USER_DATA_WRITE")

    for node in ast.walk(tree):
        alias_sources = _direct_alias_sources(node)
        if alias_sources & _RESTRICTED_BINDINGS:
            findings.add("SOURCE_POLICY_VIOLATION")
        alias_attribute = _direct_alias_attribute(node)
        if alias_attribute and _is_user_data_write_name(alias_attribute):
            findings.add("USER_DATA_WRITE")
        if "__import__" in alias_sources:
            findings.add("DYNAMIC_EXECUTION")
        if isinstance(node, ast.Attribute):
            _classify_attribute(node, rebound, findings, allow_ctypes)
        elif isinstance(node, ast.Call):
            name = _qualified_name(node.func)
            if name in {"__import__", "compile", "eval", "exec"}:
                findings.add("DYNAMIC_EXECUTION")
            if (
                _call_name(node.func) in {"getattr", "vars"}
                and node.args
                and _qualified_name(node.args[0]).split(".", 1)[0]
                in {"os", "pathlib", "Path"}
            ):
                findings.add("USER_DATA_WRITE")
            dynamic_attribute = _dynamic_attribute_name(node)
            if dynamic_attribute and (
                _is_user_data_write_name(dynamic_attribute)
                or dynamic_attribute.rsplit(".", 1)[-1]
                in _WRITE_ATTRIBUTE_MEMBERS
            ):
                findings.add("USER_DATA_WRITE")
            mode = _open_mode(node)
            if (
                mode is not None
                and any(flag in mode for flag in "wax+")
                and node not in allowed_user_data_calls
            ):
                findings.add("USER_DATA_WRITE")
            if _is_user_data_write_call(node) and node not in allowed_user_data_calls:
                findings.add("USER_DATA_WRITE")


def _import_findings(module: str, member: str | None = None) -> set[str]:
    normalized = module.casefold()
    root = normalized.split(".", 1)[0]
    findings: set[str] = set()
    if root in _NETWORK_MODULES or normalized.startswith("pyside6.qtnetwork"):
        findings.add("NETWORK_MODULE_IMPORT")
    if root == "asyncio":
        findings.add("NETWORK_CAPABILITY")
    if root == "subprocess":
        findings.add("SHELL_EXECUTION")
    if root == "shutil":
        findings.add("USER_DATA_WRITE")
    if root == "tkinter":
        findings.add("CLIPBOARD_CAPABILITY")
    if root in _CLIPBOARD_MODULES:
        findings.update(("CLIPBOARD_CAPABILITY", "USER_DATA_WRITE"))
    if root in _TELEMETRY_MODULES:
        findings.add("TELEMETRY_CAPABILITY")
    if root in {"ensurepip", "pip"}:
        findings.add("UPDATER_CAPABILITY")
    if normalized in _LLM_MODULES or root in _LLM_MODULES:
        findings.add("LLM_CAPABILITY")
    if root in {"builtins", "importlib", "runpy"}:
        findings.add("DYNAMIC_EXECUTION")
    if root == "webbrowser":
        findings.update(("EXTERNAL_CAPABILITY", "NETWORK_MODULE_IMPORT"))
    if root == "sqlite3":
        findings.add("DATABASE_CAPABILITY")
    if root == "os" and member and _is_shell_member(member):
        findings.add("SHELL_EXECUTION")
    return findings


def _classify_attribute(
    node: ast.Attribute,
    rebound: set[str],
    findings: set[str],
    allow_ctypes: bool,
) -> None:
    name = _qualified_name(node)
    root = name.split(".", 1)[0]
    if (
        root == "os"
        and root not in rebound
        and (
            name in {"os.popen", "os.startfile", "os.system"}
            or name.startswith("os.spawn")
        )
    ):
        findings.add("SHELL_EXECUTION")
    if node.attr in {"write_bytes", "write_text"}:
        findings.add(
            "USER_DATA_WRITE"
            if name.startswith(("Path.", "pathlib.Path."))
            else "SOURCE_POLICY_VIOLATION"
        )
    if node.attr == "__dict__" and root in {"os", "pathlib", "Path"}:
        findings.add("USER_DATA_WRITE")
    if "clipboard_" in node.attr:
        findings.add("CLIPBOARD_CAPABILITY")
        if node.attr in {"clipboard_append", "clipboard_clear"}:
            findings.add("USER_DATA_WRITE")
    if name.startswith("ctypes.") and not allow_ctypes:
        findings.add("NATIVE_CAPABILITY")


def _is_shell_member(member: str) -> bool:
    lowered = member.casefold()
    return lowered in {"popen", "startfile", "system"} or lowered.startswith("spawn")


def _direct_alias_sources(node: ast.AST) -> set[str]:
    value: ast.expr | None = None
    if isinstance(node, (ast.AnnAssign, ast.Assign, ast.NamedExpr)):
        value = node.value
    if value is None:
        return set()
    if isinstance(value, ast.Name):
        return {value.id}
    if isinstance(value, (ast.List, ast.Tuple)):
        return {
            item.id
            for item in value.elts
            if isinstance(item, ast.Name)
        }
    return set()


def _direct_alias_attribute(node: ast.AST) -> str:
    value: ast.expr | None = None
    if isinstance(node, (ast.AnnAssign, ast.Assign, ast.NamedExpr)):
        value = node.value
    if isinstance(value, ast.Attribute):
        return _qualified_name(value)
    return ""


def _qualified_name(expression: ast.expr) -> str:
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        parent = _qualified_name(expression.value)
        return f"{parent}.{expression.attr}" if parent else expression.attr
    if isinstance(expression, ast.Call):
        return _qualified_name(expression.func)
    return ""


def _open_mode(node: ast.Call) -> str | None:
    name = _qualified_name(node.func)
    if name in {"open", "builtins.open"}:
        positional_mode = node.args[1] if len(node.args) > 1 else None
    elif name.endswith(".open"):
        positional_mode = node.args[0] if node.args else None
    else:
        return None
    mode_node = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "mode"),
        positional_mode,
    )
    if mode_node is None:
        return "r"
    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        return mode_node.value.casefold()
    return "+"


def _allowed_report_export_call(
    relative_path: str, tree: ast.Module
) -> ast.Call | None:
    if relative_path != "app.py":
        return None
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "export_new_report"
    ]
    if len(functions) != 1:
        return None
    function = functions[0]
    if [argument.arg for argument in function.args.args] != [
        "path",
        "content",
        "scanned_roots",
    ]:
        return None
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
    writes = [node for node in calls if _open_mode(node) == "x"]
    if len(writes) != 1:
        return None
    write = writes[0]
    if (
        not write.args
        or not isinstance(write.args[0], ast.Name)
        or write.args[0].id != "final_target"
        or not _keyword_is(write, "encoding", "utf-8")
        or not _keyword_is(write, "newline", "\n")
    ):
        return None
    required_calls = {
        "_is_reparse",
        "_is_unc_path",
        "is_dir",
        "is_relative_to",
        "resolve",
        "write",
    }
    if not required_calls <= {_call_name(call.func) for call in calls}:
        return None
    raises = {
        _call_name(node.exc.func)
        for node in ast.walk(function)
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
    }
    if not {"filenotfounderror", "oserror", "valueerror"} <= raises:
        return None
    return write


def _allowed_state_store_write_calls(
    relative_path: str, tree: ast.Module
) -> set[ast.Call]:
    if relative_path != "state_store.py":
        return set()
    save_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "save_protected_state"
    ]
    target_functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_target_path"
    ]
    if len(save_functions) != 1 or len(target_functions) != 1:
        return set()
    save_function = save_functions[0]
    target_function = target_functions[0]
    if (
        [argument.arg for argument in save_function.args.args] != ["snapshot"]
        or [argument.arg for argument in save_function.args.kwonlyargs]
        != ["directory", "protect"]
        or [argument.arg for argument in target_function.args.args] != ["directory"]
        or [argument.arg for argument in target_function.args.kwonlyargs] != ["create"]
    ):
        return set()

    save_calls = [
        node for node in ast.walk(save_function) if isinstance(node, ast.Call)
    ]
    target_calls = [
        node for node in ast.walk(target_function) if isinstance(node, ast.Call)
    ]
    opens = [node for node in save_calls if _open_mode(node) == "xb"]
    replaces = [
        node for node in save_calls if _qualified_name(node.func) == "os.replace"
    ]
    directories = [
        node for node in target_calls if _qualified_name(node.func) == "parent.mkdir"
    ]
    unlinks = [
        node for node in save_calls if _qualified_name(node.func) == "temporary.unlink"
    ]
    stream_writes = [
        node for node in save_calls if _qualified_name(node.func) == "stream.write"
    ]
    if not all(
        len(group) == 1
        for group in (opens, replaces, directories, unlinks, stream_writes)
    ):
        return set()

    opened = opens[0]
    replaced = replaces[0]
    directory = directories[0]
    unlinked = unlinks[0]
    stream_write = stream_writes[0]
    if (
        len(opened.args) != 2
        or not isinstance(opened.args[0], ast.Name)
        or opened.args[0].id != "temporary"
        or not isinstance(opened.args[1], ast.Constant)
        or opened.args[1].value != "xb"
        or len(replaced.args) != 2
        or not all(isinstance(argument, ast.Name) for argument in replaced.args)
        or [argument.id for argument in replaced.args] != ["temporary", "target"]
        or directory.args
        or not _keyword_is(directory, "mode", 0o700)
        or not _keyword_is(directory, "exist_ok", True)
        or unlinked.args
        or not _keyword_is(unlinked, "missing_ok", True)
        or len(stream_write.args) != 1
        or not isinstance(stream_write.args[0], ast.Name)
        or stream_write.args[0].id != "ciphertext"
    ):
        return set()
    return {opened, replaced, directory, unlinked}


def _is_user_data_write_call(node: ast.Call) -> bool:
    name = _qualified_name(node.func)
    return _is_user_data_write_name(name) or _call_name(node.func) in {
        "mkdir",
        "rmdir",
        "touch",
        "unlink",
    }


def _is_user_data_write_name(name: str) -> bool:
    return name in {
        "os.fdopen",
        "os.makedirs",
        "os.mkdir",
        "os.open",
        "os.remove",
        "os.renames",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.unlink",
    }


def _dynamic_attribute_name(node: ast.Call) -> str:
    if (
        _qualified_name(node.func) == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    ):
        root = _qualified_name(node.args[0])
        if root:
            return f"{root}.{node.args[1].value}"
    return ""


def _keyword_is(node: ast.Call, name: str, value: object) -> bool:
    return any(
        keyword.arg == name
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value == value
        for keyword in node.keywords
    )


def _call_name(function: ast.expr) -> str:
    if isinstance(function, ast.Name):
        return function.id.casefold()
    if isinstance(function, ast.Attribute):
        return function.attr.casefold()
    return ""


def _exact_ctypes_import(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Import)
        and len(node.names) == 1
        and node.names[0].name == "ctypes"
        and node.names[0].asname is None
    )


def _allowed_ctypes_usage(relative_path: str, tree: ast.AST) -> bool:
    if relative_path == "self_audit.py":
        return _allowed_admin_probe(tree)
    if relative_path == "windows_dpapi.py":
        return _allowed_windows_dpapi(tree)
    return False


def _allowed_admin_probe(tree: ast.AST) -> bool:
    nodes = tuple(ast.walk(tree))
    imports = tuple(node for node in nodes if _exact_ctypes_import(node))
    calls = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Call) and _exact_admin_probe(node)
    )
    if len(imports) != 1 or len(calls) != 1:
        return False
    references = {
        node for node in nodes if isinstance(node, ast.Name) and node.id == "ctypes"
    }
    allowed_references = {
        node
        for node in ast.walk(calls[0].func)
        if isinstance(node, ast.Name) and node.id == "ctypes"
    }
    return references == allowed_references and len(allowed_references) == 1


def _allowed_windows_dpapi(tree: ast.AST) -> bool:
    nodes = tuple(ast.walk(tree))
    imports = tuple(node for node in nodes if _exact_ctypes_import(node))
    from_imports = tuple(
        node
        for node in nodes
        if isinstance(node, ast.ImportFrom) and node.module == "ctypes"
    )
    if (
        len(imports) != 1
        or len(from_imports) != 1
        or len(from_imports[0].names) != 1
        or from_imports[0].names[0].name != "wintypes"
        or from_imports[0].names[0].asname is not None
    ):
        return False

    allowed_ctypes = {
        "ctypes.POINTER",
        "ctypes.Structure",
        "ctypes.WinDLL",
        "ctypes.byref",
        "ctypes.c_ubyte",
        "ctypes.cast",
        "ctypes.string_at",
    }
    ctypes_attributes = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and _qualified_name(node).startswith("ctypes.")
    )
    if {
        _qualified_name(node) for node in ctypes_attributes
    } - allowed_ctypes:
        return False
    ctypes_references = {
        node for node in nodes if isinstance(node, ast.Name) and node.id == "ctypes"
    }
    allowed_ctypes_references = {
        child
        for node in ctypes_attributes
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and child.id == "ctypes"
    }
    if ctypes_references != allowed_ctypes_references:
        return False

    allowed_wintypes = {
        "wintypes.BOOL",
        "wintypes.DWORD",
        "wintypes.LPCWSTR",
        "wintypes.LPVOID",
        "wintypes.LPWSTR",
    }
    wintypes_attributes = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and _qualified_name(node).startswith("wintypes.")
    )
    if {
        _qualified_name(node) for node in wintypes_attributes
    } - allowed_wintypes:
        return False
    wintypes_references = {
        node for node in nodes if isinstance(node, ast.Name) and node.id == "wintypes"
    }
    allowed_wintypes_references = {
        child
        for node in wintypes_attributes
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and child.id == "wintypes"
    }
    if wintypes_references != allowed_wintypes_references:
        return False

    libraries: dict[str, str] = {}
    for node in nodes:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and _qualified_name(node.value.func) == "ctypes.WinDLL"
            and len(node.value.args) == 1
            and isinstance(node.value.args[0], ast.Constant)
            and isinstance(node.value.args[0].value, str)
            and len(node.value.keywords) == 1
            and node.value.keywords[0].arg == "use_last_error"
            and isinstance(node.value.keywords[0].value, ast.Constant)
            and node.value.keywords[0].value.value is True
        ):
            libraries[node.targets[0].id] = node.value.args[0].value
    if libraries != {"crypt32": "Crypt32.dll", "kernel32": "Kernel32.dll"}:
        return False
    if any(_direct_alias_sources(node) & libraries.keys() for node in nodes):
        return False
    if any(
        isinstance(node, ast.Subscript)
        and any(
            isinstance(child, ast.Name) and child.id in libraries
            for child in ast.walk(node)
        )
        for node in nodes
    ):
        return False
    if any(
        isinstance(node, ast.Call)
        and _qualified_name(node.func) in {"getattr", "setattr", "vars"}
        for node in nodes
    ):
        return False

    allowed_native_attributes = {
        "crypt32.CryptProtectData",
        "crypt32.CryptUnprotectData",
        "kernel32.LocalFree",
    }
    native_attribute_nodes = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Attribute)
        and _qualified_name(node).split(".", 1)[0] in libraries
    )
    native_attributes = tuple(
        _qualified_name(node) for node in native_attribute_nodes
    )
    library_bindings = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Tuple)
        and [
            item.id if isinstance(item, ast.Name) else ""
            for item in node.targets[0].elts
        ]
        == ["crypt32", "kernel32"]
        and isinstance(node.value, ast.Call)
        and _qualified_name(node.value.func) == "_libraries"
        and not node.value.args
        and not node.value.keywords
    )
    library_calls = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Call) and _qualified_name(node.func) == "_libraries"
    )
    library_factory_references = {
        node
        for node in nodes
        if isinstance(node, ast.Name) and node.id == "_libraries"
    }
    allowed_library_factory_references = {
        node.func
        for node in library_calls
        if isinstance(node.func, ast.Name)
    }
    library_functions = tuple(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_libraries"
    )
    dpapi_calls = tuple(
        node
        for node in nodes
        if isinstance(node, ast.Call) and _qualified_name(node.func) == "_call"
    )
    if (
        len(library_bindings) != 2
        or set(library_calls) != {node.value for node in library_bindings}
        or library_factory_references != allowed_library_factory_references
        or len(library_functions) != 1
        or len(dpapi_calls) != 2
        or any(
            len(node.args) < 3
            or not isinstance(node.args[2], ast.Name)
            or node.args[2].id != "kernel32"
            for node in dpapi_calls
        )
    ):
        return False
    library_returns = tuple(
        node
        for node in ast.walk(library_functions[0])
        if isinstance(node, ast.Return)
    )
    if (
        len(library_returns) != 1
        or not isinstance(library_returns[0].value, ast.Tuple)
        or [
            item.id if isinstance(item, ast.Name) else ""
            for item in library_returns[0].value.elts
        ]
        != ["crypt32", "kernel32"]
    ):
        return False
    library_references = {
        node
        for node in nodes
        if isinstance(node, ast.Name) and node.id in libraries
    }
    allowed_library_references = {
        child
        for node in native_attribute_nodes
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and child.id in libraries
    }
    allowed_library_references.update(
        node.targets[0]
        for node in nodes
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in libraries
        and isinstance(node.value, ast.Call)
        and _qualified_name(node.value.func) == "ctypes.WinDLL"
    )
    allowed_library_references.update(
        item for node in library_bindings for item in node.targets[0].elts
    )
    allowed_library_references.update(library_returns[0].value.elts)
    allowed_library_references.update(node.args[2] for node in dpapi_calls)
    return (
        set(native_attributes) == allowed_native_attributes
        and native_attributes.count("crypt32.CryptProtectData") == 1
        and native_attributes.count("crypt32.CryptUnprotectData") == 1
        and native_attributes.count("kernel32.LocalFree") == 2
        and library_references == allowed_library_references
    )


def _exact_admin_probe(node: ast.Call) -> bool:
    return (
        _qualified_name(node.func) == "ctypes.windll.shell32.IsUserAnAdmin"
        and not node.args
        and not node.keywords
    )
