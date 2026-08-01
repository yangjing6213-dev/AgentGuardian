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
    allow_admin_probe = _allowed_ctypes_usage(relative_path, tree)
    allowed_report_call = _allowed_report_export_call(relative_path, tree)
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
                if root == "ctypes" and not allow_admin_probe:
                    findings.add("NATIVE_CAPABILITY")
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                imported_bindings.add(alias.asname or alias.name)
                findings.update(_import_findings(node.module, alias.name))
                if alias.asname and node.module.split(".", 1)[0] in {
                    "os",
                    "pathlib",
                }:
                    findings.add("SOURCE_POLICY_VIOLATION")
                if node.module.split(".", 1)[0] == "ctypes":
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

    for node in ast.walk(tree):
        alias_sources = _direct_alias_sources(node)
        if alias_sources & _RESTRICTED_BINDINGS:
            findings.add("SOURCE_POLICY_VIOLATION")
        if "__import__" in alias_sources:
            findings.add("DYNAMIC_EXECUTION")
        if isinstance(node, ast.Attribute):
            _classify_attribute(node, rebound, findings, allow_admin_probe)
        elif isinstance(node, ast.Call):
            name = _qualified_name(node.func)
            if name in {"__import__", "compile", "eval", "exec"}:
                findings.add("DYNAMIC_EXECUTION")
            mode = _open_mode(node)
            if (
                mode is not None
                and any(flag in mode for flag in "wax+")
                and node is not allowed_report_call
            ):
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
    allow_admin_probe: bool,
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
    if "clipboard_" in node.attr:
        findings.add("CLIPBOARD_CAPABILITY")
        if node.attr in {"clipboard_append", "clipboard_clear"}:
            findings.add("USER_DATA_WRITE")
    if name.startswith("ctypes.") and not allow_admin_probe:
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
    if _qualified_name(node.func) not in {"open", "builtins.open"}:
        return None
    mode_node = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "mode"),
        node.args[1] if len(node.args) > 1 else None,
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


def _keyword_is(node: ast.Call, name: str, value: str) -> bool:
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
    if relative_path != "self_audit.py":
        return False
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


def _exact_admin_probe(node: ast.Call) -> bool:
    return (
        _qualified_name(node.func) == "ctypes.windll.shell32.IsUserAnAdmin"
        and not node.args
        and not node.keywords
    )
