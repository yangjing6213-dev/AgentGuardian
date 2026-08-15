import ast
import ctypes
import hashlib
import io
import json
import sys
import tokenize
from pathlib import Path

from . import __version__

DEFAULT_RULES_PATH = Path(__file__).with_name("rules") / "default.json"
SOURCE_POLICY_PATH = Path(__file__).with_name("source_policy.json")

_MAX_MANIFEST_BYTES = 65_536
_MANIFEST_ERROR = ("SOURCE_POLICY_MANIFEST_INVALID", "SOURCE_SCAN_ERROR")
_NETWORK_MODULES = {
    "aiohttp",
    "ftplib",
    "http",
    "httpx",
    "imaplib",
    "nntplib",
    "poplib",
    "requests",
    "smtplib",
    "socket",
    "socketserver",
    "telnetlib",
    "urllib",
    "urllib3",
    "websockets",
    "xmlrpc",
}
_NETWORK_IMPORT_PREFIXES = (
    "pyside6.qtnetwork",
    "pyside6.qtwebengine",
    "pyside6.qtwebsockets",
)
_AUDITED_CAPABILITY_MODULES = {"remediation.py", "share_verification.py"}
_SAFE_DIRECT_IMPORTS = {
    "ast",
    "ctypes",
    "hashlib",
    "hmac",
    "ipaddress",
    "json",
    "math",
    "ntpath",
    "os",
    "pathlib",
    "re",
    "secrets",
    "stat",
    "sys",
    "unicodedata",
}
_SAFE_FROM_IMPORTS = {
    "__future__",
    "agentguardian",
    "collections.abc",
    "ctypes",
    "dataclasses",
    "dataclasses.dataclass",
    "datetime",
    "enum",
    "enum.Enum",
    "hashlib",
    "html",
    "itertools",
    "math",
    "pathlib.Path",
    "pathlib",
    "pyside6.qtcore",
    "pyside6.qtgui",
    "pyside6.qtwidgets",
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
_WRITE_MEMBERS = {
    "chmod",
    "copy",
    "copy_into",
    "hardlink_to",
    "lchmod",
    "link",
    "link_to",
    "mkdir",
    "move",
    "move_into",
    "open",
    "rename",
    "replace",
    "rmdir",
    "symlink",
    "symlink_to",
    "touch",
    "truncate",
    "unlink",
    "write",
    "write_bytes",
    "write_text",
    "writelines",
}
_OS_WRITE_NAMES = {
    "os.chmod",
    "os.chown",
    "os.fdopen",
    "os.fchmod",
    "os.fchown",
    "os.ftruncate",
    "os.link",
    "os.lchown",
    "os.makedirs",
    "os.mkfifo",
    "os.mknod",
    "os.mkdir",
    "os.open",
    "os.pwrite",
    "os.pwritev",
    "os.remove",
    "os.removedirs",
    "os.renames",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.symlink",
    "os.truncate",
    "os.unlink",
    "os.utime",
    "os.write",
    "os.writev",
}
_SENSITIVE_DYNAMIC_MEMBERS = {"__dict__", "__getattribute__", "__import__"}


def collect_self_audit() -> dict[str, object]:
    findings = static_capability_findings()
    network_capability = _network_capability(findings)
    return {
        "version": __version__,
        "python_version": (
            f"{sys.version_info.major}."
            f"{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "rules_sha256": _rules_sha256(),
        "local_only": network_capability == "not_detected" and not findings,
        "network_capability": network_capability,
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
    policy = _load_source_policy()
    if policy is None:
        return _MANIFEST_ERROR
    root = _package_root(package_root)
    scan_declared_network = package_root is None
    if not root.is_dir():
        return ("SOURCE_SCAN_ERROR",)
    try:
        modules = sorted(root.rglob("*.py"), key=lambda path: _module_key(root, path))
    except OSError:
        return ("SOURCE_SCAN_ERROR",)

    findings: set[str] = set()
    relative_paths = [module.relative_to(root).as_posix() for module in modules]
    module_names = set(relative_paths)
    reviewed_names = set(policy)
    reviewed_package = (
        package_root is None
        or (root / SOURCE_POLICY_PATH.name).is_file()
        or bool(module_names & reviewed_names)
    )
    if reviewed_package and module_names != reviewed_names:
        findings.add("SOURCE_POLICY_VIOLATION")
    for module, relative_path in zip(modules, relative_paths, strict=True):
        try:
            source = module.read_bytes()
            tree = ast.parse(source, filename=str(module))
            digest = _canonical_source_sha256(source)
        except (OSError, SyntaxError, UnicodeError):
            if reviewed_package:
                findings.add("SOURCE_POLICY_VIOLATION")
            findings.add("SOURCE_SCAN_ERROR")
            continue
        if reviewed_package:
            expected = policy.get(relative_path)
            if expected is None or digest != expected:
                findings.add("SOURCE_POLICY_VIOLATION")
            if scan_declared_network and relative_path in _AUDITED_CAPABILITY_MODULES:
                _scan_heuristic(tree, findings)
        else:
            _scan_heuristic(tree, findings)
    return tuple(sorted(findings))


def _load_source_policy() -> dict[str, str] | None:
    try:
        with SOURCE_POLICY_PATH.open("rb") as stream:
            raw = stream.read(_MAX_MANIFEST_BYTES + 1)
        if not raw or len(raw) > _MAX_MANIFEST_BYTES:
            raise ValueError
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(data) is not dict or list(data) != ["schema", "modules"]:
            raise ValueError
        if type(data["schema"]) is not int or data["schema"] != 1:
            raise ValueError
        modules = data["modules"]
        if type(modules) is not dict or not modules:
            raise ValueError
        names = list(modules)
        if names != sorted(names):
            raise ValueError
        for name, digest in modules.items():
            if not _canonical_module_name(name) or not _canonical_digest(digest):
                raise ValueError
        return modules
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError
    return dict(pairs)


def _canonical_module_name(value: object) -> bool:
    if type(value) is not str or not value.endswith(".py") or "\\" in value:
        return False
    parts = value.split("/")
    stems = [*parts[:-1], parts[-1][:-3]]
    return bool(stems) and all(
        stem
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in stem)
        for stem in stems
    )


def _canonical_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_source_sha256(source: bytes) -> str:
    normalized = source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    encoding, _ = tokenize.detect_encoding(io.BytesIO(normalized).readline)
    decoded = normalized.decode(encoding)
    return hashlib.sha256(decoded.encode("utf-8")).hexdigest()


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


def _scan_heuristic(tree: ast.Module, findings: set[str]) -> None:
    direct_calls = {
        node.func: node for node in ast.walk(tree) if isinstance(node, ast.Call)
    }
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                findings.update(_import_findings(alias.name))
                if alias.asname and alias.name.split(".", 1)[0] in {"os", "pathlib"}:
                    findings.add("SOURCE_POLICY_VIOLATION")
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                findings.update(_import_findings(node.module, alias.name))
                if alias.asname and node.module.split(".", 1)[0] in {"os", "pathlib"}:
                    findings.add("SOURCE_POLICY_VIOLATION")
        elif isinstance(node, ast.Call):
            _scan_call(node, findings)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            _scan_name(node, findings, parents, direct_calls)
        elif isinstance(node, ast.Attribute):
            _scan_attribute(node, findings, direct_calls)
        elif isinstance(node, ast.Subscript):
            _scan_subscript(node, findings)


def _scan_call(node: ast.Call, findings: set[str]) -> None:
    name = _qualified_name(node.func)
    member = _literal_getattr_member(node)
    if name in {"__import__", "builtins.__import__", "compile", "eval", "exec"}:
        findings.add("DYNAMIC_EXECUTION")
    if _is_shell_name(name):
        findings.add("SHELL_EXECUTION")
    if name in {"globals", "locals"} or (name == "vars" and not node.args):
        findings.add("SOURCE_POLICY_VIOLATION")
    if name == "getattr":
        if (
            member is None
            or member in _SENSITIVE_DYNAMIC_MEMBERS
            or member in _WRITE_MEMBERS
            or not _has_exact_zero_default(node)
        ):
            findings.add("SOURCE_POLICY_VIOLATION")
        if member == "__import__":
            findings.add("DYNAMIC_EXECUTION")
        if member in _WRITE_MEMBERS:
            findings.add("USER_DATA_WRITE")
    mode = _open_mode(node)
    if (
        mode is not None
        and any(flag in mode for flag in "wax+")
    ):
        findings.add("USER_DATA_WRITE")


def _scan_name(
    node: ast.Name,
    findings: set[str],
    parents: dict[ast.AST, ast.AST],
    direct_calls: dict[ast.expr, ast.Call],
) -> None:
    if node.id == "__builtins__":
        findings.update(("DYNAMIC_EXECUTION", "SOURCE_POLICY_VIOLATION"))
    elif node.id == "__import__":
        findings.add("DYNAMIC_EXECUTION")
    elif node.id in {"globals", "locals", "vars"}:
        findings.add("SOURCE_POLICY_VIOLATION")
    elif node.id == "open":
        direct = direct_calls.get(node)
        mode = _open_mode(direct) if direct is not None else None
        if mode is None or any(flag in mode for flag in "wax+"):
            findings.add("USER_DATA_WRITE")
    elif node.id in {"os", "pathlib", "Path"}:
        parent = parents.get(node)
        namespace = isinstance(parent, ast.Attribute) and parent.value is node
        constructor = (
            node.id == "Path" and isinstance(parent, ast.Call) and parent.func is node
        )
        if not namespace and not constructor:
            findings.add("SOURCE_POLICY_VIOLATION")


def _scan_attribute(
    node: ast.Attribute,
    findings: set[str],
    direct_calls: dict[ast.expr, ast.Call],
) -> None:
    name = _qualified_name(node)
    if _is_shell_name(name):
        findings.add("SHELL_EXECUTION")
    if name == "sys.modules" or node.attr in {
        "__annotations__",
        "__dict__",
        "__getattribute__",
    }:
        findings.add("SOURCE_POLICY_VIOLATION")
    if "clipboard_" in node.attr:
        findings.add("CLIPBOARD_CAPABILITY")
        if node.attr in {"clipboard_append", "clipboard_clear"}:
            findings.add("USER_DATA_WRITE")
    direct = direct_calls.get(node)
    mode = _open_mode(direct) if direct is not None else None
    if (
        (node.attr in _WRITE_MEMBERS or name in _OS_WRITE_NAMES)
        and not (mode is not None and not any(flag in mode for flag in "wax+"))
    ):
        findings.add("USER_DATA_WRITE")


def _scan_subscript(node: ast.Subscript, findings: set[str]) -> None:
    if not isinstance(node.slice, ast.Constant):
        return
    key = node.slice.value
    target = _qualified_name(node.value)
    if target in {"__builtins__", "builtins", "__builtins__.__dict__"}:
        findings.update(("DYNAMIC_EXECUTION", "SOURCE_POLICY_VIOLATION"))
        if key == "open":
            findings.add("USER_DATA_WRITE")
    if target == "sys.modules":
        findings.add("SOURCE_POLICY_VIOLATION")


def _literal_getattr_member(node: ast.Call) -> str | None:
    if _qualified_name(node.func) != "getattr" or len(node.args) < 2:
        return None
    member = node.args[1]
    if isinstance(member, ast.Constant) and isinstance(member.value, str):
        return member.value
    return None


def _has_exact_zero_default(node: ast.Call) -> bool:
    if len(node.args) != 3 or node.keywords:
        return False
    default = node.args[2]
    return (
        isinstance(default, ast.Constant)
        and type(default.value) is int
        and default.value == 0
    )


def _import_findings(module: str, member: str | None = None) -> set[str]:
    normalized = module.casefold()
    qualified = f"{normalized}.{member.casefold()}" if member else normalized
    root = normalized.split(".", 1)[0]
    findings: set[str] = set()
    if root in _NETWORK_MODULES or any(
        qualified.startswith(prefix) for prefix in _NETWORK_IMPORT_PREFIXES
    ):
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
    if root == "ctypes":
        findings.add("NATIVE_CAPABILITY")
    if root == "webbrowser":
        findings.update(("EXTERNAL_CAPABILITY", "NETWORK_MODULE_IMPORT"))
    if root == "sqlite3":
        findings.add("DATABASE_CAPABILITY")
    if root == "os" and member and _is_shell_name(f"os.{member}"):
        findings.add("SHELL_EXECUTION")
    if root == "os" and member and f"os.{member}" in _OS_WRITE_NAMES:
        findings.add("USER_DATA_WRITE")
    if root == "builtins" and member == "open":
        findings.add("USER_DATA_WRITE")
    safe = (
        normalized in _SAFE_DIRECT_IMPORTS
        if member is None
        else normalized in _SAFE_FROM_IMPORTS
    )
    if not findings and not safe:
        findings.add("SOURCE_POLICY_VIOLATION")
    return findings


def _qualified_name(expression: ast.expr) -> str:
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute):
        parent = _qualified_name(expression.value)
        return f"{parent}.{expression.attr}" if parent else expression.attr
    return ""


def _open_mode(node: ast.Call | None) -> str | None:
    if node is None:
        return None
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


def _is_shell_name(name: str) -> bool:
    lowered = name.casefold()
    return lowered in {"os.popen", "os.startfile", "os.system"} or lowered.startswith(
        "os.spawn"
    )
