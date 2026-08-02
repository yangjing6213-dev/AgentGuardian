from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
from pathlib import Path
import re
import unicodedata

from .dispositions import make_disposition_ref
from .domain import Evidence, Finding, RiskDomain, Severity


DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "default.json"
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FINDINGS = 1000
_INPUT_ERROR = "DETECTOR_INPUT_INVALID"


class DetectionLimitError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("finding limit reached")


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    domain: RiskDomain
    severity: Severity
    kind: str
    pattern: re.Pattern[str]
    match_group: str | int = 0


@dataclass(frozen=True, slots=True)
class RuleBundle:
    version: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True, slots=True)
class FileDetectionResult:
    findings: tuple[Finding, ...]
    scanned: bool
    limits: tuple[str, ...]


def load_rules(path: str | Path = DEFAULT_RULES_PATH) -> RuleBundle:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        text = None
    if text is None:
        raise ValueError("rule bundle must be readable UTF-8 JSON")
    raw = _parse_json(text, "rule bundle must be readable UTF-8 JSON")
    if not isinstance(raw, dict):
        raise ValueError("rule bundle must be a JSON object")
    version = raw.get("version")
    rules = raw.get("rules")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("rule bundle version must be a non-empty string")
    if not isinstance(rules, list) or not rules:
        raise ValueError("rule bundle rules must be a non-empty list")

    parsed: list[Rule] = []
    seen: set[str] = set()
    for item in rules:
        if not isinstance(item, dict):
            raise ValueError("each rule must be a JSON object")
        rule_id = item.get("rule_id")
        if not isinstance(rule_id, str) or re.fullmatch(r"[A-Z][A-Z0-9_]*", rule_id) is None:
            raise ValueError("rule_id must use uppercase letters, digits, and underscores")
        if rule_id in seen:
            raise ValueError(f"duplicate rule_id: {rule_id}")
        seen.add(rule_id)
        try:
            domain = RiskDomain(item.get("domain"))
            severity = Severity(item.get("severity"))
        except ValueError as error:
            raise ValueError(f"invalid domain or severity for {rule_id}") from error
        kind = item.get("kind")
        pattern_text = item.get("pattern")
        match_group = item.get("match_group", 0)
        if kind not in {"secret", "email", "phone", "endpoint"}:
            raise ValueError(f"invalid kind for {rule_id}")
        if not isinstance(pattern_text, str) or not pattern_text:
            raise ValueError(f"pattern must be a non-empty string for {rule_id}")
        if not isinstance(match_group, (str, int)) or isinstance(match_group, bool):
            raise ValueError(f"match_group must be a string or integer for {rule_id}")
        try:
            pattern = re.compile(pattern_text)
            if isinstance(match_group, int) and not 0 <= match_group <= pattern.groups:
                raise IndexError
            if isinstance(match_group, str) and match_group not in pattern.groupindex:
                raise IndexError
        except (IndexError, re.error) as error:
            raise ValueError(f"invalid pattern or match_group for {rule_id}") from error
        parsed.append(Rule(rule_id, domain, severity, kind, pattern, match_group))
    return RuleBundle(version, tuple(parsed))


def detect_text(
    text: str,
    source: str,
    *,
    scan_key: bytes,
    keywords: Sequence[str] = (),
    disposition_key: bytes | None = None,
) -> tuple[Finding, ...]:
    text = _validated_string(text)
    source = _validated_string(source)
    validated_keywords = _validated_keywords(keywords)
    key = _validated_key(scan_key)
    local_key = _validated_disposition_key(disposition_key)
    findings, limit_reached = _detect_text(
        text,
        source,
        key,
        validated_keywords,
        disposition_key=local_key,
        source_identity=source,
    )
    if limit_reached:
        raise DetectionLimitError()
    return findings


def _detect_text(
    text: str,
    source: str,
    scan_key: bytes,
    keywords: Sequence[str],
    *,
    disposition_key: bytes | None = None,
    source_identity: str,
) -> tuple[tuple[Finding, ...], bool]:
    key = _validated_key(scan_key)
    source_name = _safe_filename(source)
    findings: list[Finding] = []
    occupied: list[tuple[int, int]] = []
    for rule in load_rules().rules:
        for match in rule.pattern.finditer(text):
            span = match.span(rule.match_group)
            if any(start < span[1] and span[0] < end for start, end in occupied):
                continue
            if len(findings) >= MAX_FINDINGS:
                return tuple(findings), True
            raw_match = match.group(rule.match_group)
            findings.append(
                _finding(
                    rule.rule_id,
                    rule.domain,
                    rule.severity,
                    raw_match,
                    rule.kind,
                    source_name,
                    key,
                    disposition_key=disposition_key,
                    source_identity=source_identity,
                )
            )
            occupied.append(span)

    for keyword in keywords:
        start = 0
        while (index := text.find(keyword, start)) >= 0:
            if len(findings) >= MAX_FINDINGS:
                return tuple(findings), True
            findings.append(
                _finding(
                    "CUSTOM_KEYWORD",
                    RiskDomain.PRIVACY,
                    Severity.MEDIUM,
                    keyword,
                    "keyword",
                    source_name,
                    key,
                    disposition_key=disposition_key,
                    source_identity=source_identity,
                )
            )
            start = index + len(keyword)
    return tuple(findings), False


def detect_mcp_config(
    config: str | Mapping[str, object],
    source: str,
    *,
    scan_key: bytes,
    disposition_key: bytes | None = None,
) -> tuple[Finding, ...]:
    source = _validated_string(source)
    key = _validated_key(scan_key)
    local_key = _validated_disposition_key(disposition_key)
    if isinstance(config, str):
        parsed = _parse_json(config, "MCP config must be valid JSON")
    else:
        parsed = config
    if not isinstance(parsed, Mapping):
        raise ValueError("MCP config must be a JSON object")
    servers = parsed.get("mcpServers", parsed.get("servers", {}))
    if not isinstance(servers, Mapping):
        raise ValueError("MCP servers must be a JSON object")

    findings: list[Finding] = []
    for server_name, server in servers.items():
        if type(server_name) is not str or not isinstance(server, Mapping):
            continue
        paths = tuple(_active_capability_paths(server))
        joined = ("_".join(path) for path in paths)
        capabilities = tuple(joined)
        has_shell = any(
            any(part in {"shell", "process", "subprocess", "exec", "command_execution"} for part in path)
            for path in paths
        )
        has_write_filesystem = any(
            "filesystem" in capability and "write" in capability
            for capability in capabilities
        )
        has_network = any(
            any(part in {"network", "network_access", "internet", "http"} for part in path)
            for path in paths
        )
        if has_shell and has_write_filesystem and has_network:
            if len(findings) >= MAX_FINDINGS:
                raise DetectionLimitError()
            findings.append(
                _finding(
                    "MCP_DANGEROUS_COMBINATION",
                    RiskDomain.PERMISSIONS,
                    Severity.HIGH,
                    server_name,
                    "mcp",
                    _safe_filename(source),
                    key,
                    disposition_key=local_key,
                    source_identity=source,
                )
            )
    return tuple(findings)


def detect_file(
    path: str | Path,
    *,
    scan_key: bytes,
    keywords: Sequence[str] = (),
    disposition_key: bytes | None = None,
) -> FileDetectionResult:
    validated_keywords = _validated_keywords(keywords)
    key = _validated_key(scan_key)
    local_key = _validated_disposition_key(disposition_key)
    file_path = Path(path).absolute()
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return FileDetectionResult((), False, ("file_too_large",))
        with open(file_path, "rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
    except OSError:
        return FileDetectionResult((), False, ("file_read_error",))
    if len(data) > MAX_FILE_BYTES:
        return FileDetectionResult((), False, ("file_too_large",))
    text = _decode_text(data)
    if text is None:
        return FileDetectionResult((), False, ("unsupported_text_encoding",))
    findings, limit_reached = _detect_text(
        text,
        file_path.name,
        key,
        validated_keywords,
        disposition_key=local_key,
        source_identity=str(file_path),
    )
    if limit_reached:
        return FileDetectionResult(findings, False, ("finding_limit_reached",))
    return FileDetectionResult(findings, True, ())


def _finding(
    rule_id: str,
    domain: RiskDomain,
    severity: Severity,
    raw_match: str,
    kind: str,
    source: str,
    scan_key: bytes,
    *,
    disposition_key: bytes | None = None,
    source_identity: str,
) -> Finding:
    masked = _mask(raw_match, kind)
    fingerprint = hmac.new(
        scan_key,
        (rule_id + unicodedata.normalize("NFKC", raw_match)).encode("utf-8"),
        sha256,
    ).hexdigest()
    local_reference = (
        make_disposition_ref(
            disposition_key,
            rule_id=rule_id,
            source=source_identity,
            raw_match=raw_match,
        )
        if disposition_key is not None
        else None
    )
    evidence = Evidence(source=source, fingerprint=fingerprint, masked=masked)
    return Finding(
        rule_id,
        domain,
        severity,
        fingerprint,
        (evidence,),
        disposition_ref=local_reference,
    )


def _parse_json(value: str, message: str) -> object:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        pass
    raise ValueError(message)


def _mask(value: str, kind: str) -> str:
    if kind == "mcp":
        return "shell + filesystem write + network"
    if kind == "endpoint":
        return "OpenAI API base URL override configured"
    if kind == "phone":
        return value[:3] + "****" + value[-4:]
    if kind == "email":
        local = value.split("@", 1)[0]
        return local[:1] + "***@***.***"
    if kind == "keyword":
        return "*" * min(len(value), 16)
    if len(value) <= 8:
        return value[:1] + "*" * max(1, len(value) - 2) + value[-1:]
    return value[:4] + "*" * min(12, len(value) - 8) + value[-4:]


def _validated_key(scan_key: bytes) -> bytes:
    if not isinstance(scan_key, bytes) or len(scan_key) < 32:
        raise ValueError("scan_key must contain at least 32 bytes")
    return scan_key


def _validated_disposition_key(disposition_key: bytes | None) -> bytes | None:
    if disposition_key is not None and (
        type(disposition_key) is not bytes or len(disposition_key) != 32
    ):
        raise ValueError("DISPOSITION_INVALID")
    return disposition_key


def _validated_string(value: object) -> str:
    if type(value) is not str:
        raise ValueError(_INPUT_ERROR)
    return value


def _validated_keywords(keywords: Sequence[str]) -> tuple[str, ...]:
    validated: list[str] = []
    for keyword in keywords:
        if type(keyword) is not str:
            raise ValueError(_INPUT_ERROR)
        if not keyword:
            raise ValueError("keywords must contain non-empty strings")
        validated.append(keyword)
    return tuple(validated)


def _safe_filename(source: str) -> str:
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    name = source.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(
        character if character.isprintable() and character != ":" else "_"
        for character in name
    )
    return (name or "unknown")[:80]


def _normal_token(value: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _active_capability_paths(
    value: object,
    path: tuple[str, ...] = (),
) -> tuple[tuple[str, ...], ...]:
    found: list[tuple[str, ...]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or child is False or child is None:
                continue
            token = _normal_token(key)
            if token in {"args", "command", "description", "env", "name", "title"}:
                continue
            found.extend(_active_capability_paths(child, path + (token,)))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            found.extend(_active_capability_paths(child, path))
    elif value is True:
        found.append(path)
    elif isinstance(value, str):
        found.append(path + (_normal_token(value),))
    return tuple(found)


def _decode_text(data: bytes) -> str | None:
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
    if data.startswith(b"\xff\xfe"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if len(data) >= 4 and data[1::2].count(0) / len(data[1::2]) >= 0.2:
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        if len(data) % 2:
            return None
        try:
            decoded = data.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        printable = sum(character.isprintable() or character.isspace() for character in decoded)
        return decoded if decoded and printable / len(decoded) >= 0.9 else None
