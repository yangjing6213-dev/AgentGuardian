import ast
import hashlib
import hmac
import json
from pathlib import Path
import unicodedata

import pytest

import agentguardian.detectors as detector_module
from agentguardian.detectors import (
    DEFAULT_RULES_PATH,
    MAX_FINDINGS,
    DetectionLimitError,
    detect_file,
    detect_mcp_config,
    detect_text,
    load_rules,
)
from agentguardian.dispositions import make_disposition_ref
from agentguardian.domain import RiskDomain, Severity


SCAN_KEY = b"k" * 32
DISPOSITION_KEY = b"d" * 32


class _BytesSubclass(bytes):
    pass


def _track_finding_calls(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls = [0]
    original = detector_module._finding

    def tracked(*args: object, **kwargs: object):
        calls[0] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(detector_module, "_finding", tracked)
    return calls


def _detector_policy_violations(source: str) -> set[str]:
    blocked_imports = {"ftplib", "http", "requests", "socket", "subprocess", "urllib"}
    dangerous_names = {"__import__", "compile", "eval", "exec", "popen", "system"}
    mutating_attributes = {
        "mkdir",
        "remove",
        "rename",
        "rmdir",
        "touch",
        "unlink",
        "write",
        "write_bytes",
        "write_text",
        "writelines",
    }
    violations: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in blocked_imports:
                    violations.add(f"import:{root}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            if root in blocked_imports:
                violations.add(f"import:{root}")
        elif isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                if function.id == "open":
                    _check_open_mode(node, 1, violations)
                elif function.id in dangerous_names:
                    violations.add(f"call:{function.id}")
            elif isinstance(function, ast.Attribute):
                owner = _root_name(function.value)
                if function.attr == "open":
                    mode_position = 1 if owner == "Path" and isinstance(function.value, ast.Name) else 0
                    _check_open_mode(node, mode_position, violations)
                if function.attr in mutating_attributes:
                    violations.add(f"call:{function.attr}")
                if owner == "os" and function.attr in {"popen", "system"}:
                    violations.add(f"call:os.{function.attr}")
                if owner == "subprocess":
                    violations.add(f"call:subprocess.{function.attr}")
    return violations


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Call)):
        node = node.value if isinstance(node, ast.Attribute) else node.func
    return node.id if isinstance(node, ast.Name) else None


def _check_open_mode(
    call: ast.Call,
    position: int,
    violations: set[str],
) -> None:
    mode_node = call.args[position] if len(call.args) > position else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        mode = "r"
    elif isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        mode = mode_node.value
    else:
        mode = "<dynamic>"
    if mode == "<dynamic>" or any(flag in mode for flag in "wax+"):
        violations.add(f"open-mode:{mode}")


def test_default_rules_load_with_valid_schema() -> None:
    bundle = load_rules(DEFAULT_RULES_PATH)

    assert bundle.version == "1.1.0"
    assert {rule.rule_id for rule in bundle.rules} == {
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL_OVERRIDE",
        "GENERIC_API_KEY",
        "EMAIL_ADDRESS",
        "CN_MOBILE_PHONE",
    }


def test_rule_loader_rejects_invalid_schema(tmp_path: Path) -> None:
    rules_path = tmp_path / "invalid.json"
    rules_path.write_text(json.dumps({"version": "1.0.0", "rules": [{}]}))

    with pytest.raises(ValueError, match="rule_id"):
        load_rules(rules_path)


def test_rule_loader_hides_malformed_json_exception_chain(tmp_path: Path) -> None:
    marker = "private" + "-rule-marker"
    rules_path = tmp_path / "malformed.json"
    rules_path.write_text('{"rules": ["' + marker + '"')

    with pytest.raises(ValueError) as captured:
        load_rules(rules_path)

    error = captured.value
    assert str(error) == "rule bundle must be readable UTF-8 JSON"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert marker not in repr(error)


def test_rule_loader_rejects_negative_match_group(tmp_path: Path) -> None:
    rules_path = tmp_path / "invalid-group.json"
    rules_path.write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "rules": [
                    {
                        "rule_id": "TEST_RULE",
                        "domain": "privacy",
                        "severity": "low",
                        "kind": "email",
                        "pattern": "value",
                        "match_group": -1,
                    }
                ],
            }
        )
    )

    with pytest.raises(ValueError, match="match_group"):
        load_rules(rules_path)


def test_secret_is_masked_and_hmac_fingerprinted() -> None:
    secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuv"
    findings = detect_text(
        f"OPENAI_API_KEY={secret}",
        "sample.env",
        scan_key=SCAN_KEY,
    )

    assert len(findings) == 1
    finding = findings[0]
    expected = hmac.new(
        SCAN_KEY,
        ("OPENAI_API_KEY" + secret).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert finding.rule_id == "OPENAI_API_KEY"
    assert finding.root_fingerprint == expected
    assert finding.evidence[0].fingerprint == expected
    assert finding.evidence[0].source == "sample.env"
    assert finding.evidence[0].masked.startswith("sk-p")
    assert secret not in finding.evidence[0].masked
    assert "abcdefghijkl" not in finding.evidence[0].masked


def test_detector_keeps_report_and_disposition_hmac_purposes_separate() -> None:
    secret = "sk-" + "proj-" + "synthetic-private-value"
    source = r"C:\Synthetic\private\config.env"
    arguments = {
        "text": f"OPENAI_API_KEY={secret}",
        "source": source,
        "disposition_key": DISPOSITION_KEY,
    }

    first = detect_text(**arguments, scan_key=b"a" * 32)[0]
    second = detect_text(**arguments, scan_key=b"b" * 32)[0]

    assert first.root_fingerprint != second.root_fingerprint
    assert first.disposition_ref == second.disposition_ref
    assert first.disposition_ref == make_disposition_ref(
        DISPOSITION_KEY,
        rule_id="OPENAI_API_KEY",
        source=source,
        raw_match=secret,
    )
    assert first.disposition_ref is not None
    assert first.disposition_ref not in repr(first)
    evidence = repr(first.evidence)
    for private_value in (
        secret,
        source,
        "private",
        repr(DISPOSITION_KEY),
        DISPOSITION_KEY.hex(),
        first.disposition_ref,
    ):
        assert private_value not in evidence


def test_detector_disposition_ref_separates_inputs_and_normalizes_windows_paths() -> None:
    secret = "sk-" + "proj-" + "synthetic-disposition-value"

    def reference(
        *,
        source: str = r"C:\Synthetic\config.env",
        key: bytes = DISPOSITION_KEY,
        raw: str = secret,
    ) -> str | None:
        return detect_text(
            raw,
            source,
            scan_key=SCAN_KEY,
            disposition_key=key,
        )[0].disposition_ref

    base = reference()
    equivalent = reference(source=r"c:\synthetic\.\config.env")
    custom_rule = detect_text(
        secret,
        r"C:\Synthetic\config.env",
        scan_key=SCAN_KEY,
        disposition_key=DISPOSITION_KEY,
        keywords=(secret,),
    )[1]
    separated = {
        base,
        reference(key=b"e" * 32),
        reference(source=r"C:\Synthetic\moved.env"),
        reference(raw="sk-proj-synthetic-changed-value"),
        custom_rule.disposition_ref,
    }

    assert base == equivalent
    assert custom_rule.rule_id == "CUSTOM_KEYWORD"
    assert len(separated) == 5
    assert reference(source="C:\\Synthetic\\caf\u00e9.env") != reference(
        source="C:\\Synthetic\\cafe\u0301.env"
    )


@pytest.mark.parametrize(
    "disposition_key",
    (
        b"short",
        b"x" * 33,
        bytearray(b"private-key-marker".ljust(32, b"x")),
        _BytesSubclass(b"y" * 32),
    ),
)
def test_public_detectors_reject_invalid_disposition_key_before_zero_findings(
    tmp_path: Path,
    disposition_key: object,
) -> None:
    raw_marker = "private-raw-marker"
    source_marker = r"C:\Private\private-source-marker.txt"
    file_path = tmp_path / "private-file-marker.txt"
    file_path.write_text("safe", encoding="utf-8")
    calls = (
        lambda: detect_text(
            raw_marker,
            source_marker,
            scan_key=SCAN_KEY,
            disposition_key=disposition_key,  # type: ignore[arg-type]
        ),
        lambda: detect_mcp_config(
            {},
            source_marker,
            scan_key=SCAN_KEY,
            disposition_key=disposition_key,  # type: ignore[arg-type]
        ),
        lambda: detect_file(
            file_path,
            scan_key=SCAN_KEY,
            disposition_key=disposition_key,  # type: ignore[arg-type]
        ),
    )

    for call in calls:
        with pytest.raises(ValueError) as captured:
            call()

        error = captured.value
        assert str(error) == "DISPOSITION_INVALID"
        assert error.__cause__ is None
        assert error.__context__ is None
        exception_text = repr(error)
        for private_value in (
            raw_marker,
            source_marker,
            "private-source-marker",
            str(file_path),
            file_path.name,
            repr(disposition_key),
            bytes(disposition_key).hex(),
        ):
            assert private_value not in exception_text


def test_omitted_disposition_key_preserves_none_reference() -> None:
    secret = "sk-" + "proj-" + "synthetic-backward-compatible"

    finding = detect_text(secret, "sample.env", scan_key=SCAN_KEY)[0]

    assert finding.disposition_ref is None


def test_openai_base_url_override_is_masked() -> None:
    endpoint = "https://synthetic-provider.invalid/v1"

    finding = detect_text(
        f"OPENAI_BASE_URL={endpoint}",
        ".env",
        scan_key=SCAN_KEY,
    )[0]

    expected = hmac.new(
        SCAN_KEY,
        ("OPENAI_BASE_URL_OVERRIDE" + endpoint).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert finding.rule_id == "OPENAI_BASE_URL_OVERRIDE"
    assert finding.domain is RiskDomain.SUPPLY_CHAIN
    assert finding.severity is Severity.LOW
    assert finding.root_fingerprint == expected
    assert finding.evidence[0].masked == "OpenAI API base URL override configured"
    assert endpoint not in repr(finding)


def test_fingerprint_preserves_nfkc_normalized_match_boundaries() -> None:
    raw_match = " " + "\uff21" + "\t"
    normalized_match = unicodedata.normalize("NFKC", raw_match)

    raw_finding = detect_text(
        f"prefix{raw_match}suffix",
        "sample.txt",
        scan_key=SCAN_KEY,
        keywords=(raw_match,),
    )[0]
    normalized_finding = detect_text(
        f"prefix{normalized_match}suffix",
        "sample.txt",
        scan_key=SCAN_KEY,
        keywords=(normalized_match,),
    )[0]
    expected = hmac.new(
        SCAN_KEY,
        ("CUSTOM_KEYWORD" + normalized_match).encode(),
        hashlib.sha256,
    ).hexdigest()
    stripped = hmac.new(
        SCAN_KEY,
        ("CUSTOM_KEYWORD" + normalized_match.strip()).encode(),
        hashlib.sha256,
    ).hexdigest()

    assert raw_finding.root_fingerprint == expected
    assert raw_finding.evidence[0].fingerprint == expected
    assert raw_finding.root_fingerprint == normalized_finding.root_fingerprint
    assert raw_finding.root_fingerprint != stripped


def test_scan_key_must_contain_at_least_32_bytes() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        detect_text("nothing", "sample.txt", scan_key=b"short")


def test_detect_text_allows_exact_finding_limit() -> None:
    phone = "138" + "1234" + "5678"
    text = (phone + " ") * MAX_FINDINGS

    findings = detect_text(
        text,
        "sample.txt",
        scan_key=SCAN_KEY,
        disposition_key=DISPOSITION_KEY,
    )

    assert MAX_FINDINGS == 1000
    assert len(findings) == MAX_FINDINGS
    assert all(finding.disposition_ref is not None for finding in findings)


def test_detect_text_stops_before_excess_rule_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phone = "138" + "1234" + "5678"
    text = (phone + " ") * (MAX_FINDINGS + 1)
    calls = _track_finding_calls(monkeypatch)

    with pytest.raises(DetectionLimitError) as captured:
        detect_text(text, "sample.txt", scan_key=SCAN_KEY)

    error = captured.value
    assert str(error) == "finding limit reached"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert phone not in repr(error)
    assert calls == [MAX_FINDINGS]


def test_email_phone_and_custom_chinese_keyword_are_masked() -> None:
    email = "alice" + "@" + "example.invalid"
    phone = "138" + "1234" + "5678"
    keyword = "北" + "辰"
    findings = detect_text(
        f"联系人 {email} {phone}，项目代号：{keyword}",
        "chat.txt",
        scan_key=SCAN_KEY,
        keywords=(keyword,),
    )

    by_rule = {finding.rule_id: finding for finding in findings}
    assert set(by_rule) == {"EMAIL_ADDRESS", "CN_MOBILE_PHONE", "CUSTOM_KEYWORD"}
    for raw, finding in ((email, by_rule["EMAIL_ADDRESS"]), (phone, by_rule["CN_MOBILE_PHONE"]), (keyword, by_rule["CUSTOM_KEYWORD"])):
        assert raw not in finding.evidence[0].masked
    assert by_rule["CUSTOM_KEYWORD"].evidence[0].masked == "**"


def test_long_email_uses_fixed_length_mask() -> None:
    local = "a" * 64
    domain = "b" * 63
    suffix = "c" * 63
    email = local + "@" + domain + "." + suffix

    findings = detect_text(email, "sample.txt", scan_key=SCAN_KEY)

    assert len(findings) == 1
    masked = findings[0].evidence[0].masked
    assert masked == "a***@***.***"
    assert email not in masked
    assert len(masked) <= 80


def test_custom_keyword_uses_literal_case_sensitive_matching() -> None:
    findings = detect_text(
        "Project project project.*",
        "chat.txt",
        scan_key=SCAN_KEY,
        keywords=("project", "project.*"),
    )

    assert [finding.rule_id for finding in findings] == [
        "CUSTOM_KEYWORD",
        "CUSTOM_KEYWORD",
        "CUSTOM_KEYWORD",
    ]


def test_detect_text_reduces_source_path_to_display_name() -> None:
    secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuv"

    finding = detect_text(
        secret,
        r"C:\Users\Alice\sample.env",
        scan_key=SCAN_KEY,
    )[0]

    assert finding.evidence[0].source == "sample.env"


def test_detect_text_keeps_source_within_domain_contract() -> None:
    secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuv"

    finding = detect_text(
        secret,
        "label:" + "x" * 100,
        scan_key=SCAN_KEY,
    )[0]

    assert len(finding.evidence[0].source) <= 80
    assert ":" not in finding.evidence[0].source


def test_mcp_combination_requires_all_capabilities_on_same_server() -> None:
    dangerous = json.dumps(
        {
            "mcpServers": {
                "local-tool": {
                    "capabilities": {
                        "process": True,
                        "filesystem": {"write": True},
                        "network": True,
                    }
                }
            }
        }
    )
    split = json.dumps(
        {
            "mcpServers": {
                "process-only": {"capabilities": {"process": True}},
                "io": {
                    "capabilities": {
                        "filesystem": {"write": True},
                        "network": True,
                    }
                },
            }
        }
    )
    read_only = json.dumps(
        {
            "mcpServers": {
                "reader": {
                    "permissions": ["shell", "filesystem:read", "network"]
                }
            }
        }
    )

    findings = detect_mcp_config(dangerous, "mcp.json", scan_key=SCAN_KEY)

    assert len(findings) == 1
    assert findings[0].rule_id == "MCP_DANGEROUS_COMBINATION"
    assert findings[0].evidence[0].masked == "shell + filesystem write + network"
    assert detect_mcp_config(split, "mcp.json", scan_key=SCAN_KEY) == ()
    assert detect_mcp_config(read_only, "mcp.json", scan_key=SCAN_KEY) == ()


def test_custom_keyword_and_mcp_findings_receive_local_references() -> None:
    keyword = "synthetic-private-keyword"
    text_source = r"C:\Synthetic\private\chat.txt"
    server_name = "synthetic-private-server"
    mcp_source = r"C:\Synthetic\private\mcp.json"
    config = {
        "mcpServers": {
            server_name: {
                "capabilities": {
                    "process": True,
                    "filesystem": {"write": True},
                    "network": True,
                }
            }
        }
    }

    keyword_finding = detect_text(
        keyword,
        text_source,
        scan_key=SCAN_KEY,
        keywords=(keyword,),
        disposition_key=DISPOSITION_KEY,
    )[0]
    mcp_finding = detect_mcp_config(
        config,
        mcp_source,
        scan_key=SCAN_KEY,
        disposition_key=DISPOSITION_KEY,
    )[0]

    assert keyword_finding.disposition_ref == make_disposition_ref(
        DISPOSITION_KEY,
        rule_id="CUSTOM_KEYWORD",
        source=text_source,
        raw_match=keyword,
    )
    assert mcp_finding.disposition_ref == make_disposition_ref(
        DISPOSITION_KEY,
        rule_id="MCP_DANGEROUS_COMBINATION",
        source=mcp_source,
        raw_match=server_name,
    )
    assert keyword_finding.evidence[0].source == "chat.txt"
    assert mcp_finding.evidence[0].source == "mcp.json"
    assert keyword not in repr(keyword_finding)
    assert server_name not in repr(mcp_finding)


def test_mcp_detector_rejects_non_object_json() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        detect_mcp_config("[]", "mcp.json", scan_key=SCAN_KEY)


def test_mcp_detector_hides_malformed_json_exception_chain() -> None:
    marker = "private" + "-mcp-marker"
    config = '{"mcpServers": ["' + marker + '"'

    with pytest.raises(ValueError) as captured:
        detect_mcp_config(config, "mcp.json", scan_key=SCAN_KEY)

    error = captured.value
    assert str(error) == "MCP config must be valid JSON"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert marker not in repr(error)


def test_mcp_detector_ignores_descriptive_metadata() -> None:
    config = json.dumps(
        {
            "mcpServers": {
                "documented-reader": {
                    "description": ["shell", "filesystem:write", "network"]
                }
            }
        }
    )

    assert detect_mcp_config(config, "mcp.json", scan_key=SCAN_KEY) == ()


def test_mcp_detector_stops_before_excess_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = {
        "capabilities": {
            "process": True,
            "filesystem": {"write": True},
            "network": True,
        }
    }
    config = {
        "mcpServers": {
            f"server-{index}": capability for index in range(MAX_FINDINGS + 1)
        }
    }
    calls = _track_finding_calls(monkeypatch)

    with pytest.raises(DetectionLimitError, match="^finding limit reached$"):
        detect_mcp_config(config, "mcp.json", scan_key=SCAN_KEY)

    assert calls == [MAX_FINDINGS]


@pytest.mark.parametrize(
    ("encoding", "with_bom"),
    (("utf-8", False), ("utf-8-sig", True), ("utf-16-le", False)),
)
def test_detect_file_supports_required_text_encodings(
    tmp_path: Path,
    encoding: str,
    with_bom: bool,
) -> None:
    secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuv"
    path = tmp_path / f"sample-{encoding}.txt"
    content = f"OPENAI_API_KEY={secret}".encode(encoding)
    assert content.startswith(b"\xef\xbb\xbf") is with_bom
    path.write_bytes(content)

    result = detect_file(path, scan_key=SCAN_KEY)

    assert result.scanned is True
    assert result.limits == ()
    assert len(result.findings) == 1


def test_detect_file_uses_full_path_only_for_disposition_identity(
    tmp_path: Path,
) -> None:
    secret = "sk-" + "proj-" + "synthetic-file-identity"
    first_path = tmp_path / "first-private-directory" / "config.env"
    second_path = tmp_path / "second-private-directory" / "config.env"
    first_path.parent.mkdir()
    second_path.parent.mkdir()
    first_path.write_text(secret, encoding="utf-8")
    second_path.write_text(secret, encoding="utf-8")

    first = detect_file(
        first_path,
        scan_key=SCAN_KEY,
        disposition_key=DISPOSITION_KEY,
    ).findings[0]
    second = detect_file(
        second_path,
        scan_key=SCAN_KEY,
        disposition_key=DISPOSITION_KEY,
    ).findings[0]
    direct = detect_text(
        secret,
        str(first_path.absolute()),
        scan_key=SCAN_KEY,
        disposition_key=DISPOSITION_KEY,
    )[0]

    assert first.disposition_ref == direct.disposition_ref
    assert first.disposition_ref != second.disposition_ref
    assert first.evidence[0].source == second.evidence[0].source == "config.env"
    assert str(first_path) not in repr(first)
    assert str(second_path) not in repr(second)
    assert first_path.parent.name not in repr(first)
    assert second_path.parent.name not in repr(second)


def test_detect_file_reports_oversize_without_scanning(tmp_path: Path) -> None:
    path = tmp_path / "large.txt"
    with path.open("wb") as stream:
        stream.seek(10 * 1024 * 1024)
        stream.write(b"x")

    result = detect_file(path, scan_key=SCAN_KEY)

    assert result.scanned is False
    assert result.findings == ()
    assert result.limits == ("file_too_large",)


def test_detect_file_reports_decode_failure_without_scanning(tmp_path: Path) -> None:
    path = tmp_path / "binary.dat"
    path.write_bytes(b"\xff\xff\xff")

    result = detect_file(path, scan_key=SCAN_KEY)

    assert result.scanned is False
    assert result.findings == ()
    assert result.limits == ("unsupported_text_encoding",)


def test_detect_file_reports_malformed_bom_without_raising(tmp_path: Path) -> None:
    path = tmp_path / "malformed.txt"
    path.write_bytes(b"\xef\xbb\xbf\xff")

    result = detect_file(path, scan_key=SCAN_KEY)

    assert result.scanned is False
    assert result.findings == ()
    assert result.limits == ("unsupported_text_encoding",)


def test_detect_file_returns_masked_findings_when_keyword_limit_is_reached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyword = "needle"
    path = tmp_path / "many.txt"
    path.write_text((keyword + " ") * (MAX_FINDINGS + 1), encoding="utf-8")
    calls = _track_finding_calls(monkeypatch)

    result = detect_file(
        path,
        scan_key=SCAN_KEY,
        keywords=(keyword,),
        disposition_key=DISPOSITION_KEY,
    )

    assert result.scanned is False
    assert result.limits == ("finding_limit_reached",)
    assert len(result.findings) == MAX_FINDINGS
    assert all(finding.evidence[0].masked == "******" for finding in result.findings)
    assert all(finding.disposition_ref is not None for finding in result.findings)
    assert calls == [MAX_FINDINGS]


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("from socket import create_connection", "import:socket"),
        ("eval('synthetic')", "call:eval"),
        ("import os\nos.system('synthetic')", "call:os.system"),
        (
            "import subprocess\nsubprocess.run(['synthetic'])",
            "call:subprocess.run",
        ),
        ("open('synthetic.txt', 'w')", "open-mode:w"),
        ("Path('synthetic.txt').open(mode='a')", "open-mode:a"),
        ("Path('synthetic.txt').write_text('synthetic')", "call:write_text"),
    ),
)
def test_detector_ast_policy_checker_flags_disallowed_patterns(
    source: str,
    expected: str,
) -> None:
    assert expected in _detector_policy_violations(source)


@pytest.mark.parametrize(
    "source",
    (
        "open('synthetic.txt', 'rb')",
        "Path('synthetic.txt').open(mode='r', encoding='utf-8')",
    ),
)
def test_detector_ast_policy_checker_allows_explicit_read_modes(source: str) -> None:
    assert _detector_policy_violations(source) == set()


def test_detector_ast_matches_local_read_only_policy() -> None:
    module_path = Path(__file__).parents[1] / "src" / "agentguardian" / "detectors.py"
    source = module_path.read_text(encoding="utf-8")

    assert _detector_policy_violations(source) == set()
