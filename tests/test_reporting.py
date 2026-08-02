import ast
from datetime import datetime, timezone
from html import escape
import json
import math
from pathlib import Path

import pytest

from agentguardian.detectors import detect_text
from agentguardian.dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
    reviewed_findings,
)
from agentguardian.domain import Evidence, Finding, RiskDomain, Score, Severity
from agentguardian.reporting import render_html, render_json
from agentguardian.scoring import score as calculate_score


EVALUATED_AT = datetime(2026, 8, 2, 12, tzinfo=timezone.utc)


def _score() -> Score:
    return Score(
        total=39,
        deductions=tuple(
            (domain, 7 if domain is RiskDomain.CREDENTIALS else 0)
            for domain in RiskDomain
        ),
        cap_reason="public_active_credential",
        coverage=0.75,
        confidence=0.8,
        limits=("未扫描浏览器",),
        incomplete=True,
    )


def _findings() -> tuple[Finding, ...]:
    return (
        Finding(
            "Z_RULE",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "b" * 64,
            (
                Evidence("凭据.env", "d" * 64, "sk-p************stuv"),
                Evidence("配置.txt", "c" * 64, "身份证号：********1234"),
            ),
        ),
        Finding(
            "A_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "a" * 64,
            (Evidence("分享记录.txt", "e" * 64, "已脱敏分享标识"),),
        ),
    )


def _reviewed_report_inputs() -> tuple[
    tuple[Finding, ...], tuple[DispositionRecord, ...], Score, Score
]:
    findings = (
        Finding(
            "PUBLIC_ACTIVE_CREDENTIAL",
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            "a" * 64,
            (),
            "1" * 64,
        ),
        Finding(
            "ACCEPTED_RULE",
            RiskDomain.PRIVACY,
            Severity.MEDIUM,
            "b" * 64,
            (),
            "2" * 64,
        ),
        Finding(
            "EXPIRED_RULE",
            RiskDomain.EXPOSURE,
            Severity.LOW,
            "c" * 64,
            (),
            "3" * 64,
        ),
        Finding(
            "OPEN_RULE",
            RiskDomain.RETENTION,
            Severity.LOW,
            "d" * 64,
            (),
        ),
        Finding(
            "MISMATCH_RULE",
            RiskDomain.PERMISSIONS,
            Severity.LOW,
            "e" * 64,
            (),
            "4" * 64,
        ),
    )
    records = (
        DispositionRecord(
            "1" * 64,
            "PUBLIC_ACTIVE_CREDENTIAL",
            DispositionStatus.FALSE_POSITIVE,
            "Synthetic <false positive>",
            "Reviewer & one",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        ),
        DispositionRecord(
            "2" * 64,
            "ACCEPTED_RULE",
            DispositionStatus.ACCEPTED_RISK,
            "Accepted <risk>",
            "Reviewer & two",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        ),
        DispositionRecord(
            "3" * 64,
            "EXPIRED_RULE",
            DispositionStatus.FALSE_POSITIVE,
            "Expired <false positive>",
            "Reviewer & three",
            "2026-08-01T08:00:00Z",
            "2026-08-02T11:00:00Z",
        ),
        DispositionRecord(
            "4" * 64,
            "OTHER_RULE",
            DispositionStatus.ACCEPTED_RISK,
            "Should stay hidden",
            "Hidden reviewer",
            "2026-08-02T08:00:00Z",
            "2026-08-03T08:00:00Z",
        ),
    )
    scoring_options = {
        "coverage": 0.75,
        "confidence": 0.8,
        "limits": ("browser not scanned",),
    }
    technical = calculate_score(findings, **scoring_options)
    reviewed = calculate_score(
        reviewed_findings(
            findings,
            disposition_index(records),
            now=EVALUATED_AT,
        ),
        **scoring_options,
    )
    return findings, records, technical, reviewed


def _expected_score_data(score: Score) -> dict[str, object]:
    return {
        "total": score.total,
        "deductions": [
            {"domain": domain.value, "amount": amount}
            for domain, amount in score.deductions
        ],
        "cap_reason": score.cap_reason,
        "coverage": score.coverage,
        "confidence": score.confidence,
        "incomplete": score.incomplete,
        "limits": list(score.limits),
    }


def test_render_json_contains_safe_complete_deterministic_report() -> None:
    first = render_json(_score(), _findings(), rule_version="规则-1")
    second = render_json(_score(), tuple(reversed(_findings())), rule_version="规则-1")
    report = json.loads(first)

    assert first == second
    assert first == json.dumps(report, ensure_ascii=False, indent=2)
    assert report["product"] == "AgentGuardian"
    assert report["version"] == "0.1.0"
    assert report["rule_version"] == "规则-1"
    assert report["score"] == {
        "total": 39,
        "deductions": [
            {"domain": domain.value, "amount": 7 if domain is RiskDomain.CREDENTIALS else 0}
            for domain in RiskDomain
        ],
        "cap_reason": "public_active_credential",
        "coverage": 0.75,
        "confidence": 0.8,
        "incomplete": True,
        "limits": ["未扫描浏览器"],
    }
    assert report["reviewed_score"] == report["score"]
    assert all(
        finding["disposition"] == {"status": "open"}
        for finding in report["findings"]
    )
    assert [finding["rule_id"] for finding in report["findings"]] == [
        "A_RULE",
        "Z_RULE",
    ]
    assert report["findings"][1]["root_hmac_fingerprint"] == "b" * 64
    evidence = report["findings"][1]["evidence"]
    assert [item["source"] for item in evidence] == ["配置.txt", "凭据.env"]
    assert evidence[0]["hmac_fingerprint"] == "c" * 64
    assert evidence[0]["masked"] == "身份证号：********1234"
    assert "身份证号" in first


def test_render_json_exports_exact_reviewed_dispositions_from_one_shot_inputs() -> None:
    findings, records, technical, reviewed = _reviewed_report_inputs()
    finding_generator = (finding for finding in reversed(findings))
    disposition_generator = (record for record in reversed(records))

    first = render_json(
        technical,
        finding_generator,
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=disposition_generator,
        evaluated_at=EVALUATED_AT,
    )
    second = render_json(
        technical,
        (finding for finding in findings),
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=(record for record in records),
        evaluated_at=EVALUATED_AT,
    )
    report = json.loads(first)
    by_rule = {finding["rule_id"]: finding for finding in report["findings"]}

    assert first == second
    assert tuple(finding_generator) == ()
    assert tuple(disposition_generator) == ()
    assert report["score"] == _expected_score_data(technical)
    assert report["reviewed_score"] == _expected_score_data(reviewed)
    assert report["score"]["total"] == 39
    assert report["reviewed_score"]["total"] == 94
    assert by_rule["PUBLIC_ACTIVE_CREDENTIAL"]["disposition"] == {
        "status": "false_positive",
        "reason": "Synthetic <false positive>",
        "reviewer": "Reviewer & one",
        "created_at": "2026-08-02T08:00:00Z",
        "expires_at": "2026-08-03T08:00:00Z",
    }
    assert by_rule["ACCEPTED_RULE"]["disposition"] == {
        "status": "accepted_risk",
        "reason": "Accepted <risk>",
        "reviewer": "Reviewer & two",
        "created_at": "2026-08-02T08:00:00Z",
        "expires_at": "2026-08-03T08:00:00Z",
    }
    assert by_rule["EXPIRED_RULE"]["disposition"] == {
        "status": "expired",
        "last_status": "false_positive",
        "reason": "Expired <false positive>",
        "reviewer": "Reviewer & three",
        "created_at": "2026-08-01T08:00:00Z",
        "expires_at": "2026-08-02T11:00:00Z",
    }
    assert by_rule["OPEN_RULE"]["disposition"] == {"status": "open"}
    assert by_rule["MISMATCH_RULE"]["disposition"] == {"status": "open"}
    assert "Should stay hidden" not in first
    assert "Hidden reviewer" not in first
    assert "disposition_ref" not in first
    for finding in findings:
        if finding.disposition_ref is not None:
            assert finding.disposition_ref not in first


def test_real_detection_scoring_reporting_chain_keeps_raw_data_private() -> None:
    raw_secret = "sk-" + "proj-" + "abcdefghijklmnopqrstuv"
    full_source = r"C:\Users\Synthetic\sample.env"
    scan_key = b"synthetic-scan-key-with-at-least-32-bytes"
    disposition_key = b"private-disposition-key-12345678"
    findings = detect_text(
        f"OPENAI_API_KEY={raw_secret}",
        full_source,
        scan_key=scan_key,
        disposition_key=disposition_key,
    )
    assert findings[0].disposition_ref is not None
    record = DispositionRecord(
        findings[0].disposition_ref,
        findings[0].rule_id,
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic <reviewed>",
        "Analyst & owner",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )
    audit_score = calculate_score(findings, coverage=1.0)
    reviewed_score = calculate_score((), coverage=1.0)
    json_report = render_json(
        audit_score,
        findings,
        rule_version="rules-1",
        reviewed_score=reviewed_score,
        dispositions=(record for record in (record,)),
        evaluated_at=EVALUATED_AT,
    )
    html_report = render_html(
        audit_score,
        (finding for finding in findings),
        rule_version="rules-1",
        reviewed_score=reviewed_score,
        dispositions=(record for record in (record,)),
        evaluated_at=EVALUATED_AT,
    )
    finding = findings[0]
    evidence = finding.evidence[0]

    assert finding.evidence[0].source == "sample.env"
    assert json.loads(json_report)["findings"][0]["evidence"][0]["source"] == "sample.env"

    for output in (json_report, html_report):
        assert raw_secret not in output
        assert full_source not in output
        assert scan_key.decode() not in output
        assert disposition_key.decode() not in output
        assert findings[0].disposition_ref not in output
        assert "disposition_ref" not in output
        assert "sample.env" in output
        assert evidence.masked in output
        assert findings[0].root_fingerprint in output
        assert evidence.fingerprint in output

    disposition = json.loads(json_report)["findings"][0]["disposition"]
    assert disposition["reason"] == "Synthetic <reviewed>"
    assert disposition["reviewer"] == "Analyst & owner"
    assert "Synthetic <reviewed>" not in html_report
    assert "Analyst & owner" not in html_report
    assert escape("Synthetic <reviewed>", quote=True) in html_report
    assert escape("Analyst & owner", quote=True) in html_report


def test_render_json_rejects_non_finite_score_values() -> None:
    malformed = Score(
        100,
        ((RiskDomain.EXPOSURE, math.nan),),
        None,
        1.0,
        1.0,
        (),
        False,
    )

    with pytest.raises(ValueError, match="Out of range float values"):
        render_json(malformed, (), rule_version="rules-1")

    with pytest.raises(ValueError, match="Out of range float values"):
        render_json(
            _score(),
            (),
            rule_version="rules-1",
            reviewed_score=malformed,
        )


def test_render_html_escapes_every_dynamic_text_field() -> None:
    malicious = "<svg onload='alert(1)'>"
    finding = Finding(
        malicious,
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        (Evidence("<img onerror='x'>", "e" * 64, "<b onclick='x'>已脱敏"),),
    )
    audit_score = Score(
        97,
        tuple((domain, 3 if domain is RiskDomain.PRIVACY else 0) for domain in RiskDomain),
        malicious,
        1.0,
        0.5,
        (malicious,),
        True,
    )

    rendered = render_html(audit_score, (finding,), rule_version=malicious)

    assert malicious not in rendered
    assert "<img onerror='x'>" not in rendered
    assert "<b onclick='x'>已脱敏" not in rendered
    assert escape(malicious, quote=True) in rendered
    assert escape("<img onerror='x'>", quote=True) in rendered
    assert escape("<b onclick='x'>已脱敏", quote=True) in rendered
    assert "HMAC fingerprint" in rendered


def test_render_html_contains_requested_score_and_finding_fields() -> None:
    rendered = render_html(_score(), _findings(), rule_version="规则-1")

    for value in (
        "AgentGuardian",
        "0.1.0",
        "规则-1",
        "39",
        "public_active_credential",
        "0.75",
        "0.8",
        "未扫描浏览器",
        "Z_RULE",
        "凭据.env",
        "身份证号：********1234",
        "b" * 64,
        "c" * 64,
    ):
        assert escape(value, quote=True) in rendered

    assert "<h2>Technical score</h2>" in rendered
    assert "<h2>Reviewed score</h2>" in rendered
    assert rendered.count("<p>Disposition status: open</p>") == 2
    assert "Disposition reason:" not in rendered


def test_render_html_presents_complete_reviewed_scores_and_dispositions() -> None:
    findings, records, technical, reviewed = _reviewed_report_inputs()

    forward = render_html(
        technical,
        (finding for finding in findings),
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=(record for record in records),
        evaluated_at=EVALUATED_AT,
    )
    reverse = render_html(
        technical,
        (finding for finding in reversed(findings)),
        rule_version="rules-1",
        reviewed_score=reviewed,
        dispositions=(record for record in reversed(records)),
        evaluated_at=EVALUATED_AT,
    )

    assert forward == reverse
    technical_section = forward[
        forward.index("<h2>Technical score</h2>") : forward.index(
            "<h2>Reviewed score</h2>"
        )
    ]
    reviewed_section = forward[
        forward.index("<h2>Reviewed score</h2>") : forward.index(
            "<h2>Findings</h2>"
        )
    ]
    for section, audit_score in (
        (technical_section, technical),
        (reviewed_section, reviewed),
    ):
        assert f"<p>Total: {audit_score.total}</p>" in section
        assert "<h3>Domain deductions</h3>" in section
        assert f"<p>Coverage: {audit_score.coverage}</p>" in section
        assert f"<p>Confidence: {audit_score.confidence}</p>" in section
        assert "<p>Incomplete: true</p>" in section
        assert "browser not scanned" in section
        for domain, amount in audit_score.deductions:
            assert f"<li>{domain.value}: {amount}</li>" in section
    assert "<p>Cap reason: public_active_credential</p>" in technical_section
    assert "<p>Cap reason: None</p>" in reviewed_section
    assert "<p>Disposition status: false_positive</p>" in forward
    assert "<p>Disposition status: accepted_risk</p>" in forward
    assert "<p>Disposition status: expired</p>" in forward
    assert "<p>Last disposition status: false_positive</p>" in forward
    for value in (
        "Synthetic <false positive>",
        "Reviewer & one",
        "Accepted <risk>",
        "Reviewer & two",
        "Expired <false positive>",
        "Reviewer & three",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
        "2026-08-01T08:00:00Z",
        "2026-08-02T11:00:00Z",
    ):
        assert escape(value, quote=True) in forward
    assert "Synthetic <false positive>" not in forward
    assert "Accepted <risk>" not in forward
    assert "Expired <false positive>" not in forward
    assert "Should stay hidden" not in forward
    assert "Hidden reviewer" not in forward
    assert "disposition_ref" not in forward
    mismatch_section = forward[
        forward.index("<h3>MISMATCH_RULE</h3>") : forward.index(
            "<h3>OPEN_RULE</h3>"
        )
    ]
    assert "<p>Disposition status: open</p>" in mismatch_section
    assert "Disposition reason:" not in mismatch_section
    assert "Disposition reviewer:" not in mismatch_section
    assert "Disposition created at:" not in mismatch_section
    assert "Disposition expires at:" not in mismatch_section


def test_renderers_sort_identical_finding_keys_by_evidence() -> None:
    first = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        (Evidence("b.txt", "b" * 64, "脱敏证据B"),),
    )
    second = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        (Evidence("a.txt", "a" * 64, "脱敏证据A"),),
    )

    forward_json = render_json(_score(), (first, second), rule_version="规则-1")
    reverse_json = render_json(_score(), (second, first), rule_version="规则-1")
    forward_html = render_html(_score(), (first, second), rule_version="规则-1")
    reverse_html = render_html(_score(), (second, first), rule_version="规则-1")

    assert forward_json == reverse_json
    assert forward_html == reverse_html
    assert [
        item["evidence"][0]["hmac_fingerprint"]
        for item in json.loads(forward_json)["findings"]
    ] == ["a" * 64, "b" * 64]
    assert forward_html.index("a" * 64) < forward_html.index("b" * 64)


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_stabilize_identical_findings_by_safe_disposition(
    renderer: object,
) -> None:
    evidence = (Evidence("same.txt", "a" * 64, "same masked evidence"),)
    false_positive = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        evidence,
        "5" * 64,
    )
    open_finding = Finding(
        "SAME_RULE",
        RiskDomain.PRIVACY,
        Severity.MEDIUM,
        "f" * 64,
        evidence,
        "6" * 64,
    )
    record = DispositionRecord(
        "5" * 64,
        "SAME_RULE",
        DispositionStatus.FALSE_POSITIVE,
        "Synthetic duplicate review",
        "Local reviewer",
        "2026-08-02T08:00:00Z",
        "2026-08-03T08:00:00Z",
    )

    forward = renderer(  # type: ignore[operator]
        _score(),
        (finding for finding in (false_positive, open_finding)),
        rule_version="rules-1",
        dispositions=(item for item in (record,)),
        evaluated_at=EVALUATED_AT,
    )
    reverse = renderer(  # type: ignore[operator]
        _score(),
        (finding for finding in (open_finding, false_positive)),
        rule_version="rules-1",
        dispositions=(item for item in (record,)),
        evaluated_at=EVALUATED_AT,
    )

    assert forward == reverse


@pytest.mark.parametrize("renderer", (render_json, render_html))
def test_renderers_accept_one_shot_finding_generators(renderer: object) -> None:
    findings = (
        finding
        for finding in (
            Finding(
                "GENERATOR_A",
                RiskDomain.EXPOSURE,
                Severity.LOW,
                "a" * 64,
                (),
            ),
            Finding(
                "GENERATOR_B",
                RiskDomain.PRIVACY,
                Severity.MEDIUM,
                "b" * 64,
                (),
            ),
        )
    )

    output = renderer(_score(), findings, rule_version="rules-1")  # type: ignore[operator]

    assert "GENERATOR_A" in output
    assert "GENERATOR_B" in output
    assert tuple(findings) == ()


def test_scoring_and_reporting_use_only_approved_imports_and_calls() -> None:
    allowed_imports = {
        "scoring.py": {
            ("from", 0, "collections.abc", (("Iterable", None),)),
            (
                "from",
                1,
                "domain",
                (
                    ("Finding", None),
                    ("RiskDomain", None),
                    ("Score", None),
                    ("Severity", None),
                ),
            ),
        },
        "reporting.py": {
            ("from", 0, "collections.abc", (("Iterable", None),)),
            (
                "from",
                0,
                "datetime",
                (("datetime", None), ("timezone", None)),
            ),
            ("from", 0, "html", (("escape", None),)),
            ("import", 0, None, (("json", None),)),
            ("from", 1, None, (("__version__", None),)),
            (
                "from",
                1,
                "dispositions",
                (
                    ("DispositionRecord", None),
                    ("disposition_index", None),
                    ("evaluate_disposition", None),
                ),
            ),
            (
                "from",
                1,
                "domain",
                (("Evidence", None), ("Finding", None), ("Score", None)),
            ),
        },
    }
    allowed_name_calls = {
        "scoring.py": {
            "Score",
            "bool",
            "max",
            "min",
            "set",
            "sum",
            "tuple",
        },
        "reporting.py": {
            "_disposition_data",
            "_disposition_sort_key",
            "_finding_data",
            "_score_data",
            "_sorted_evidence",
            "_sorted_finding_dispositions",
            "_text",
            "disposition_index",
            "escape",
            "evaluate_disposition",
            "list",
            "sorted",
            "str",
            "tuple",
        },
    }
    allowed_attribute_calls = {
        "scoring.py": {"add", "get", "items"},
        "reporting.py": {"append", "dumps", "extend", "join", "lower", "now"},
    }
    blocked_dynamic_calls = {"__import__", "eval", "exec", "getattr", "open"}

    package_path = Path(__file__).parents[1] / "src" / "agentguardian"
    for module_name in ("scoring.py", "reporting.py"):
        tree = ast.parse((package_path / module_name).read_text(encoding="utf-8"))
        imports = {
            (
                "import" if isinstance(node, ast.Import) else "from",
                0 if isinstance(node, ast.Import) else node.level,
                None if isinstance(node, ast.Import) else node.module,
                tuple((alias.name, alias.asname) for alias in node.names),
            )
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        }
        calls = [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]
        name_calls = {node.id for node in calls if isinstance(node, ast.Name)}
        attribute_calls = {
            node.attr for node in calls if isinstance(node, ast.Attribute)
        }
        dynamic_calls = {
            type(node).__name__
            for node in calls
            if not isinstance(node, (ast.Name, ast.Attribute))
        }

        assert imports == allowed_imports[module_name]
        assert name_calls <= allowed_name_calls[module_name]
        assert attribute_calls <= allowed_attribute_calls[module_name]
        assert name_calls.isdisjoint(blocked_dynamic_calls)
        assert attribute_calls.isdisjoint(blocked_dynamic_calls)
        assert dynamic_calls == set()
