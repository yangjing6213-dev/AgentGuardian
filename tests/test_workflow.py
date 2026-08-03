from collections.abc import Callable, Iterator
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone, tzinfo
import ntpath
import os
from pathlib import Path

import pytest

import agentguardian.workflow as workflow_module
from agentguardian.dispositions import DispositionRecord, DispositionStatus
from agentguardian.domain import Evidence, Finding, RiskDomain, Score, Severity
from agentguardian.workflow import (
    COVERAGE_LIMIT_LABELS,
    COVERAGE_STATE_LABELS,
    CoverageState,
    FindingFilters,
    ScopeConsent,
    ScopePreview,
    bind_scope_consent,
    build_scope_preview,
    classify_coverage,
    filter_findings,
    scope_consent_matches,
)


ROOTS = (Path(r"C:\Synthetic\selected-root"),)
SELECTORS = (".env", ".json")
CAPS = {
    "max_files": 10_000,
    "max_entries": 50_000,
    "max_bytes": 512 * 1024 * 1024,
    "max_findings": 2_000,
    "max_evidence": 4_000,
}
WINDOWS_RESERVED_COMPONENTS = tuple(
    variant
    for name in (
        "CON",
        "NUL",
        "PRN",
        "AUX",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        *(f"COM{number}" for number in "¹²³"),
        *(f"LPT{number}" for number in "¹²³"),
        "CONIN$",
        "CONOUT$",
    )
    for variant in (name, f"{name.lower()}.txt")
)


class ExplosiveEquality:
    def __init__(self, marker: str) -> None:
        self.marker = marker

    def __eq__(self, _other: object) -> bool:
        raise RuntimeError(self.marker)


def _assert_full_paths_not_in_repr(value: object, roots: tuple[Path, ...]) -> None:
    representation = repr(value).casefold().replace("/", "\\")
    while "\\\\" in representation:
        representation = representation.replace("\\\\", "\\")
    for root in roots:
        identity = ntpath.normcase(
            ntpath.abspath(ntpath.normpath(os.fspath(root)))
        ).casefold()
        assert identity not in representation, "full root path leaked"


def _build_preview(
    roots: tuple[Path, ...] = ROOTS,
    selectors: tuple[str, ...] = SELECTORS,
    **caps: object,
) -> ScopePreview:
    return build_scope_preview(roots, selectors, **(CAPS | caps))


def test_scope_preview_is_pure_private_and_immutable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("scope preview touched the filesystem")

    monkeypatch.setattr(Path, "stat", fail)
    monkeypatch.setattr(Path, "resolve", fail)
    monkeypatch.setattr(Path, "iterdir", fail)
    monkeypatch.setattr(os, "scandir", fail)
    monkeypatch.setattr(os, "listdir", fail)

    preview = _build_preview()

    assert preview.root_count == 1
    assert preview.root_names == ("selected-root",)
    assert preview.selectors == SELECTORS
    assert preview.max_files == 10_000
    assert preview.max_entries == 50_000
    assert preview.max_bytes == 512 * 1024 * 1024
    assert preview.max_findings == 2_000
    assert preview.max_evidence == 4_000
    assert preview.local_only is True
    assert preview.read_only is True
    assert preview.manual_guidance_only is True
    assert preview.unc_roots_excluded is True
    assert preview.drive_roots_excluded is True
    assert preview.reparse_paths_excluded is True
    _assert_full_paths_not_in_repr(preview, ROOTS)
    with pytest.raises(FrozenInstanceError):
        preview.max_files = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    ("roots", "selectors"),
    (
        ((), SELECTORS),
        ([ROOTS[0]], SELECTORS),
        (ROOTS, [".env", ".json"]),
    ),
)
def test_scope_preview_rejects_empty_or_mutable_inputs(
    roots: object, selectors: object
) -> None:
    with pytest.raises((TypeError, ValueError)):
        build_scope_preview(roots, selectors, **CAPS)  # type: ignore[arg-type]


def test_scope_preview_rejects_tuple_and_path_subclasses() -> None:
    class RootTuple(tuple):
        pass

    class SelectorTuple(tuple):
        pass

    class RootPath(type(Path())):
        pass

    with pytest.raises(TypeError):
        _build_preview(RootTuple(ROOTS))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        _build_preview(selectors=SelectorTuple(SELECTORS))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        _build_preview((RootPath(r"C:\Synthetic\selected-root"),))


def test_scope_preview_rejects_duplicate_windows_root_identities() -> None:
    with pytest.raises(ValueError):
        _build_preview(
            (
                Path(r"C:\Synthetic\selected-root"),
                Path(r"c:\synthetic\SELECTED-ROOT\."),
            )
        )


@pytest.mark.parametrize(
    "root",
    (
        Path("C:\\"),
        Path(r"\\server\share\selected-root"),
        Path("C:/Synthetic/" + "x" * 81),
        Path("C:/Synthetic/unsafe\x01name"),
    ),
)
def test_scope_preview_rejects_drive_unc_and_unsafe_names(root: Path) -> None:
    with pytest.raises(ValueError):
        _build_preview((root,))


@pytest.mark.parametrize(
    "root",
    (
        Path(r"relative\root"),
        Path(r"C:drive-relative"),
        Path(r"\rooted\root"),
        Path("/rooted/root"),
    ),
)
def test_scope_root_anchor_rejects_unqualified_windows_roots(root: Path) -> None:
    with pytest.raises(ValueError):
        _build_preview((root,))


def test_scope_root_anchor_keeps_consent_stable_after_chdir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    preview = _build_preview()
    consent = bind_scope_consent(preview)

    monkeypatch.chdir(tmp_path)

    assert bind_scope_consent(preview) == consent
    assert scope_consent_matches(consent, preview) is True


@pytest.mark.parametrize("value", (0, -1, True, 1.0))
@pytest.mark.parametrize("cap_name", tuple(CAPS))
def test_scope_preview_requires_exact_positive_integer_caps(
    cap_name: str, value: object
) -> None:
    with pytest.raises(ValueError):
        _build_preview(**{cap_name: value})


def test_scope_preview_rejects_unsafe_or_duplicate_selectors() -> None:
    class Selector(str):
        pass

    for selectors in (
        (".env", ".env"),
        (".env", r"C:\private\file.json"),
        (".env", "line\nbreak"),
        (".env", Selector(".json")),
    ):
        with pytest.raises((TypeError, ValueError)):
            _build_preview(selectors=selectors)


@pytest.mark.parametrize("unsafe_character", tuple('*?"<>|'))
@pytest.mark.parametrize("target", ("root", "selector"))
def test_scope_preview_rejects_windows_unsafe_short_name_characters(
    unsafe_character: str, target: str
) -> None:
    if target == "root":
        with pytest.raises(ValueError):
            _build_preview(
                (Path(f"C:/Synthetic/unsafe{unsafe_character}name"),)
            )
    else:
        with pytest.raises(ValueError):
            _build_preview(selectors=(f".env{unsafe_character}",))


@pytest.mark.parametrize(
    "component",
    (
        "src.",
        "src ",
        *WINDOWS_RESERVED_COMPONENTS,
        *(f"unsafe{character}name" for character in '*?"<>|'),
    ),
)
@pytest.mark.parametrize("position", ("intermediate", "final"))
def test_scope_preview_rejects_all_windows_unsafe_path_components_before_identity(
    monkeypatch: pytest.MonkeyPatch, component: str, position: str
) -> None:
    parts = ("C:/Synthetic", component)
    if position == "intermediate":
        parts += ("selected-root",)
    root = Path("/".join(parts))

    identity_calls: list[str] = []
    original_normpath = workflow_module.ntpath.normpath

    def record_identity(value: str) -> str:
        identity_calls.append(value)
        return original_normpath(value)

    monkeypatch.setattr(workflow_module.ntpath, "normpath", record_identity)

    with pytest.raises(ValueError):
        _build_preview((root,))
    assert identity_calls == []


def test_consent_binds_to_normalized_roots_without_path_repr() -> None:
    preview = _build_preview(
        (
            Path(r"C:\Synthetic\FIRST\."),
            Path(r"C:\Synthetic\second"),
        )
    )
    equivalent = _build_preview(
        (
            Path(r"c:\synthetic\first"),
            Path(r"c:\SYNTHETIC\SECOND\."),
        )
    )

    consent = bind_scope_consent(preview)

    assert scope_consent_matches(consent, preview) is True
    assert scope_consent_matches(consent, equivalent) is True
    _assert_full_paths_not_in_repr(consent, preview._roots)
    assert not hasattr(consent, "__dict__")
    with pytest.raises(FrozenInstanceError):
        consent.contract_version = 2  # type: ignore[misc]


@pytest.mark.parametrize(
    "leak",
    (
        Path(r"C:\Synthetic\selected-root"),
        r"C:\Synthetic\selected-root",
        r"c:\synthetic\selected-root",
    ),
)
def test_repr_privacy_guard_detects_leaky_forged_preview(leak: object) -> None:
    preview = _build_preview()
    object.__setattr__(preview, "root_names", (leak,))

    with pytest.raises(AssertionError, match="full root path leaked"):
        _assert_full_paths_not_in_repr(preview, ROOTS)


def test_consent_rejects_changed_order_root_and_version() -> None:
    preview = _build_preview(
        (Path(r"C:\Synthetic\first"), Path(r"C:\Synthetic\second"))
    )
    consent = bind_scope_consent(preview)
    reversed_preview = _build_preview(tuple(reversed(preview._roots)))
    changed_root = _build_preview(
        (Path(r"C:\Synthetic\first"), Path(r"C:\Synthetic\third"))
    )
    changed_version = _build_preview(preview._roots)
    object.__setattr__(changed_version, "contract_version", 2)

    assert scope_consent_matches(consent, reversed_preview) is False
    assert scope_consent_matches(consent, changed_root) is False
    assert scope_consent_matches(consent, changed_version) is False


def test_consent_rejects_subclasses_and_forged_mutable_fields() -> None:
    preview = _build_preview()
    consent = bind_scope_consent(preview)

    class ConsentSubclass(ScopeConsent):
        pass

    class PreviewSubclass(ScopePreview):
        pass

    forged_consent_subclass = object.__new__(ConsentSubclass)
    object.__setattr__(
        forged_consent_subclass, "_root_identity", consent._root_identity
    )
    object.__setattr__(
        forged_consent_subclass, "contract_version", consent.contract_version
    )
    forged_preview_subclass = object.__new__(PreviewSubclass)
    for field_name in ScopePreview.__dataclass_fields__:
        object.__setattr__(
            forged_preview_subclass, field_name, getattr(preview, field_name)
        )

    assert scope_consent_matches(forged_consent_subclass, preview) is False
    assert scope_consent_matches(consent, forged_preview_subclass) is False
    with pytest.raises(TypeError):
        bind_scope_consent(forged_preview_subclass)

    object.__setattr__(consent, "_root_identity", list(consent._root_identity))
    object.__setattr__(preview, "_roots", list(preview._roots))
    assert scope_consent_matches(consent, preview) is False
    with pytest.raises(TypeError):
        bind_scope_consent(preview)


def test_consent_match_rejects_non_contract_values() -> None:
    preview = _build_preview()

    assert scope_consent_matches(object(), preview) is False
    assert scope_consent_matches(bind_scope_consent(preview), object()) is False


@pytest.mark.parametrize("target", ("preview", "consent"))
def test_hostile_match_rejects_explosive_exact_contract_fields(target: str) -> None:
    marker = "PRIVATE_EQUALITY_SECRET_MARKER"
    preview = _build_preview()
    consent = bind_scope_consent(preview)
    explosive = ExplosiveEquality(marker)
    if target == "preview":
        object.__setattr__(preview, "root_names", (explosive,))
    else:
        object.__setattr__(consent, "_root_identity", (explosive,))

    assert scope_consent_matches(consent, preview) is False


def test_hostile_match_contains_ordinary_equality_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "PRIVATE_BOUNDARY_SECRET_MARKER"
    explosive = ExplosiveEquality(marker)
    preview = _build_preview()
    consent = bind_scope_consent(preview)

    def fail_validation(_value: object) -> None:
        explosive == object()

    monkeypatch.setattr(workflow_module, "_validate_scope_consent", fail_validation)

    assert scope_consent_matches(consent, preview) is False


def _score(
    *,
    coverage: float = 1.0,
    confidence: float = 1.0,
    limits: tuple[str, ...] = (),
    incomplete: bool = False,
) -> Score:
    return Score(100, (), None, coverage, confidence, limits, incomplete)


def test_coverage_classifier_has_exact_states() -> None:
    assert tuple(state.value for state in CoverageState) == (
        "complete",
        "limited",
        "no_supported_files",
    )
    assert classify_coverage(_score()) is CoverageState.COMPLETE
    assert classify_coverage(_score(coverage=0.5, incomplete=True)) is (
        CoverageState.LIMITED
    )
    assert classify_coverage(
        _score(limits=("file_limit_reached",), incomplete=True)
    ) is CoverageState.LIMITED
    assert classify_coverage(
        _score(
            coverage=0.0,
            limits=("no_supported_files",),
            incomplete=True,
        )
    ) is CoverageState.NO_SUPPORTED_FILES


def test_coverage_labels_are_fixed_chinese_text() -> None:
    assert dict(COVERAGE_STATE_LABELS) == {
        CoverageState.COMPLETE: "已完成",
        CoverageState.LIMITED: "覆盖受限",
        CoverageState.NO_SUPPORTED_FILES: "无支持文件",
    }
    assert dict(COVERAGE_LIMIT_LABELS) == {
        "byte_limit_reached": "达到扫描字节上限",
        "directory_excluded": "目录已排除",
        "directory_read_limited": "目录读取受限",
        "entry_limit_reached": "达到目录条目上限",
        "entry_read_limited": "目录条目读取受限",
        "file_limit_reached": "达到文件数量上限",
        "file_scan_limited": "文件扫描受限",
        "finding_limit_reached": "达到发现数量上限",
        "mcp_config_scan_limited": "MCP 配置扫描受限",
        "no_supported_files": "未发现支持的文件",
        "reparse_changed": "重解析路径在扫描期间发生变化",
        "reparse_excluded": "已排除重解析路径",
        "root_reparse_excluded": "已排除重解析根路径",
    }
    with pytest.raises(TypeError):
        COVERAGE_STATE_LABELS[CoverageState.COMPLETE] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        COVERAGE_LIMIT_LABELS["file_limit_reached"] = "changed"  # type: ignore[index]


def test_coverage_classifier_rejects_non_score_and_subclass() -> None:
    class ScoreSubclass(Score):
        pass

    with pytest.raises(ValueError, match="^COVERAGE_INVALID$"):
        classify_coverage(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="^COVERAGE_INVALID$"):
        classify_coverage(ScoreSubclass(100, (), None, 1.0, 1.0, (), False))


@pytest.mark.parametrize(
    "limits",
    (
        ("unknown-private-marker",),
        ("file_limit_reached", "file_limit_reached"),
    ),
)
def test_coverage_classifier_rejects_unknown_or_duplicate_limits(
    limits: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError, match="^COVERAGE_INVALID$") as raised:
        classify_coverage(_score(coverage=0.5, limits=limits, incomplete=True))
    assert "unknown-private-marker" not in str(raised.value)


@pytest.mark.parametrize(
    "score",
    (
        _score(coverage=0.5),
        _score(limits=("file_limit_reached",)),
        _score(incomplete=True),
        _score(
            coverage=0.1,
            limits=("no_supported_files",),
            incomplete=True,
        ),
        _score(
            coverage=0.0,
            limits=("no_supported_files", "file_limit_reached"),
            incomplete=True,
        ),
    ),
)
def test_coverage_classifier_rejects_contradictory_scores(score: Score) -> None:
    with pytest.raises(ValueError, match="^COVERAGE_INVALID$"):
        classify_coverage(score)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("total", True),
        ("deductions", []),
        ("deductions", ((RiskDomain.EXPOSURE, True),)),
        ("cap_reason", True),
        ("coverage", True),
        ("coverage", float("nan")),
        ("confidence", float("inf")),
        ("limits", ["file_limit_reached"]),
        ("limits", (1,)),
        ("incomplete", 1),
    ),
)
def test_coverage_classifier_rejects_forged_malformed_score_fields(
    field_name: str, invalid_value: object
) -> None:
    score = _score()
    object.__setattr__(score, field_name, invalid_value)

    with pytest.raises(ValueError, match="^COVERAGE_INVALID$"):
        classify_coverage(score)


FILTER_NOW = datetime(2026, 8, 3, 10, tzinfo=timezone.utc)
FILTER_PRIVATE_MARKER = r"C:\private\RAW_MATCH_REVIEW_SECRET.txt"
FILTER_RAW_SECRET = "sk-proj-PRIVATE_RAW_SECRET_MARKER"


class _FilterDatetimeSubclass(datetime):
    pass


class _FilterHostileTimezone(tzinfo):
    def utcoffset(self, value: datetime | None) -> timedelta | None:
        raise RuntimeError(FILTER_PRIVATE_MARKER)


class _FilterCountingUtc(tzinfo):
    def __init__(self) -> None:
        self.calls = 0

    def utcoffset(self, value: datetime | None) -> timedelta:
        self.calls += 1
        return timedelta(0)


class _FilterSinglePass(Iterator[object]):
    def __init__(self, values: tuple[object, ...]) -> None:
        self._values = iter(values)
        self.iterations = 0

    def __iter__(self) -> Iterator[object]:
        self.iterations += 1
        if self.iterations > 1:
            raise RuntimeError(FILTER_PRIVATE_MARKER)
        return self

    def __next__(self) -> object:
        return next(self._values)


class _FilterExplodingIterable:
    def __iter__(self) -> Iterator[object]:
        raise RuntimeError(FILTER_PRIVATE_MARKER)


class _FilterOverLimit:
    def __init__(self, factory: Callable[[int], object]) -> None:
        self._factory = factory
        self.consumed = 0

    def __iter__(self) -> Iterator[object]:
        for index in range(2_001):
            self.consumed += 1
            yield self._factory(index)


def _filter_evidence(index: int) -> Evidence:
    return Evidence(
        f"synthetic-{index}.env",
        f"{index + 100:064x}",
        f"masked synthetic value {index}",
    )


def _forged_filter_evidence(**overrides: object) -> Evidence:
    fields: dict[str, object] = {
        "source": "synthetic.env",
        "fingerprint": "f" * 64,
        "masked": "masked synthetic value",
    }
    fields.update(overrides)
    evidence = object.__new__(Evidence)
    for field_name, value in fields.items():
        object.__setattr__(evidence, field_name, value)
    return evidence


def _filter_finding(
    index: int,
    domain: RiskDomain,
    severity: Severity,
    disposition_ref: str | None = None,
    *,
    evidence_count: int = 1,
) -> Finding:
    return Finding(
        f"RULE_{index}",
        domain,
        severity,
        f"{index + 1:064x}",
        tuple(_filter_evidence(index * 10 + item) for item in range(evidence_count)),
        disposition_ref,
    )


def _forged_filter_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "rule_id": "RULE_9",
        "domain": RiskDomain.EXPOSURE,
        "severity": Severity.LOW,
        "root_fingerprint": "9" * 64,
        "evidence": (_forged_filter_evidence(),),
        "disposition_ref": None,
    }
    fields.update(overrides)
    finding = object.__new__(Finding)
    for field_name, value in fields.items():
        object.__setattr__(finding, field_name, value)
    return finding


def _filter_record(
    disposition_ref: str,
    rule_id: str,
    *,
    status: DispositionStatus = DispositionStatus.FALSE_POSITIVE,
    expires_at: str = "2026-08-03T11:00:00Z",
) -> DispositionRecord:
    return DispositionRecord(
        disposition_ref,
        rule_id,
        status,
        "PRIVATE_REASON_MARKER",
        "PRIVATE_REVIEWER_MARKER",
        "2026-08-03T09:00:00Z",
        expires_at,
    )


def _forged_filter_record(**overrides: object) -> DispositionRecord:
    fields: dict[str, object] = {
        "disposition_ref": "e" * 64,
        "rule_id": "RULE_8",
        "status": DispositionStatus.FALSE_POSITIVE,
        "reason": "Synthetic reason",
        "reviewer": "Synthetic reviewer",
        "created_at": "2026-08-03T09:00:00Z",
        "expires_at": "2026-08-03T11:00:00Z",
    }
    fields.update(overrides)
    record = object.__new__(DispositionRecord)
    for field_name, value in fields.items():
        object.__setattr__(record, field_name, value)
    return record


def _filter_fixture() -> tuple[tuple[Finding, ...], tuple[DispositionRecord, ...]]:
    false_positive_ref = "a" * 64
    accepted_risk_ref = "b" * 64
    expired_ref = "c" * 64
    findings = (
        _filter_finding(0, RiskDomain.EXPOSURE, Severity.CRITICAL, evidence_count=2),
        _filter_finding(
            1,
            RiskDomain.PRIVACY,
            Severity.HIGH,
            false_positive_ref,
            evidence_count=3,
        ),
        _filter_finding(
            2,
            RiskDomain.CREDENTIALS,
            Severity.HIGH,
            accepted_risk_ref,
        ),
        _filter_finding(
            3,
            RiskDomain.PERMISSIONS,
            Severity.MEDIUM,
            expired_ref,
        ),
        _filter_finding(4, RiskDomain.RETENTION, Severity.LOW),
        _filter_finding(5, RiskDomain.SUPPLY_CHAIN, Severity.MEDIUM),
    )
    dispositions = (
        _filter_record(false_positive_ref, "RULE_1"),
        _filter_record(
            accepted_risk_ref,
            "RULE_2",
            status=DispositionStatus.ACCEPTED_RISK,
        ),
        _filter_record(
            expired_ref,
            "RULE_3",
            expires_at="2026-08-03T09:30:00Z",
        ),
    )
    return findings, dispositions


def _assert_finding_filter_invalid(call: Callable[[], object]) -> None:
    with pytest.raises(ValueError) as raised:
        call()

    assert str(raised.value) == "FINDING_FILTER_INVALID"
    for marker in (FILTER_PRIVATE_MARKER, FILTER_RAW_SECRET):
        assert marker not in str(raised.value)
        assert marker not in repr(raised.value)
    assert raised.value.__cause__ is None


def test_finding_filters_are_exact_frozen_slotted_and_private() -> None:
    filters = FindingFilters(
        severity=Severity.HIGH,
        domain=RiskDomain.CREDENTIALS,
        disposition_state="accepted_risk",
    )

    assert filters.severity is Severity.HIGH
    assert filters.domain is RiskDomain.CREDENTIALS
    assert filters.disposition_state == "accepted_risk"
    assert not hasattr(filters, "__dict__")
    assert FILTER_PRIVATE_MARKER not in repr(filters)
    with pytest.raises(FrozenInstanceError):
        filters.severity = Severity.LOW  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("severity", "high"),
        ("severity", True),
        ("domain", "credentials"),
        ("domain", False),
        ("disposition_state", "PRIVATE_UNKNOWN_STATE"),
        ("disposition_state", True),
    ),
)
def test_finding_filters_reject_invalid_exact_field_types(
    field_name: str, invalid_value: object
) -> None:
    _assert_finding_filter_invalid(
        lambda: FindingFilters(**{field_name: invalid_value})  # type: ignore[arg-type]
    )


def test_finding_filters_reject_subclasses_and_forged_mutable_fields() -> None:
    class FindingFiltersSubclass(FindingFilters):
        pass

    _assert_finding_filter_invalid(lambda: FindingFiltersSubclass())

    filters = FindingFilters()
    object.__setattr__(filters, "severity", [Severity.HIGH])
    _assert_finding_filter_invalid(
        lambda: filter_findings((), (), filters, now=FILTER_NOW)
    )


@pytest.mark.parametrize(
    ("filters", "expected_indexes"),
    (
        (FindingFilters(severity=Severity.CRITICAL), (0,)),
        (FindingFilters(severity=Severity.HIGH), (1, 2)),
        (FindingFilters(severity=Severity.MEDIUM), (3, 5)),
        (FindingFilters(severity=Severity.LOW), (4,)),
        (FindingFilters(domain=RiskDomain.EXPOSURE), (0,)),
        (FindingFilters(domain=RiskDomain.PRIVACY), (1,)),
        (FindingFilters(domain=RiskDomain.CREDENTIALS), (2,)),
        (FindingFilters(domain=RiskDomain.PERMISSIONS), (3,)),
        (FindingFilters(domain=RiskDomain.RETENTION), (4,)),
        (FindingFilters(domain=RiskDomain.SUPPLY_CHAIN), (5,)),
        (FindingFilters(disposition_state="open"), (0, 4, 5)),
        (FindingFilters(disposition_state="false_positive"), (1,)),
        (FindingFilters(disposition_state="accepted_risk"), (2,)),
        (FindingFilters(disposition_state="expired"), (3,)),
        (
            FindingFilters(
                severity=Severity.HIGH,
                domain=RiskDomain.CREDENTIALS,
                disposition_state="accepted_risk",
            ),
            (2,),
        ),
    ),
)
def test_filter_findings_applies_exact_criteria_per_finding_in_original_order(
    filters: FindingFilters, expected_indexes: tuple[int, ...]
) -> None:
    findings, dispositions = _filter_fixture()
    finding_input = list(findings)
    disposition_input = list(dispositions)

    visible = filter_findings(
        finding_input,
        disposition_input,
        filters,
        now=FILTER_NOW,
    )

    assert visible == tuple(findings[index] for index in expected_indexes)
    assert all(
        actual is findings[index]
        for actual, index in zip(visible, expected_indexes, strict=True)
    )
    assert finding_input == list(findings)
    assert disposition_input == list(dispositions)


@pytest.mark.parametrize(
    ("filters", "expected_indexes"),
    (
        (
            FindingFilters(severity=Severity.HIGH, domain=RiskDomain.PRIVACY),
            (1,),
        ),
        (
            FindingFilters(severity=Severity.HIGH, domain=RiskDomain.RETENTION),
            (),
        ),
        (
            FindingFilters(
                severity=Severity.HIGH,
                disposition_state="false_positive",
            ),
            (1,),
        ),
        (
            FindingFilters(
                severity=Severity.LOW,
                disposition_state="accepted_risk",
            ),
            (),
        ),
        (
            FindingFilters(
                domain=RiskDomain.PERMISSIONS,
                disposition_state="expired",
            ),
            (3,),
        ),
        (
            FindingFilters(
                domain=RiskDomain.EXPOSURE,
                disposition_state="expired",
            ),
            (),
        ),
    ),
    ids=(
        "severity-domain-positive",
        "severity-domain-negative",
        "severity-disposition-positive",
        "severity-disposition-negative",
        "domain-disposition-positive",
        "domain-disposition-negative",
    ),
)
def test_filter_findings_applies_pairwise_criteria(
    filters: FindingFilters,
    expected_indexes: tuple[int, ...],
) -> None:
    findings, dispositions = _filter_fixture()

    visible = filter_findings(findings, dispositions, filters, now=FILTER_NOW)

    assert visible == tuple(findings[index] for index in expected_indexes)


def test_filter_findings_counts_findings_not_evidence_rows() -> None:
    findings, dispositions = _filter_fixture()

    visible = filter_findings(findings, dispositions, FindingFilters(), now=FILTER_NOW)

    assert len(visible) == len(findings) == 6
    assert sum(len(finding.evidence) for finding in findings) == 9
    assert visible == findings


def test_filter_findings_reuses_expiry_evaluation_at_later_validated_time() -> None:
    reference = "d" * 64
    finding = _filter_finding(
        6,
        RiskDomain.CREDENTIALS,
        Severity.HIGH,
        reference,
    )
    record = _filter_record(reference, "RULE_6")

    assert filter_findings(
        (finding,),
        (record,),
        FindingFilters(disposition_state="false_positive"),
        now=FILTER_NOW,
    ) == (finding,)
    assert filter_findings(
        (finding,),
        (record,),
        FindingFilters(disposition_state="expired"),
        now=datetime(2026, 8, 3, 12, tzinfo=timezone.utc),
    ) == (finding,)


def test_filter_findings_supports_one_pass_inputs_without_reiteration() -> None:
    findings, dispositions = _filter_fixture()
    finding_input = _FilterSinglePass(findings)
    disposition_input = _FilterSinglePass(dispositions)

    visible = filter_findings(
        finding_input,
        disposition_input,
        FindingFilters(),
        now=FILTER_NOW,
    )

    assert visible == findings
    assert finding_input.iterations == 1
    assert disposition_input.iterations == 1


@pytest.mark.parametrize("target", ("findings", "dispositions"))
def test_filter_findings_normalizes_hostile_iterator_failures(target: str) -> None:
    findings, dispositions = _filter_fixture()
    finding_input: object = _FilterExplodingIterable() if target == "findings" else findings
    disposition_input: object = (
        _FilterExplodingIterable() if target == "dispositions" else dispositions
    )

    _assert_finding_filter_invalid(
        lambda: filter_findings(  # type: ignore[arg-type]
            finding_input,
            disposition_input,
            FindingFilters(),
            now=FILTER_NOW,
        )
    )


@pytest.mark.parametrize("target", ("findings", "dispositions"))
def test_filter_findings_bounds_findings_and_dispositions(target: str) -> None:
    finding = _filter_finding(7, RiskDomain.EXPOSURE, Severity.LOW)
    if target == "findings":
        probe = _FilterOverLimit(lambda _index: finding)
        findings: object = probe
        dispositions: object = ()
    else:
        probe = _FilterOverLimit(
            lambda index: _filter_record(f"{index:064x}", "RULE_7")
        )
        findings = ()
        dispositions = probe

    _assert_finding_filter_invalid(
        lambda: filter_findings(  # type: ignore[arg-type]
            findings,
            dispositions,
            FindingFilters(),
            now=FILTER_NOW,
        )
    )
    assert probe.consumed == 2_001


@pytest.mark.parametrize("target", ("finding", "disposition"))
def test_filter_findings_rejects_item_subclasses(target: str) -> None:
    class FindingSubclass(Finding):
        pass

    class DispositionSubclass(DispositionRecord):
        pass

    findings, dispositions = _filter_fixture()
    finding_input: object = findings
    disposition_input: object = dispositions
    if target == "finding":
        base = findings[0]
        finding_input = (
            FindingSubclass(
                base.rule_id,
                base.domain,
                base.severity,
                base.root_fingerprint,
                base.evidence,
                base.disposition_ref,
            ),
        )
    else:
        base_record = dispositions[0]
        disposition_input = (
            DispositionSubclass(
                base_record.disposition_ref,
                base_record.rule_id,
                base_record.status,
                base_record.reason,
                base_record.reviewer,
                base_record.created_at,
                base_record.expires_at,
            ),
        )

    _assert_finding_filter_invalid(
        lambda: filter_findings(  # type: ignore[arg-type]
            finding_input,
            disposition_input,
            FindingFilters(),
            now=FILTER_NOW,
        )
    )


def test_filter_findings_rejects_forged_mutable_finding_fields() -> None:
    finding = _filter_finding(8, RiskDomain.EXPOSURE, Severity.LOW)
    object.__setattr__(finding, "evidence", list(finding.evidence))

    _assert_finding_filter_invalid(
        lambda: filter_findings((finding,), (), FindingFilters(), now=FILTER_NOW)
    )


@pytest.mark.parametrize(
    "case",
    (
        "evidence_source_path",
        "evidence_fingerprint",
        "evidence_masked_secret",
        "root_fingerprint",
        "rule_type",
        "domain_type",
        "severity_type",
        "evidence_container",
        "evidence_item",
        "disposition_ref",
    ),
)
def test_filter_findings_revalidates_forged_finding_and_evidence_invariants(
    case: str,
) -> None:
    if case == "evidence_source_path":
        finding = _forged_filter_finding(
            evidence=(_forged_filter_evidence(source=FILTER_PRIVATE_MARKER),)
        )
    elif case == "evidence_fingerprint":
        finding = _forged_filter_finding(
            evidence=(_forged_filter_evidence(fingerprint="f" * 63),)
        )
    elif case == "evidence_masked_secret":
        finding = _forged_filter_finding(
            evidence=(_forged_filter_evidence(masked=FILTER_RAW_SECRET),)
        )
    elif case == "root_fingerprint":
        finding = _forged_filter_finding(root_fingerprint="9" * 63)
    elif case == "rule_type":
        finding = _forged_filter_finding(rule_id=["RULE_9"])
    elif case == "domain_type":
        finding = _forged_filter_finding(domain="exposure")
    elif case == "severity_type":
        finding = _forged_filter_finding(severity="low")
    elif case == "evidence_container":
        finding = _forged_filter_finding(evidence=[_forged_filter_evidence()])
    elif case == "evidence_item":
        finding = _forged_filter_finding(evidence=(object(),))
    else:
        finding = _forged_filter_finding(disposition_ref=FILTER_PRIVATE_MARKER)

    _assert_finding_filter_invalid(
        lambda: filter_findings((finding,), (), FindingFilters(), now=FILTER_NOW)
    )
    assert FILTER_PRIVATE_MARKER not in repr(FindingFilters())
    assert FILTER_RAW_SECRET not in repr(FindingFilters())


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("status", "false_positive"),
        ("reason", ["PRIVATE_REASON_MARKER"]),
        ("expires_at", ["2026-08-03T11:00:00Z"]),
    ),
)
def test_filter_findings_rejects_forged_disposition_fields(
    field_name: str, invalid_value: object
) -> None:
    record = _filter_record("e" * 64, "RULE_8")
    object.__setattr__(record, field_name, invalid_value)

    _assert_finding_filter_invalid(
        lambda: filter_findings((), (record,), FindingFilters(), now=FILTER_NOW)
    )


@pytest.mark.parametrize(
    "overrides",
    (
        {"disposition_ref": FILTER_PRIVATE_MARKER},
        {"rule_id": FILTER_PRIVATE_MARKER},
        {"status": "false_positive"},
        {"reason": FILTER_PRIVATE_MARKER},
        {"reviewer": FILTER_PRIVATE_MARKER},
        {"created_at": "2026-13-03T09:00:00Z"},
        {"expires_at": "2026-08-03T99:00:00Z"},
        {"expires_at": "2026-08-03T09:00:00Z"},
        {"expires_at": "2026-08-03T08:59:59Z"},
        {"expires_at": "2027-08-05T09:00:00Z"},
    ),
)
def test_filter_findings_revalidates_forged_disposition_constructor_invariants(
    overrides: dict[str, object],
) -> None:
    record = _forged_filter_record(**overrides)

    _assert_finding_filter_invalid(
        lambda: filter_findings((), (record,), FindingFilters(), now=FILTER_NOW)
    )
    assert FILTER_PRIVATE_MARKER not in repr(FindingFilters())


def test_filter_findings_indexes_original_valid_disposition_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _filter_record("e" * 64, "RULE_8")
    indexed: list[DispositionRecord] = []
    original_index = workflow_module.disposition_index

    def capture_index(records: object) -> dict[str, DispositionRecord]:
        indexed.extend(records)  # type: ignore[arg-type]
        return original_index(indexed)

    monkeypatch.setattr(workflow_module, "disposition_index", capture_index)

    assert filter_findings((), (record,), FindingFilters(), now=FILTER_NOW) == ()
    assert indexed == [record]
    assert indexed[0] is record


@pytest.mark.parametrize(
    "now",
    (
        datetime(2026, 8, 3, 10),
        datetime(2026, 8, 3, 10, tzinfo=timezone(timedelta(hours=1))),
        _FilterDatetimeSubclass(2026, 8, 3, 10, tzinfo=timezone.utc),
        datetime(2026, 8, 3, 10, tzinfo=_FilterHostileTimezone()),
    ),
)
def test_filter_findings_requires_exact_timezone_aware_utc_time(now: datetime) -> None:
    _assert_finding_filter_invalid(
        lambda: filter_findings((), (), FindingFilters(), now=now)
    )


def test_filter_findings_validates_evaluation_time_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings, dispositions = _filter_fixture()
    counting_utc = _FilterCountingUtc()
    now = datetime(2026, 8, 3, 10, tzinfo=counting_utc)
    evaluated_times: list[datetime] = []
    original_evaluate = workflow_module.evaluate_disposition

    def capture_time(
        finding: Finding,
        records: object,
        *,
        now: datetime,
    ) -> object:
        evaluated_times.append(now)
        return original_evaluate(finding, records, now=now)  # type: ignore[arg-type]

    monkeypatch.setattr(workflow_module, "evaluate_disposition", capture_time)

    assert filter_findings(findings, dispositions, FindingFilters(), now=now) == findings
    assert len(evaluated_times) == len(findings)
    validated_time = evaluated_times[0]
    assert validated_time == FILTER_NOW
    assert validated_time.tzinfo is timezone.utc
    assert validated_time is not now
    assert all(value is validated_time for value in evaluated_times)
    assert counting_utc.calls == 1


def test_filter_findings_normalizes_dependency_equality_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings, dispositions = _filter_fixture()
    explosive = ExplosiveEquality(FILTER_PRIVATE_MARKER)

    def fail_evaluation(*_args: object, **_kwargs: object) -> object:
        return explosive == object()

    monkeypatch.setattr(workflow_module, "evaluate_disposition", fail_evaluation)

    _assert_finding_filter_invalid(
        lambda: filter_findings(
            findings,
            dispositions,
            FindingFilters(),
            now=FILTER_NOW,
        )
    )


def test_finding_filter_repr_and_errors_do_not_expose_disposition_details() -> None:
    findings, dispositions = _filter_fixture()
    filters = FindingFilters(disposition_state="false_positive")
    protected = (
        dispositions[0].disposition_ref,
        dispositions[0].reason,
        dispositions[0].reviewer,
        "RAW_MATCH_REVIEW_SECRET",
        FILTER_PRIVATE_MARKER,
    )

    assert filter_findings(findings, dispositions, filters, now=FILTER_NOW) == (
        findings[1],
    )
    for value in protected:
        assert value not in repr(filters)

    _assert_finding_filter_invalid(
        lambda: filter_findings(
            _FilterExplodingIterable(),  # type: ignore[arg-type]
            dispositions,
            filters,
            now=FILTER_NOW,
        )
    )
