from dataclasses import FrozenInstanceError
import ntpath
import os
from pathlib import Path

import pytest

import agentguardian.workflow as workflow_module
from agentguardian.domain import RiskDomain, Score
from agentguardian.workflow import (
    COVERAGE_LIMIT_LABELS,
    COVERAGE_STATE_LABELS,
    CoverageState,
    ScopeConsent,
    ScopePreview,
    bind_scope_consent,
    build_scope_preview,
    classify_coverage,
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
