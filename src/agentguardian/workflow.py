from dataclasses import dataclass, field
from enum import Enum
from math import isfinite
import ntpath
import os
from pathlib import Path, PureWindowsPath
from types import MappingProxyType

from .domain import RiskDomain, Score


SCOPE_PREVIEW_CONTRACT_VERSION = 1
_PATH_TYPE = type(Path())
_COVERAGE_ERROR = "COVERAGE_INVALID"
_WINDOWS_RESERVED_DEVICE_NAMES = frozenset(
    {"con", "nul", "prn", "aux", "conin$", "conout$"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)


class CoverageState(str, Enum):
    COMPLETE = "complete"
    LIMITED = "limited"
    NO_SUPPORTED_FILES = "no_supported_files"


COVERAGE_STATE_LABELS = MappingProxyType(
    {
        CoverageState.COMPLETE: "已完成",
        CoverageState.LIMITED: "覆盖受限",
        CoverageState.NO_SUPPORTED_FILES: "无支持文件",
    }
)
COVERAGE_LIMIT_LABELS = MappingProxyType(
    {
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
)


@dataclass(frozen=True, slots=True)
class ScopePreview:
    root_count: int
    root_names: tuple[str, ...]
    selectors: tuple[str, ...]
    max_files: int
    max_entries: int
    max_bytes: int
    max_findings: int
    max_evidence: int
    contract_version: int
    local_only: bool
    read_only: bool
    manual_guidance_only: bool
    unc_roots_excluded: bool
    drive_roots_excluded: bool
    reparse_paths_excluded: bool
    _roots: tuple[Path, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _validate_scope_preview(self)


@dataclass(frozen=True, slots=True)
class ScopeConsent:
    contract_version: int
    _root_identity: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _validate_scope_consent(self)


def build_scope_preview(
    roots: tuple[Path, ...],
    selectors: tuple[str, ...],
    *,
    max_files: int,
    max_entries: int,
    max_bytes: int,
    max_findings: int,
    max_evidence: int,
) -> ScopePreview:
    normalized_roots, root_names = _validated_roots(roots)
    validated_selectors = _validated_selectors(selectors)
    caps = (
        _positive_int("max_files", max_files),
        _positive_int("max_entries", max_entries),
        _positive_int("max_bytes", max_bytes),
        _positive_int("max_findings", max_findings),
        _positive_int("max_evidence", max_evidence),
    )
    if len(set(normalized_roots)) != len(normalized_roots):
        raise ValueError("roots must be unique")
    return ScopePreview(
        root_count=len(roots),
        root_names=root_names,
        selectors=validated_selectors,
        max_files=caps[0],
        max_entries=caps[1],
        max_bytes=caps[2],
        max_findings=caps[3],
        max_evidence=caps[4],
        contract_version=SCOPE_PREVIEW_CONTRACT_VERSION,
        local_only=True,
        read_only=True,
        manual_guidance_only=True,
        unc_roots_excluded=True,
        drive_roots_excluded=True,
        reparse_paths_excluded=True,
        _roots=roots,
    )


def bind_scope_consent(preview: ScopePreview) -> ScopeConsent:
    _validate_scope_preview(preview)
    root_identity, _ = _validated_roots(preview._roots)
    return ScopeConsent(preview.contract_version, root_identity)


def scope_consent_matches(consent: object, preview: object) -> bool:
    try:
        _validate_scope_consent(consent)
        _validate_scope_preview(preview)
        root_identity, _ = _validated_roots(preview._roots)
        return (
            consent.contract_version == preview.contract_version
            and consent._root_identity == root_identity
        )
    except Exception:
        return False


def classify_coverage(score: Score) -> CoverageState:
    try:
        return _classify_validated_coverage(score)
    except Exception:
        pass
    raise ValueError(_COVERAGE_ERROR) from None


def _classify_validated_coverage(score: Score) -> CoverageState:
    if type(score) is not Score:
        raise ValueError(_COVERAGE_ERROR)
    if type(score.total) is not int or not 0 <= score.total <= 100:
        raise ValueError(_COVERAGE_ERROR)
    if type(score.deductions) is not tuple:
        raise ValueError(_COVERAGE_ERROR)
    for deduction in score.deductions:
        if type(deduction) is not tuple or len(deduction) != 2:
            raise ValueError(_COVERAGE_ERROR)
        domain, amount = deduction
        if type(domain) is not RiskDomain or type(amount) is not int or amount < 0:
            raise ValueError(_COVERAGE_ERROR)
    if score.cap_reason is not None and type(score.cap_reason) is not str:
        raise ValueError(_COVERAGE_ERROR)
    for ratio in (score.coverage, score.confidence):
        if (
            type(ratio) not in (int, float)
            or not isfinite(ratio)
            or not 0 <= ratio <= 1
        ):
            raise ValueError(_COVERAGE_ERROR)
    if type(score.limits) is not tuple:
        raise ValueError(_COVERAGE_ERROR)
    if any(
        type(limit) is not str or limit not in COVERAGE_LIMIT_LABELS
        for limit in score.limits
    ) or len(set(score.limits)) != len(score.limits):
        raise ValueError(_COVERAGE_ERROR)
    if type(score.incomplete) is not bool:
        raise ValueError(_COVERAGE_ERROR)

    if not score.incomplete:
        if score.coverage != 1 or score.limits:
            raise ValueError(_COVERAGE_ERROR)
        return CoverageState.COMPLETE
    if "no_supported_files" in score.limits:
        if score.coverage != 0 or score.limits != ("no_supported_files",):
            raise ValueError(_COVERAGE_ERROR)
        return CoverageState.NO_SUPPORTED_FILES
    if score.coverage == 1 and not score.limits:
        raise ValueError(_COVERAGE_ERROR)
    return CoverageState.LIMITED


def _validate_scope_preview(preview: ScopePreview) -> None:
    if type(preview) is not ScopePreview:
        raise TypeError("preview must be an exact ScopePreview")
    normalized_roots, root_names = _validated_roots(preview._roots)
    if (
        type(preview.root_count) is not int
        or preview.root_count != len(preview._roots)
        or type(preview.root_names) is not tuple
        or any(type(name) is not str for name in preview.root_names)
        or preview.root_names != root_names
        or preview.selectors != _validated_selectors(preview.selectors)
        or len(set(normalized_roots)) != len(normalized_roots)
        or type(preview.contract_version) is not int
        or preview.contract_version != SCOPE_PREVIEW_CONTRACT_VERSION
        or any(
            value is not True
            for value in (
                preview.local_only,
                preview.read_only,
                preview.manual_guidance_only,
                preview.unc_roots_excluded,
                preview.drive_roots_excluded,
                preview.reparse_paths_excluded,
            )
        )
    ):
        raise ValueError("invalid scope preview")
    for name in (
        "max_files",
        "max_entries",
        "max_bytes",
        "max_findings",
        "max_evidence",
    ):
        _positive_int(name, getattr(preview, name))


def _validate_scope_consent(consent: object) -> None:
    if type(consent) is not ScopeConsent:
        raise TypeError("consent must be an exact ScopeConsent")
    if (
        type(consent.contract_version) is not int
        or consent.contract_version != SCOPE_PREVIEW_CONTRACT_VERSION
        or type(consent._root_identity) is not tuple
        or not consent._root_identity
        or any(type(root) is not str or not root for root in consent._root_identity)
        or len(set(consent._root_identity)) != len(consent._root_identity)
    ):
        raise ValueError("invalid scope consent")


def _validated_roots(roots: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if type(roots) is not tuple or not roots:
        raise TypeError("roots must be a non-empty tuple")
    normalized: list[str] = []
    names: list[str] = []
    for root in roots:
        if type(root) is not _PATH_TYPE:
            raise TypeError("roots must contain exact Path values")
        windows_path = PureWindowsPath(os.fspath(root))
        if windows_path.drive.startswith("\\\\"):
            raise ValueError("UNC roots are not allowed")
        if not windows_path.is_absolute() or not windows_path.drive:
            raise ValueError("roots must be absolute drive-qualified paths")
        if windows_path.root and windows_path == PureWindowsPath(windows_path.anchor):
            raise ValueError("Windows root paths are not allowed")
        _validate_windows_path_components(windows_path)
        name = windows_path.name
        _validate_short_name(name)
        normalized.append(
            ntpath.normcase(ntpath.normpath(os.fspath(root)))
        )
        names.append(name)
    return tuple(normalized), tuple(names)


def _validated_selectors(selectors: object) -> tuple[str, ...]:
    if type(selectors) is not tuple or not selectors:
        raise TypeError("selectors must be a non-empty tuple")
    for selector in selectors:
        if type(selector) is not str:
            raise TypeError("selectors must contain exact strings")
        _validate_short_name(selector)
    if len({selector.casefold() for selector in selectors}) != len(selectors):
        raise ValueError("selectors must be unique")
    return selectors


def _validate_short_name(value: str) -> None:
    if len(value) > 80 or _is_unsafe_windows_component(value):
        raise ValueError("unsafe short name")


def _validate_windows_path_components(path: PureWindowsPath) -> None:
    if any(_is_unsafe_windows_component(component) for component in path.parts[1:]):
        raise ValueError("unsafe Windows path component")


def _is_unsafe_windows_component(value: str) -> bool:
    device_name = value.partition(".")[0].rstrip(" .").casefold()
    return (
        not value
        or value.endswith((" ", "."))
        or any(character in value for character in '/\\:*?"<>|')
        or any(not character.isprintable() for character in value)
        or device_name in _WINDOWS_RESERVED_DEVICE_NAMES
    )


def _positive_int(name: str, value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value
