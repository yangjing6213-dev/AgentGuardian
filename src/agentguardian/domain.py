from dataclasses import dataclass, field
from enum import Enum
import re


_UNMASKED_SECRET_PATTERNS = (
    re.compile(r"\bsk[-_](?:proj|live|test)?[-_]?[A-Za-z0-9_-]{6,}\b", re.IGNORECASE),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[a-z]-[A-Za-z0-9-]{20,}\b", re.IGNORECASE),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{3,}\b"),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s]+", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_-]?key|password|passwd|token)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_WINDOWS_PATH = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/]")
_UNC_PATH = re.compile(r"\\\\[^\\/\s]+[\\/][^\\/\s]+")
_POSIX_PATH = re.compile(r"(?:^|[\s=\"'(:])/(?!/)\S+")


class RiskDomain(str, Enum):
    EXPOSURE = "exposure"
    PRIVACY = "privacy"
    CREDENTIALS = "credentials"
    PERMISSIONS = "permissions"
    RETENTION = "retention"
    SUPPLY_CHAIN = "supply_chain"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationMode(str, Enum):
    MANUAL = "manual"


class VerificationStatus(str, Enum):
    NOT_PERFORMED = "not_performed"


@dataclass(frozen=True, slots=True)
class Asset:
    asset_id: str
    kind: str
    display_name: str

    def __post_init__(self) -> None:
        if _SHA256_HEX.fullmatch(self.asset_id) is None:
            raise ValueError("asset_id must be a 64-character lowercase HMAC digest")
        _validate_display_name("display_name", self.display_name)


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    fingerprint: str
    masked: str

    def __post_init__(self) -> None:
        if (
            not self.masked
            or len(self.masked) > 80
            or any(pattern.search(self.masked) for pattern in _UNMASKED_SECRET_PATTERNS)
            or _URL.search(self.masked)
            or _looks_like_path(self.masked)
            or _looks_like_seed_phrase(self.masked)
        ):
            raise ValueError("masked evidence contains unsafe content")
        _validate_display_name("source", self.source)
        if _SHA256_HEX.fullmatch(self.fingerprint) is None:
            raise ValueError("fingerprint must be a 64-character lowercase HMAC digest")


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    domain: RiskDomain
    severity: Severity
    root_fingerprint: str
    evidence: tuple[Evidence, ...]
    disposition_ref: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _require_tuple("evidence", self.evidence)
        if _SHA256_HEX.fullmatch(self.root_fingerprint) is None:
            raise ValueError("root_fingerprint must be a 64-character lowercase HMAC digest")
        if (
            self.disposition_ref is not None
            and (
                type(self.disposition_ref) is not str
                or _SHA256_HEX.fullmatch(self.disposition_ref) is None
            )
        ):
            raise ValueError(
                "disposition_ref must be a 64-character lowercase HMAC digest"
            )


@dataclass(frozen=True, slots=True)
class Score:
    total: int
    deductions: tuple[tuple[RiskDomain, int], ...]
    cap_reason: str | None
    coverage: float
    confidence: float
    limits: tuple[str, ...]
    incomplete: bool

    def __post_init__(self) -> None:
        _require_tuple("deductions", self.deductions)
        _require_tuple("limits", self.limits)
        if any(not isinstance(deduction, tuple) for deduction in self.deductions):
            raise TypeError("deductions entries must be tuples")
        if not 0 <= self.total <= 100:
            raise ValueError("total must be between 0 and 100")
        if not 0.0 <= self.coverage <= 1.0:
            raise ValueError("coverage must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if any(amount < 0 for _, amount in self.deductions):
            raise ValueError("deductions cannot be negative")


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    rule_id: str
    asset_ref: str
    mode: RemediationMode
    steps: tuple[str, ...]
    verification_steps: tuple[str, ...]

    def __post_init__(self) -> None:
        if _SHA256_HEX.fullmatch(self.asset_ref) is None:
            raise ValueError("asset_ref must be a 64-character lowercase HMAC digest")
        _require_tuple("steps", self.steps)
        _require_tuple("verification_steps", self.verification_steps)
        if self.mode is not RemediationMode.MANUAL:
            raise ValueError("Founder Alpha remediation must be manual")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: VerificationStatus
    notes: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_tuple("notes", self.notes)
        if self.status is not VerificationStatus.NOT_PERFORMED:
            raise ValueError("Founder Alpha verification is not performed")


def _looks_like_path(value: str) -> bool:
    return any(pattern.search(value) for pattern in (_WINDOWS_PATH, _UNC_PATH, _POSIX_PATH))


def _looks_like_seed_phrase(value: str) -> bool:
    words = value.split()
    return (
        len(words) in {12, 15, 18, 21, 24}
        and len(set(words)) >= 8
        and all(word.isascii() and word.isalpha() and word.islower() for word in words)
    )


def validate_safe_annotation(name: str, value: object, max_length: int) -> str:
    if type(value) is not str or type(max_length) is not int or max_length < 1:
        raise ValueError(f"{name} contains unsafe content")
    trimmed = value.strip()
    if (
        not trimmed
        or len(trimmed) > max_length
        or any(not character.isprintable() for character in trimmed)
        or any(pattern.search(trimmed) for pattern in _UNMASKED_SECRET_PATTERNS)
        or _URL.search(trimmed)
        or _looks_like_path(trimmed)
        or _looks_like_seed_phrase(trimmed)
    ):
        raise ValueError(f"{name} contains unsafe content")
    return trimmed


def _require_tuple(name: str, value: object) -> None:
    if not isinstance(value, tuple):
        raise TypeError(f"{name} must be a tuple")


def _validate_display_name(name: str, value: str) -> None:
    if (
        not value
        or len(value) > 80
        or any(separator in value for separator in ("/", "\\", ":"))
        or any(not character.isprintable() for character in value)
    ):
        raise ValueError(f"{name} must be a short display name, not a path")
