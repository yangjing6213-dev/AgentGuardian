from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import re

from . import __version__
from .domain import Evidence, Finding, Score


SCHEMA_VERSION = 1
MAX_STATE_BYTES = 1024 * 1024
MAX_STATE_FINDINGS = 2000
MAX_STATE_EVIDENCE = 4000

_ERROR = "PROTECTED_STATE_INVALID"
_HMAC = re.compile(r"[0-9a-f]{64}")
_RULE_ID = re.compile(r"[A-Z][A-Z0-9_]{0,79}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")
_LIMIT = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CAPTURED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class EvidenceStateError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    hmac_fingerprint: str
    masked: str

    def __post_init__(self) -> None:
        if not _is_hmac(self.hmac_fingerprint):
            raise _invalid()
        try:
            Evidence("protected-state", self.hmac_fingerprint, self.masked)
        except (TypeError, ValueError):
            raise _invalid() from None


@dataclass(frozen=True, slots=True)
class FindingReference:
    rule_id: str
    root_hmac_fingerprint: str
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.rule_id, str)
            or _RULE_ID.fullmatch(self.rule_id) is None
            or not _is_hmac(self.root_hmac_fingerprint)
            or not isinstance(self.evidence, tuple)
            or len(self.evidence) > MAX_STATE_EVIDENCE
            or any(not isinstance(item, EvidenceReference) for item in self.evidence)
            or tuple(sorted(self.evidence, key=_evidence_key)) != self.evidence
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ScanMetadata:
    coverage: float
    confidence: float
    incomplete: bool
    limits: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not _is_unit_number(self.coverage)
            or not _is_unit_number(self.confidence)
            or type(self.incomplete) is not bool
            or not isinstance(self.limits, tuple)
            or any(
                not isinstance(limit, str) or _LIMIT.fullmatch(limit) is None
                for limit in self.limits
            )
            or tuple(sorted(set(self.limits))) != self.limits
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    schema_version: int
    captured_at: str
    product_version: str
    rule_version: str
    scan: ScanMetadata
    findings: tuple[FindingReference, ...]

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
            or not _is_captured_at(self.captured_at)
            or not _is_version(self.product_version)
            or not _is_version(self.rule_version)
            or not isinstance(self.scan, ScanMetadata)
            or not isinstance(self.findings, tuple)
            or len(self.findings) > MAX_STATE_FINDINGS
            or any(not isinstance(item, FindingReference) for item in self.findings)
            or tuple(sorted(self.findings, key=_finding_key)) != self.findings
            or sum(len(item.evidence) for item in self.findings) > MAX_STATE_EVIDENCE
        ):
            raise _invalid()


def build_snapshot(
    findings: Iterable[Finding],
    score: Score,
    *,
    rule_version: str,
    captured_at: datetime,
) -> EvidenceSnapshot:
    try:
        if not isinstance(score, Score) or not isinstance(captured_at, datetime):
            raise _invalid()
        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise _invalid()
        timestamp = (
            captured_at.astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        references = tuple(
            sorted((_finding_reference(item) for item in findings), key=_finding_key)
        )
        snapshot = EvidenceSnapshot(
            schema_version=SCHEMA_VERSION,
            captured_at=timestamp,
            product_version=__version__,
            rule_version=rule_version,
            scan=ScanMetadata(
                coverage=float(score.coverage),
                confidence=float(score.confidence),
                incomplete=score.incomplete,
                limits=tuple(sorted(set(score.limits))),
            ),
            findings=references,
        )
        if len(encode_snapshot(snapshot)) > MAX_STATE_BYTES:
            raise _invalid()
        return snapshot
    except EvidenceStateError:
        raise
    except (TypeError, ValueError, OverflowError):
        raise _invalid() from None


def encode_snapshot(snapshot: EvidenceSnapshot) -> bytes:
    try:
        if not isinstance(snapshot, EvidenceSnapshot):
            raise _invalid()
        encoded = json.dumps(
            _snapshot_data(snapshot),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if not encoded or len(encoded) > MAX_STATE_BYTES:
            raise _invalid()
        return encoded
    except EvidenceStateError:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError):
        raise _invalid() from None


def decode_snapshot(data: bytes) -> EvidenceSnapshot:
    try:
        if type(data) is not bytes or not data or len(data) > MAX_STATE_BYTES:
            raise _invalid()
        payload = json.loads(
            data.decode("utf-8"),
            parse_constant=lambda _: _raise_invalid(),
        )
        root = _exact_object(
            payload,
            {
                "schema_version",
                "captured_at",
                "product_version",
                "rule_version",
                "scan",
                "findings",
            },
        )
        scan_data = _exact_object(
            root["scan"],
            {"coverage", "confidence", "incomplete", "limits"},
        )
        limits_data = _list(scan_data["limits"])
        finding_data = _list(root["findings"])
        if len(finding_data) > MAX_STATE_FINDINGS:
            raise _invalid()

        references: list[FindingReference] = []
        evidence_count = 0
        for item in finding_data:
            finding = _exact_object(
                item,
                {"rule_id", "root_hmac_fingerprint", "evidence"},
            )
            evidence_data = _list(finding["evidence"])
            evidence_count += len(evidence_data)
            if evidence_count > MAX_STATE_EVIDENCE:
                raise _invalid()
            evidence = tuple(
                EvidenceReference(
                    hmac_fingerprint=_string(
                        _exact_object(
                            entry, {"hmac_fingerprint", "masked"}
                        )["hmac_fingerprint"]
                    ),
                    masked=_string(
                        _exact_object(entry, {"hmac_fingerprint", "masked"})[
                            "masked"
                        ]
                    ),
                )
                for entry in evidence_data
            )
            references.append(
                FindingReference(
                    rule_id=_string(finding["rule_id"]),
                    root_hmac_fingerprint=_string(
                        finding["root_hmac_fingerprint"]
                    ),
                    evidence=evidence,
                )
            )

        return EvidenceSnapshot(
            schema_version=_integer(root["schema_version"]),
            captured_at=_string(root["captured_at"]),
            product_version=_string(root["product_version"]),
            rule_version=_string(root["rule_version"]),
            scan=ScanMetadata(
                coverage=_number(scan_data["coverage"]),
                confidence=_number(scan_data["confidence"]),
                incomplete=_boolean(scan_data["incomplete"]),
                limits=tuple(_string(limit) for limit in limits_data),
            ),
            findings=tuple(references),
        )
    except EvidenceStateError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
        raise _invalid() from None


def _finding_reference(finding: Finding) -> FindingReference:
    if not isinstance(finding, Finding):
        raise _invalid()
    evidence = tuple(
        sorted(
            (
                EvidenceReference(
                    hmac_fingerprint=item.fingerprint,
                    masked=item.masked,
                )
                for item in finding.evidence
            ),
            key=_evidence_key,
        )
    )
    return FindingReference(
        rule_id=finding.rule_id,
        root_hmac_fingerprint=finding.root_fingerprint,
        evidence=evidence,
    )


def _snapshot_data(snapshot: EvidenceSnapshot) -> dict[str, object]:
    return {
        "schema_version": snapshot.schema_version,
        "captured_at": snapshot.captured_at,
        "product_version": snapshot.product_version,
        "rule_version": snapshot.rule_version,
        "scan": {
            "coverage": snapshot.scan.coverage,
            "confidence": snapshot.scan.confidence,
            "incomplete": snapshot.scan.incomplete,
            "limits": list(snapshot.scan.limits),
        },
        "findings": [
            {
                "rule_id": finding.rule_id,
                "root_hmac_fingerprint": finding.root_hmac_fingerprint,
                "evidence": [
                    {
                        "hmac_fingerprint": item.hmac_fingerprint,
                        "masked": item.masked,
                    }
                    for item in finding.evidence
                ],
            }
            for finding in snapshot.findings
        ],
    }


def _exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise _invalid()
    return value


def _list(value: object) -> list[object]:
    if type(value) is not list:
        raise _invalid()
    return value


def _string(value: object) -> str:
    if type(value) is not str:
        raise _invalid()
    return value


def _integer(value: object) -> int:
    if type(value) is not int:
        raise _invalid()
    return value


def _number(value: object) -> float:
    if type(value) not in {int, float}:
        raise _invalid()
    return float(value)


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise _invalid()
    return value


def _is_hmac(value: object) -> bool:
    return isinstance(value, str) and _HMAC.fullmatch(value) is not None


def _is_version(value: object) -> bool:
    return isinstance(value, str) and _VERSION.fullmatch(value) is not None


def _is_captured_at(value: object) -> bool:
    if not isinstance(value, str) or _CAPTURED_AT.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _is_unit_number(value: object) -> bool:
    return (
        type(value) in {int, float}
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def _evidence_key(item: EvidenceReference) -> tuple[str, str]:
    return item.hmac_fingerprint, item.masked


def _finding_key(
    item: FindingReference,
) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    return (
        item.rule_id,
        item.root_hmac_fingerprint,
        tuple(_evidence_key(evidence) for evidence in item.evidence),
    )


def _raise_invalid() -> None:
    raise _invalid()


def _invalid() -> EvidenceStateError:
    return EvidenceStateError(_ERROR)
