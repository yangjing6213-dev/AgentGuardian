from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
import re

from . import __version__
from .dispositions import (
    DispositionRecord,
    DispositionStatus,
    disposition_index,
)
from .domain import Evidence, Finding, Score


SCHEMA_VERSION = 2
MAX_STATE_BYTES = 1024 * 1024
MAX_STATE_FINDINGS = 2000
MAX_STATE_EVIDENCE = 4000

_ERROR = "PROTECTED_STATE_INVALID"
_HMAC = re.compile(r"[0-9a-f]{64}")
_RULE_ID = re.compile(r"[A-Z][A-Z0-9_]{0,79}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")
_LIMIT = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CAPTURED_AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_PERSISTED_SUMMARIES = {
    "CN_MOBILE_PHONE": "Chinese mobile phone number detected",
    "CUSTOM_KEYWORD": "Custom keyword detected",
    "EMAIL_ADDRESS": "Email address detected",
    "GENERIC_API_KEY": "Generic API credential detected",
    "MCP_DANGEROUS_COMBINATION": "shell + filesystem write + network",
    "OPENAI_API_KEY": "OpenAI API key detected",
    "OPENAI_BASE_URL_OVERRIDE": "OpenAI API base URL override configured",
}


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
        summary = _persistence_summary(self.rule_id)
        if (
            not isinstance(self.rule_id, str)
            or _RULE_ID.fullmatch(self.rule_id) is None
            or not _is_hmac(self.root_hmac_fingerprint)
            or not isinstance(self.evidence, tuple)
            or len(self.evidence) > MAX_STATE_EVIDENCE
            or any(not isinstance(item, EvidenceReference) for item in self.evidence)
            or any(item.masked != summary for item in self.evidence)
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
    disposition_key: bytes | None = field(default=None, repr=False)
    dispositions: tuple[DispositionRecord, ...] = ()

    def __post_init__(self) -> None:
        try:
            if (
                type(self.schema_version) is not int
                or self.schema_version not in {1, SCHEMA_VERSION}
                or not _is_captured_at(self.captured_at)
                or not _is_version(self.product_version)
                or not _is_version(self.rule_version)
                or not isinstance(self.scan, ScanMetadata)
                or not isinstance(self.findings, tuple)
                or len(self.findings) > MAX_STATE_FINDINGS
                or any(
                    not isinstance(item, FindingReference)
                    for item in self.findings
                )
                or tuple(sorted(self.findings, key=_finding_key)) != self.findings
                or sum(len(item.evidence) for item in self.findings)
                > MAX_STATE_EVIDENCE
                or type(self.dispositions) is not tuple
            ):
                raise _invalid()
            if self.schema_version == 1:
                if self.disposition_key is not None or self.dispositions != ():
                    raise _invalid()
                return
            if (
                type(self.disposition_key) is not bytes
                or len(self.disposition_key) != 32
                or len(self.dispositions) > MAX_STATE_FINDINGS
                or tuple(disposition_index(self.dispositions).values())
                != self.dispositions
            ):
                raise _invalid()
        except EvidenceStateError:
            raise
        except Exception:
            raise _invalid() from None


def build_snapshot(
    findings: Iterable[Finding],
    score: Score,
    *,
    rule_version: str,
    captured_at: datetime,
    disposition_key: bytes,
    dispositions: Iterable[DispositionRecord],
) -> EvidenceSnapshot:
    try:
        if (
            not isinstance(score, Score)
            or not isinstance(captured_at, datetime)
            or type(disposition_key) is not bytes
            or len(disposition_key) != 32
        ):
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
        records = tuple(disposition_index(dispositions).values())
        if len(records) > MAX_STATE_FINDINGS:
            raise _invalid()
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
            disposition_key=disposition_key,
            dispositions=records,
        )
        if len(encode_snapshot(snapshot)) > MAX_STATE_BYTES:
            raise _invalid()
        return snapshot
    except EvidenceStateError:
        raise
    except Exception:
        raise _invalid() from None


def encode_snapshot(snapshot: EvidenceSnapshot) -> bytes:
    try:
        if (
            not isinstance(snapshot, EvidenceSnapshot)
            or snapshot.schema_version != SCHEMA_VERSION
        ):
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
    except Exception:
        raise _invalid() from None


def decode_snapshot(data: bytes) -> EvidenceSnapshot:
    try:
        if type(data) is not bytes or not data or len(data) > MAX_STATE_BYTES:
            raise _invalid()
        payload = json.loads(
            data.decode("utf-8"),
            parse_constant=lambda _: _raise_invalid(),
            object_pairs_hook=_strict_object,
        )
        if type(payload) is not dict:
            raise _invalid()
        schema_version = _integer(payload["schema_version"])
        if schema_version == 1:
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
            disposition_key = None
            dispositions: tuple[DispositionRecord, ...] = ()
        elif schema_version == SCHEMA_VERSION:
            root = _exact_object(
                payload,
                {
                    "schema_version",
                    "captured_at",
                    "product_version",
                    "rule_version",
                    "scan",
                    "findings",
                    "disposition_hmac_key",
                    "dispositions",
                },
            )
            key_text = _string(root["disposition_hmac_key"])
            if not _is_hmac(key_text):
                raise _invalid()
            disposition_key = bytes.fromhex(key_text)
            disposition_data = _list(root["dispositions"])
            if len(disposition_data) > MAX_STATE_FINDINGS:
                raise _invalid()
            parsed_dispositions: list[DispositionRecord] = []
            for item in disposition_data:
                record = _exact_object(
                    item,
                    {
                        "disposition_ref",
                        "rule_id",
                        "status",
                        "reason",
                        "reviewer",
                        "created_at",
                        "expires_at",
                    },
                )
                parsed_dispositions.append(
                    DispositionRecord(
                        disposition_ref=_string(record["disposition_ref"]),
                        rule_id=_string(record["rule_id"]),
                        status=DispositionStatus(_string(record["status"])),
                        reason=_string(record["reason"]),
                        reviewer=_string(record["reviewer"]),
                        created_at=_string(record["created_at"]),
                        expires_at=_string(record["expires_at"]),
                    )
                )
            dispositions = tuple(parsed_dispositions)
        else:
            raise _invalid()
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
            schema_version=schema_version,
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
            disposition_key=disposition_key,
            dispositions=dispositions,
        )
    except EvidenceStateError:
        raise
    except Exception:
        raise _invalid() from None


def _finding_reference(finding: Finding) -> FindingReference:
    if not isinstance(finding, Finding):
        raise _invalid()
    summary = _persistence_summary(finding.rule_id)
    evidence = tuple(
        sorted(
            (
                EvidenceReference(
                    hmac_fingerprint=item.fingerprint,
                    masked=summary,
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
        "disposition_hmac_key": snapshot.disposition_key.hex(),
        "dispositions": [
            {
                "disposition_ref": record.disposition_ref,
                "rule_id": record.rule_id,
                "status": record.status.value,
                "reason": record.reason,
                "reviewer": record.reviewer,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
            }
            for record in snapshot.dispositions
        ],
    }


def _exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise _invalid()
    return value


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


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


def _persistence_summary(rule_id: object) -> str:
    if not isinstance(rule_id, str) or rule_id not in _PERSISTED_SUMMARIES:
        raise _invalid()
    return _PERSISTED_SUMMARIES[rule_id]


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
