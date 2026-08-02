from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import hmac
import ntpath
import re
import unicodedata

from .domain import Finding, validate_safe_annotation


_HEX = re.compile(r"[0-9a-f]{64}")
_RULE_ID = re.compile(r"[A-Z][A-Z0-9_]{0,79}")
_UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_ERROR = "DISPOSITION_INVALID"


class DispositionStatus(str, Enum):
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass(frozen=True, slots=True)
class DispositionRecord:
    disposition_ref: str = field(repr=False)
    rule_id: str
    status: DispositionStatus
    reason: str
    reviewer: str
    created_at: str
    expires_at: str

    def __post_init__(self) -> None:
        try:
            created = parse_utc(self.created_at)
            expires = parse_utc(self.expires_at)
            if (
                not isinstance(self.disposition_ref, str)
                or _HEX.fullmatch(self.disposition_ref) is None
                or not isinstance(self.rule_id, str)
                or _RULE_ID.fullmatch(self.rule_id) is None
                or not isinstance(self.status, DispositionStatus)
                or not created < expires
                or expires - created > timedelta(days=366)
            ):
                raise ValueError
            object.__setattr__(
                self, "reason", validate_safe_annotation("reason", self.reason, 240)
            )
            object.__setattr__(
                self,
                "reviewer",
                validate_safe_annotation("reviewer", self.reviewer, 80),
            )
        except (TypeError, ValueError, OverflowError):
            raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True)
class DispositionEvaluation:
    state: str
    record: DispositionRecord | None


def parse_utc(value: object) -> datetime:
    if type(value) is not str or _UTC_SECONDS.fullmatch(value) is None:
        raise ValueError(_ERROR)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise ValueError(_ERROR) from None


def make_disposition_ref(
    key: bytes,
    *,
    rule_id: str,
    source: str,
    raw_match: str,
) -> str:
    try:
        if (
            type(key) is not bytes
            or len(key) != 32
            or not isinstance(rule_id, str)
            or _RULE_ID.fullmatch(rule_id) is None
            or type(source) is not str
            or not source
            or type(raw_match) is not str
            or not raw_match
        ):
            raise ValueError
        path = unicodedata.normalize(
            "NFKC",
            ntpath.normcase(ntpath.normpath(ntpath.abspath(source))),
        )
        raw = unicodedata.normalize("NFKC", raw_match)
        parts = (rule_id.encode("utf-8"), path.encode("utf-8"), raw.encode("utf-8"))
        message = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
        return hmac.digest(key, message, "sha256").hex()
    except (TypeError, ValueError, OSError, OverflowError, UnicodeError):
        raise ValueError(_ERROR) from None


def disposition_index(
    records: Iterable[DispositionRecord],
) -> dict[str, DispositionRecord]:
    try:
        index: dict[str, DispositionRecord] = {}
        for record in records:
            if (
                not isinstance(record, DispositionRecord)
                or record.disposition_ref in index
            ):
                raise ValueError
            index[record.disposition_ref] = record
        return dict(sorted(index.items()))
    except (TypeError, ValueError):
        raise ValueError(_ERROR) from None


def evaluate_disposition(
    finding: Finding,
    records: Mapping[str, DispositionRecord],
    *,
    now: datetime,
) -> DispositionEvaluation:
    _validate_now(now)
    if not isinstance(finding, Finding) or not isinstance(records, Mapping):
        raise ValueError(_ERROR)
    reference = finding.disposition_ref
    record = records.get(reference) if reference is not None else None
    if (
        not isinstance(record, DispositionRecord)
        or record.disposition_ref != reference
        or record.rule_id != finding.rule_id
    ):
        return DispositionEvaluation("open", None)
    created = parse_utc(record.created_at)
    expires = parse_utc(record.expires_at)
    if now < created:
        return DispositionEvaluation("open", None)
    if now >= expires:
        return DispositionEvaluation("expired", record)
    return DispositionEvaluation(record.status.value, record)


def reviewed_findings(
    findings: Iterable[Finding],
    records: Mapping[str, DispositionRecord],
    *,
    now: datetime,
) -> tuple[Finding, ...]:
    _validate_now(now)
    try:
        return tuple(
            finding
            for finding in findings
            if evaluate_disposition(finding, records, now=now).state
            != DispositionStatus.FALSE_POSITIVE.value
        )
    except TypeError:
        raise ValueError(_ERROR) from None


def upsert_disposition(
    records: Iterable[DispositionRecord], record: DispositionRecord
) -> tuple[DispositionRecord, ...]:
    if not isinstance(record, DispositionRecord):
        raise ValueError(_ERROR)
    index = disposition_index(records)
    index[record.disposition_ref] = record
    return tuple(index[reference] for reference in sorted(index))


def withdraw_disposition(
    records: Iterable[DispositionRecord], disposition_ref: str
) -> tuple[DispositionRecord, ...]:
    if (
        not isinstance(disposition_ref, str)
        or _HEX.fullmatch(disposition_ref) is None
    ):
        raise ValueError(_ERROR)
    index = disposition_index(records)
    index.pop(disposition_ref, None)
    return tuple(index[reference] for reference in sorted(index))


def _validate_now(now: datetime) -> None:
    try:
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() != timedelta(0)
        ):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise ValueError(_ERROR) from None
