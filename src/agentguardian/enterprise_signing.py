"""Optional Ed25519 signatures for enterprise policy envelopes.

The desktop does not load this module on its default local audit path. The
cryptography dependency is optional and the verifier fails closed when it is
not installed or when a signed envelope is malformed.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Protocol

from .enterprise_policy import parse_enterprise_policy


MAX_SIGNED_POLICY_BYTES = 128 * 1024
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_SIGNED_KEYS = frozenset({"schema", "algorithm", "key_id", "policy", "signature"})
_SIGNATURE_BYTES = 64


class PolicySigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...


class PolicyVerifier(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class Ed25519PolicySigner:
    def __init__(self, private_key_bytes: bytes) -> None:
        if type(private_key_bytes) is not bytes or len(private_key_bytes) != 32:
            raise ValueError("POLICY_PRIVATE_KEY_INVALID")
        self._private_key_bytes = private_key_bytes

    def sign(self, payload: bytes) -> bytes:
        if type(payload) is not bytes:
            raise ValueError("POLICY_SIGNING_PAYLOAD_INVALID")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            key = Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)
            signature = key.sign(payload)
        except ImportError:
            raise ValueError("ENTERPRISE_CRYPTO_UNAVAILABLE") from None
        except Exception:
            raise ValueError("POLICY_SIGNING_FAILED") from None
        if len(signature) != _SIGNATURE_BYTES:
            raise ValueError("POLICY_SIGNING_FAILED")
        return signature


class Ed25519PolicyVerifier:
    def __init__(self, public_key_bytes: bytes) -> None:
        if type(public_key_bytes) is not bytes or len(public_key_bytes) != 32:
            raise ValueError("POLICY_PUBLIC_KEY_INVALID")
        self._public_key_bytes = public_key_bytes

    def verify(self, payload: bytes, signature: bytes) -> bool:
        if type(payload) is not bytes or type(signature) is not bytes:
            return False
        if len(signature) != _SIGNATURE_BYTES:
            return False
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            key = Ed25519PublicKey.from_public_bytes(self._public_key_bytes)
            key.verify(signature, payload)
        except Exception:
            return False
        return True


def create_signed_policy(
    policy_document: bytes,
    *,
    key_id: str,
    signer: PolicySigner,
) -> bytes:
    canonical_policy = _canonical_policy(policy_document)
    key_id = _key_id(key_id)
    unsigned = _unsigned_envelope(canonical_policy, key_id)
    payload = _canonical_json(unsigned)
    try:
        signature = signer.sign(payload)
    except ValueError:
        raise
    except Exception:
        raise ValueError("POLICY_SIGNING_FAILED") from None
    if type(signature) is not bytes or len(signature) != _SIGNATURE_BYTES:
        raise ValueError("POLICY_SIGNATURE_INVALID")
    envelope = dict(unsigned)
    envelope["signature"] = _encode_signature(signature)
    return _canonical_json(envelope)


def verify_signed_policy(
    signed_document: bytes,
    verifier: PolicyVerifier,
) -> bytes:
    if type(signed_document) is not bytes or not signed_document or len(signed_document) > MAX_SIGNED_POLICY_BYTES:
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
    try:
        envelope = json.loads(
            signed_document.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID") from None
    if not isinstance(envelope, dict) or set(envelope) != _SIGNED_KEYS:
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
    if envelope.get("schema") != 1 or envelope.get("algorithm") != "Ed25519":
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
    key_id = _key_id(envelope.get("key_id"))
    policy_value = envelope.get("policy")
    if not isinstance(policy_value, dict):
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
    canonical_policy = _canonical_policy(_canonical_json(policy_value))
    signature = _decode_signature(envelope.get("signature"))
    payload = _canonical_json(_unsigned_envelope(canonical_policy, key_id))
    try:
        verified = verifier.verify(payload, signature)
    except Exception:
        verified = False
    if verified is not True:
        raise ValueError("POLICY_SIGNATURE_INVALID")
    return canonical_policy


def _canonical_policy(document: bytes) -> bytes:
    try:
        return parse_enterprise_policy(document).canonical_bytes
    except (TypeError, ValueError):
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID") from None


def _unsigned_envelope(policy_document: bytes, key_id: str) -> dict[str, object]:
    return {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "policy": json.loads(policy_document.decode("utf-8")),
        "schema": 1,
    }


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID") from None


def _key_id(value: object) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        raise ValueError("POLICY_KEY_ID_INVALID")
    return value


def _encode_signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_signature(value: object) -> bytes:
    if type(value) is not str or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, base64.binascii.Error):
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID") from None
    if len(decoded) != _SIGNATURE_BYTES or _encode_signature(decoded) != value:
        raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
    return decoded


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("POLICY_SIGNED_DOCUMENT_INVALID")
        result[key] = value
    return result
