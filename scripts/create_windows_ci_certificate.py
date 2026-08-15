"""Create an ephemeral MSIX smoke-test certificate without Windows PKI calls."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def create_certificate(
    *,
    publisher: str,
    certificate_path: Path,
    pfx_path: Path,
    password: str,
) -> None:
    if not publisher or not password:
        raise ValueError("publisher and password are required")
    if certificate_path.exists() or pfx_path.exists():
        raise ValueError("certificate output already exists")
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    pfx_path.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, publisher)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    pfx_path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=b"AgentGuardian CI smoke",
            key=key,
            cert=certificate,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf-8")
            ),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--certificate-path", type=Path, required=True)
    parser.add_argument("--pfx-path", type=Path, required=True)
    args = parser.parse_args()
    password = os.environ.get("AGENTGUARDIAN_PFX_PASSWORD", "")
    create_certificate(
        publisher=args.publisher,
        certificate_path=args.certificate_path,
        pfx_path=args.pfx_path,
        password=password,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
