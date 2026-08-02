import base64
import binascii
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

import pytest


PROJECT_ROOT = Path(__file__).parents[1]


def _assert_record_member(row: list[str], member: bytes) -> None:
    assert len(row) == 3
    algorithm, separator, encoded_digest = row[1].partition("=")
    assert algorithm == "sha256" and separator and encoded_digest
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded_digest) is not None
    try:
        recorded_digest = base64.urlsafe_b64decode(encoded_digest + "=")
        recorded_size = int(row[2])
    except (binascii.Error, UnicodeError, ValueError) as error:
        raise AssertionError from error
    assert recorded_digest == hashlib.sha256(member).digest()
    assert recorded_size == len(member)


def test_record_member_validation_rejects_malformed_digest_and_size() -> None:
    member = b"reviewed resource"
    member_digest = hashlib.sha256(member).digest()
    digest = base64.urlsafe_b64encode(member_digest).rstrip(b"=")
    standard_digest = base64.b64encode(member_digest).rstrip(b"=")
    assert standard_digest != digest
    wrong_digest = base64.urlsafe_b64encode(
        hashlib.sha256(member + b" changed").digest()
    ).rstrip(b"=")
    rows = (
        ["resource.json", "sha256=not!base64", str(len(member))],
        [
            "resource.json",
            f"sha256={wrong_digest.decode('ascii')}",
            str(len(member)),
        ],
        [
            "resource.json",
            f"sha256={standard_digest.decode('ascii')}",
            str(len(member)),
        ],
        ["resource.json", f"sha256={digest.decode('ascii')}=", str(len(member))],
        ["resource.json", f"sha256={digest.decode('ascii')}", "not-a-size"],
        ["resource.json", f"sha256={digest.decode('ascii')}", str(len(member) + 1)],
    )

    for row in rows:
        with pytest.raises(AssertionError):
            _assert_record_member(row, member)


def test_wheel_extracts_with_self_audit_resources_offline(tmp_path: Path) -> None:
    source_tree = tmp_path / "source"
    wheel_dir = tmp_path / "wheel"
    install_dir = tmp_path / "installed"
    source_tree.mkdir()
    wheel_dir.mkdir()
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(PROJECT_ROOT / name, source_tree / name)
    shutil.copytree(PROJECT_ROOT / "src", source_tree / "src")

    subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import setuptools.build_meta as backend,sys;"
                "backend.build_wheel(sys.argv[1])"
            ),
            str(wheel_dir),
        ],
        cwd=source_tree,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(wheel_dir.glob("*.whl"))

    with zipfile.ZipFile(wheel) as archive:
        record_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/RECORD")
        )
        record_rows = {
            row[0]: row
            for row in csv.reader(
                io.StringIO(archive.read(record_name).decode("utf-8"))
            )
        }
        resources = {
            "agentguardian/rules/default.json",
            "agentguardian/source_policy.json",
        }
        assert resources <= record_rows.keys()
        for resource in resources:
            _assert_record_member(record_rows[resource], archive.read(resource))
        assert archive.read("agentguardian/rules/default.json") == (
            PROJECT_ROOT / "rules" / "default.json"
        ).read_bytes()
        archive.extractall(install_dir)

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import json,sys;"
                f"sys.path.insert(0,{str(install_dir)!r});"
                "from agentguardian.detectors import load_rules;"
                "from agentguardian.self_audit import collect_self_audit,static_capability_findings;"
                "audit=collect_self_audit();"
                "assert load_rules().rules;"
                "assert static_capability_findings()==();"
                "assert audit['findings']==[] and audit['local_only'];"
                "print(json.dumps(audit,sort_keys=True))"
            ),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    audit = json.loads(probe.stdout)
    assert audit["rules_sha256"] == hashlib.sha256(
        (PROJECT_ROOT / "rules" / "default.json").read_bytes()
    ).hexdigest()
