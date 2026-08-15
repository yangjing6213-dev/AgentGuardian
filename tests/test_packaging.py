import base64
import binascii
import csv
from email.parser import Parser
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile

import pytest


PROJECT_ROOT = Path(__file__).parents[1]
APACHE_2_NORMALIZED_SHA256 = (
    "34ebcacd4e688c691f76c88a93da94f07dec445e6c1c963023c4ce75e856fe62"
)


def _assert_apache_2_license_text(license_text: str) -> None:
    normalized = "\n".join(
        line.rstrip()
        for line in license_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ).strip()
    assert hashlib.sha256(normalized.encode("utf-8")).hexdigest() == (
        APACHE_2_NORMALIZED_SHA256
    )


def test_apache_2_license_is_declared() -> None:
    project = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    license_text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")

    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]
    _assert_apache_2_license_text(license_text)


def test_apache_2_license_rejects_missing_terms() -> None:
    incomplete = (
        "Apache License\n"
        "Version 2.0, January 2004\n"
        "http://www.apache.org/licenses/\n"
        "END OF TERMS AND CONDITIONS\n"
    )

    with pytest.raises(AssertionError):
        _assert_apache_2_license_text(incomplete)


@pytest.mark.parametrize("newline", ("\n", "\r\n"), ids=("lf", "crlf"))
def test_apache_2_license_accepts_platform_newlines(newline: str) -> None:
    license_text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")

    _assert_apache_2_license_text(license_text.replace("\n", newline))


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
    assert (
        base64.urlsafe_b64encode(recorded_digest).rstrip(b"=").decode("ascii")
        == encoded_digest
    )
    assert recorded_digest == hashlib.sha256(member).digest()
    assert recorded_size == len(member)


def test_record_member_validation_rejects_malformed_digest_and_size() -> None:
    member = b"reviewed resource"
    member_digest = hashlib.sha256(member).digest()
    digest = base64.urlsafe_b64encode(member_digest).rstrip(b"=")
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    final_index = alphabet.index(digest[-1])
    assert final_index % 4 == 0
    alternate_digest = digest[:-1] + alphabet[final_index + 1 : final_index + 2]
    assert base64.urlsafe_b64decode(alternate_digest + b"=") == member_digest
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
            f"sha256={alternate_digest.decode('ascii')}",
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
    dist_dir = tmp_path / "dist"
    install_dir = tmp_path / "installed"
    source_tree.mkdir()
    dist_dir.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(PROJECT_ROOT / name, source_tree / name)
    shutil.copytree(PROJECT_ROOT / "src", source_tree / "src")

    build_sdist = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import setuptools.build_meta as backend,sys;"
                "print(backend.build_sdist(sys.argv[1]))"
            ),
            str(dist_dir),
        ],
        cwd=source_tree,
        check=True,
        capture_output=True,
        text=True,
    )
    build_wheel = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import setuptools.build_meta as backend,sys;"
                "print(backend.build_wheel(sys.argv[1]))"
            ),
            str(dist_dir),
        ],
        cwd=source_tree,
        check=True,
        capture_output=True,
        text=True,
    )
    sdist_name = build_sdist.stdout.splitlines()[-1]
    wheel_name = build_wheel.stdout.splitlines()[-1]
    sdist = dist_dir / sdist_name
    wheel = dist_dir / wheel_name

    with tarfile.open(sdist, "r:gz") as archive:
        license_member = next(
            member for member in archive.getmembers() if member.name.endswith("/LICENSE")
        )
        pkg_info_member = next(
            member for member in archive.getmembers() if member.name.endswith("/PKG-INFO")
        )
        extracted_license = archive.extractfile(license_member)
        extracted_pkg_info = archive.extractfile(pkg_info_member)
        assert extracted_license is not None
        assert extracted_pkg_info is not None
        assert extracted_license.read() == (PROJECT_ROOT / "LICENSE").read_bytes()
        sdist_metadata = Parser().parsestr(
            extracted_pkg_info.read().decode("utf-8")
        )
        assert sdist_metadata["Metadata-Version"] == "2.4"
        assert sdist_metadata["License-Expression"] == "Apache-2.0"
        assert sdist_metadata.get_all("License-File") == ["LICENSE"]
        assert sorted(sdist_metadata.get_all("Project-URL")) == [
            "Issues, https://github.com/yangjing6213-dev/AgentGuardian/issues",
            "Repository, https://github.com/yangjing6213-dev/AgentGuardian",
        ]

    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
        parsed_metadata = Parser().parsestr(metadata)
        license_name = next(
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/licenses/LICENSE")
        )
        assert parsed_metadata["Metadata-Version"] == "2.4"
        assert parsed_metadata["License-Expression"] == "Apache-2.0"
        assert parsed_metadata.get_all("License-File") == ["LICENSE"]
        assert sorted(parsed_metadata.get_all("Project-URL")) == [
            "Issues, https://github.com/yangjing6213-dev/AgentGuardian/issues",
            "Repository, https://github.com/yangjing6213-dev/AgentGuardian",
        ]
        assert archive.read(license_name) == (PROJECT_ROOT / "LICENSE").read_bytes()
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
                "assert static_capability_findings()==('NETWORK_MODULE_IMPORT','USER_DATA_WRITE');"
                "assert audit['findings']==['NETWORK_MODULE_IMPORT','USER_DATA_WRITE'] and not audit['local_only'];"
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
