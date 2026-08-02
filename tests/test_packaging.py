import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


PROJECT_ROOT = Path(__file__).parents[1]


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
        record_paths = {
            row[0]
            for row in csv.reader(
                io.StringIO(archive.read(record_name).decode("utf-8"))
            )
        }
        assert {
            "agentguardian/rules/default.json",
            "agentguardian/source_policy.json",
        } <= record_paths
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
