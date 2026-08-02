import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile


PROJECT_ROOT = Path(__file__).parents[1]


def test_wheel_installs_with_self_audit_resources_offline(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    install_dir = tmp_path / "installed"
    environment = os.environ.copy()
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            ".",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
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

    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--target",
            str(install_dir),
            str(wheel),
        ],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
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
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    audit = json.loads(probe.stdout)
    assert audit["rules_sha256"] == hashlib.sha256(
        (PROJECT_ROOT / "rules" / "default.json").read_bytes()
    ).hexdigest()
