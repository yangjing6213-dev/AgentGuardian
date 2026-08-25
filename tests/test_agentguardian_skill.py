from __future__ import annotations

import hashlib
import os
import shutil
import zipfile
from pathlib import Path

import pytest

import scripts.build_agentguardian_skill as skill_builder
from scripts.build_agentguardian_skill import build_skill


PROJECT_ROOT = Path(__file__).parents[1]
SOURCE_ROOT = PROJECT_ROOT / "skills" / "agentguardian"
EXPECTED_ENTRIES = (
    "agentguardian/LICENSE",
    "agentguardian/README.md",
    "agentguardian/SKILL.md",
)


def _copy_source(tmp_path: Path) -> Path:
    source = tmp_path / "source" / "agentguardian"
    shutil.copytree(SOURCE_ROOT, source)
    return source


def _build(source: Path, tmp_path: Path) -> Path:
    target, _digest = build_skill(source, tmp_path / "output")
    return target


def test_skill_zip_is_allowlisted_and_deterministic(tmp_path: Path) -> None:
    first, first_digest = build_skill(SOURCE_ROOT, tmp_path / "one")
    second, second_digest = build_skill(SOURCE_ROOT, tmp_path / "two")

    assert first.read_bytes() == second.read_bytes()
    assert first_digest == second_digest == hashlib.sha256(first.read_bytes()).hexdigest()
    assert (first.parent / f"{first.name}.sha256").read_text(encoding="ascii") == (
        f"{first_digest} *{first.name}\n"
    )
    with zipfile.ZipFile(first) as archive:
        assert tuple(sorted(archive.namelist())) == EXPECTED_ENTRIES
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())
        assert all(info.filename.isascii() for info in archive.infolist())


def test_skill_source_has_required_identity_and_license() -> None:
    skill = (SOURCE_ROOT / "SKILL.md").read_text(encoding="utf-8")
    assert skill.startswith(
        "---\n"
        "name: agentguardian\n"
        "description: Use AgentGuardian to audit one bounded local AI configuration scope, browser history database aggregate, current clipboard value, or public share URL. Requires the local AgentGuardian MCP tools and must not be used for regulated or highly sensitive data.\n"
        "metadata:\n"
        '  version: "0.1.0"\n'
        '  requires-agentguardian: ">=0.3.0a1,<0.4"\n'
        "---\n"
    )
    assert (SOURCE_ROOT / "LICENSE").read_bytes() == (PROJECT_ROOT / "LICENSE").read_bytes()


@pytest.mark.parametrize(
    "relative, content",
    (
        ("notes.txt", b"unexpected"),
        (".hidden", b"unexpected"),
        ("payload.exe", b"MZ"),
        ("\u00e9.txt", b"unexpected"),
    ),
)
def test_skill_rejects_unallowlisted_or_unsafe_entries(
    tmp_path: Path,
    relative: str,
    content: bytes,
) -> None:
    source = _copy_source(tmp_path)
    (source / relative).write_bytes(content)

    with pytest.raises(ValueError):
        _build(source, tmp_path)


def test_skill_rejects_links(tmp_path: Path) -> None:
    source = _copy_source(tmp_path)
    try:
        os.symlink(source / "README.md", source / "link.txt")
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlink unavailable: {error}")

    with pytest.raises(ValueError):
        _build(source, tmp_path)


def test_skill_rejects_frontmatter_mismatch(tmp_path: Path) -> None:
    source = _copy_source(tmp_path)
    skill = source / "SKILL.md"
    skill.write_text(
        skill.read_text(encoding="utf-8").replace("version: \"0.1.0\"", "version: \"9.9.9\""),
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(ValueError):
        _build(source, tmp_path)


def test_skill_rejects_secret_patterns_and_executable_headers(tmp_path: Path) -> None:
    source = _copy_source(tmp_path)
    readme = source / "README.md"
    readme.write_bytes(readme.read_bytes() + b"\nOPENAI_API_KEY=sk-proj-abcdefghijklmnop\n")

    with pytest.raises(ValueError):
        _build(source, tmp_path)

    readme.write_bytes(b"MZ" + readme.read_bytes())
    with pytest.raises(ValueError):
        _build(source, tmp_path)


def test_skill_rejects_oversized_file_and_aggregate(tmp_path: Path) -> None:
    source = _copy_source(tmp_path)
    readme = source / "README.md"
    readme.write_bytes(readme.read_bytes() + b"x" * (256 * 1024))

    with pytest.raises(ValueError):
        _build(source, tmp_path)


def test_skill_rejects_license_mismatch(tmp_path: Path) -> None:
    source = _copy_source(tmp_path)
    license_path = source / "LICENSE"
    license_path.write_bytes(license_path.read_bytes() + b"\nchanged\n")

    with pytest.raises(ValueError):
        _build(source, tmp_path)


def test_skill_reads_sources_without_path_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _copy_source(tmp_path)

    def fail_path_read_bytes(_path: Path) -> bytes:
        raise AssertionError("source must be read through a checked handle")

    monkeypatch.setattr(Path, "read_bytes", fail_path_read_bytes)
    target, _digest = build_skill(source, tmp_path / "output")

    assert target.is_file()


def test_skill_replaces_zip_and_checksum_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replacements: list[tuple[str, str]] = []
    real_replace = os.replace

    def record_replace(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
        replacements.append((os.fspath(source), os.fspath(target)))
        real_replace(source, target)

    monkeypatch.setattr(skill_builder.os, "replace", record_replace)
    target, _digest = build_skill(SOURCE_ROOT, tmp_path / "output")

    assert target.is_file()
    assert len(replacements) == 2
    assert all(Path(source).parent == Path(destination).parent for source, destination in replacements)


def test_skill_cleans_partial_outputs_when_checksum_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    real_replace = os.replace
    calls = 0

    def fail_checksum_replace(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic replace failure")
        real_replace(source, target)

    monkeypatch.setattr(skill_builder.os, "replace", fail_checksum_replace)
    with pytest.raises(ValueError, match="skill build failed"):
        build_skill(SOURCE_ROOT, output)

    assert not (output / "AgentGuardian-Skill-0.1.0.zip").exists()
    assert not (output / "AgentGuardian-Skill-0.1.0.zip.sha256").exists()
    assert not tuple(output.glob(".agentguardian-skill-*"))
