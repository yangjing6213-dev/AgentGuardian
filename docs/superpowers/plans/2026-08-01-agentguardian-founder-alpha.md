# AgentGuardian Founder Alpha Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a Windows-only `0.1.0 Founder Alpha` that discovers a narrow set of local AI assets, detects sensitive data and risky MCP permissions, calculates an explainable score, exports a local report, and produces manual remediation guidance without sending raw evidence off-device or modifying user data.

**Architecture:** Use a small Python package with immutable dataclass contracts, pure detector/scoring functions, Windows adapters at the edges, and a PySide6 desktop shell. The core has no network capability and the Alpha performs no writes to user data; reports contain masked evidence only. The Alpha uses JSON rules and standard-library storage/HTML generation. Remediation is a manual, provider-specific checklist until a later hardening cycle proves a safe action contract.

**Tech Stack:** Python 3.12+, PySide6 6.x, pytest, standard-library `pathlib`, `json`, `re`, `hashlib`, `sqlite3`, `winreg`, `ctypes`, and `html`; SVG brand sources; Edge headless and Pillow raster verification; GitHub Actions on Windows. A .NET/WPF rewrite is deferred because this machine has no .NET SDK and adding a new runtime would not fit the seven-day Alpha.

---

## File Map

```text
assets/brand/                         deterministic brand sources and PNG exports
scripts/check_brand_assets.py         dimensions, XML, transparency, and color checks
src/agentguardian/domain.py           shared immutable contracts
src/agentguardian/discovery.py        Windows asset discovery and user-selected roots
src/agentguardian/detectors.py        secret, keyword, PII, and MCP static detectors
src/agentguardian/scoring.py          six-domain deduction and score caps
src/agentguardian/reporting.py        local JSON/HTML reports
src/agentguardian/guidance.py         manual remediation checklists; no writes
src/agentguardian/app.py              PySide6 application shell
src/agentguardian/__main__.py         `python -m agentguardian` entrypoint
rules/default.json                    Alpha rule bundle with recorded SHA-256
tests/                                synthetic fixtures and focused unit/E2E tests
.github/workflows/ci.yml              Windows test and brand validation
```

## Task 1: Trust Frame Brand Assets

**Files:**
- Create: `assets/brand/agentguardian-mark.svg`
- Create: `assets/brand/agentguardian-mark-dark.svg`
- Create: `assets/brand/agentguardian-wordmark.svg`
- Create: `assets/brand/agentguardian-cover.svg`
- Create: `assets/brand/agentguardian-mark-512.png`
- Create: `assets/brand/agentguardian-mark-dark-512.png`
- Create: `assets/brand/agentguardian-cover-1280x640.png`
- Create: `assets/brand/README.md`
- Create: `scripts/check_brand_assets.py`
- Modify: `README.md`

- [ ] **Step 1: Write the failing brand validator**

```python
from pathlib import Path
from xml.etree import ElementTree
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "assets" / "brand"


def main() -> None:
    expected_svg = {
        "agentguardian-mark.svg": (0, 0, 512, 512),
        "agentguardian-mark-dark.svg": (0, 0, 512, 512),
        "agentguardian-wordmark.svg": (0, 0, 1600, 400),
        "agentguardian-cover.svg": (0, 0, 1280, 640),
    }
    for name, view_box in expected_svg.items():
        root = ElementTree.parse(BRAND / name).getroot()
        actual = tuple(map(int, root.attrib["viewBox"].split()))
        assert actual == view_box, (name, actual)

    with Image.open(BRAND / "agentguardian-mark-512.png") as image:
        assert image.size == (512, 512)
        assert image.mode == "RGBA"
    with Image.open(BRAND / "agentguardian-mark-dark-512.png") as image:
        assert image.size == (512, 512)
        assert image.mode in {"RGB", "RGBA"}
    with Image.open(BRAND / "agentguardian-cover-1280x640.png") as image:
        assert image.size == (1280, 640)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the validator and confirm it fails because assets do not exist**

Run: `rtk python scripts/check_brand_assets.py`
Expected: FAIL with `FileNotFoundError` for `assets/brand/agentguardian-mark.svg`.

- [ ] **Step 3: Create the minimum deterministic SVG set**

The mark uses a 512 square viewBox, open corner strokes, Obsidian `#0F1215`, Trust `#15A36D`, and a centered `AG` monogram. The broader system uses Cloud `#F4F6F7`, Signal `#2A8CCB`, Warning `#D49A32`, and Critical `#C64A43`. The GitHub cover uses an opaque Obsidian background. Use SVG paths/shapes only; do not embed raster images. The wordmark and cover may use the fallback stack `Inter, 'Noto Sans SC', 'Segoe UI', sans-serif` with `letter-spacing="0"`.

- [ ] **Step 4: Render the three required PNG exports**

Run `rtk proxy powershell -NoProfile -Command "& 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' --headless --disable-gpu --hide-scrollbars --screenshot='assets/brand/agentguardian-mark-512.png' --window-size=512,512 (Resolve-Path 'assets/brand/agentguardian-mark.svg')"` and equivalent commands for `agentguardian-mark-dark.svg`/`agentguardian-mark-dark-512.png` and `agentguardian-cover.svg`/`agentguardian-cover-1280x640.png`. Use Pillow once to turn only the white background pixels in the light mark transparent, then save it as RGBA. Keep the dark mark and cover opaque.

- [ ] **Step 5: Run validator and visual inspection**

Run: `rtk python scripts/check_brand_assets.py`
Expected: exit 0. Inspect both PNG files at original detail; verify all four frame corners, the AG monogram, Chinese title, English name, and cover audit mockup are fully visible.

- [ ] **Step 6: Update README and commit**

```markdown
![AgentGuardian](assets/brand/agentguardian-cover.svg)
```

Run: `rtk git add README.md assets/brand scripts/check_brand_assets.py docs/superpowers/plans/2026-08-01-agentguardian-founder-alpha.md`
Run: `rtk git commit -m "Add AgentGuardian brand assets and Alpha plan"`

## Task 2: Package Scaffold and Contracts

**Files:**
- Create: `pyproject.toml`
- Create: `src/agentguardian/__init__.py`
- Create: `src/agentguardian/domain.py`
- Create: `tests/test_domain.py`

- [ ] **Step 1: Write contract tests**

```python
from agentguardian.domain import Evidence, Finding, RiskDomain, Severity


def test_evidence_rejects_unmasked_secret() -> None:
    try:
        Evidence(source="a.txt", fingerprint="abc", masked="sk-live-secret")
    except ValueError as error:
        assert "masked" in str(error)
    else:
        raise AssertionError("raw-looking evidence must be rejected")


def test_finding_keeps_domain_and_severity() -> None:
    finding = Finding("R-1", RiskDomain.CREDENTIALS, Severity.HIGH, "root-1", ())
    assert finding.domain is RiskDomain.CREDENTIALS
    assert finding.severity is Severity.HIGH
```

- [ ] **Step 2: Verify tests fail before package exists**

Run: `rtk pytest tests/test_domain.py -q`
Expected: FAIL with `ModuleNotFoundError: agentguardian`.

- [ ] **Step 3: Add immutable contracts and raw-value guard**

```python
from dataclasses import dataclass
from enum import Enum


class RiskDomain(str, Enum):
    EXPOSURE = "exposure"
    PRIVACY = "privacy"
    CREDENTIALS = "credentials"
    PERMISSIONS = "permissions"
    RETENTION = "retention"
    SUPPLY_CHAIN = "supply_chain"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Evidence:
    source: str
    fingerprint: str
    masked: str

    def __post_init__(self) -> None:
        if len(self.masked) > 80 or "live-secret" in self.masked:
            raise ValueError("masked evidence contains unsafe content")


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    domain: RiskDomain
    severity: Severity
    root_fingerprint: str
    evidence: tuple[Evidence, ...]
```

- [ ] **Step 4: Run tests and commit**

Run: `rtk pytest tests/test_domain.py -q`
Expected: 2 passed.
Commit: `rtk git commit -am "Add immutable audit contracts"`

## Task 3: Windows Asset Discovery

**Files:**
- Create: `src/agentguardian/discovery.py`
- Create: `tests/test_discovery.py`

- [ ] **Step 1: Test known config and user-root discovery**

```python
from pathlib import Path
from agentguardian.discovery import discover_files


def test_discovery_is_read_only_and_bounded(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ignore.bin").write_bytes(b"x")
    found = discover_files([tmp_path], {".json"}, max_files=10)
    assert found == [tmp_path / "mcp.json"]
```

- [ ] **Step 2: Confirm red state**

Run: `rtk pytest tests/test_discovery.py -q`
Expected: FAIL importing `agentguardian.discovery`.

- [ ] **Step 3: Implement bounded pathlib traversal**

```python
def discover_files(roots: list[Path], suffixes: set[str], max_files: int = 50_000) -> list[Path]:
    found: list[Path] = []
    for root in roots:
        for path in root.rglob("*"):
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            found.append(path)
            if len(found) >= max_files:
                return sorted(found)
    return sorted(found)
```

- [ ] **Step 4: Add explicit known-path providers**

Known paths are returned only when they exist and remain under `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%\.config`, or user-selected roots. Do not scan the whole drive and do not follow junctions.

- [ ] **Step 5: Test and commit**

Run: `rtk pytest tests/test_discovery.py -q`
Expected: pass.
Commit: `rtk git commit -am "Add bounded Windows asset discovery"`

## Task 4: Local Detectors and Custom Rules

**Files:**
- Create: `rules/default.json`
- Create: `src/agentguardian/detectors.py`
- Create: `tests/test_detectors.py`

- [ ] **Step 1: Add synthetic positive and negative tests**

```python
from agentguardian.detectors import detect_text


def test_secret_is_masked_and_fingerprinted() -> None:
    findings = detect_text("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuv", "sample.env")
    assert len(findings) == 1
    assert findings[0].evidence[0].masked.startswith("sk-p")
    assert "abcdefghijkl" not in findings[0].evidence[0].masked


def test_custom_chinese_keyword() -> None:
    findings = detect_text("项目代号：北辰", "chat.txt", keywords=["北辰"])
    assert findings[0].rule_id == "CUSTOM_KEYWORD"
```

- [ ] **Step 2: Confirm tests fail**

Run: `rtk pytest tests/test_detectors.py -q`
Expected: FAIL importing detector.

- [ ] **Step 3: Implement regex matching with SHA-256 root fingerprints**

Use compiled patterns from `rules/default.json`, read files as UTF-8 with replacement, cap each file at 10 MiB, mask every match before constructing `Evidence`, and hash `rule_id + normalized_match` locally. Never log match text.

- [ ] **Step 4: Add MCP combination rule**

Parse JSON structurally. Emit `MCP_DANGEROUS_COMBINATION` only when one server has shell/process capability, write-capable filesystem scope, and network access in the same configuration.

- [ ] **Step 5: Test and commit**

Run: `rtk pytest tests/test_detectors.py -q`
Expected: all pass.
Commit: `rtk git commit -am "Add local sensitive-data detectors"`

## Task 5: Explainable Scoring and Reports

**Files:**
- Create: `src/agentguardian/scoring.py`
- Create: `src/agentguardian/reporting.py`
- Create: `tests/test_scoring.py`
- Create: `tests/test_reporting.py`

- [ ] **Step 1: Test root-cause deduplication and hard caps**

```python
from agentguardian.domain import Finding, RiskDomain, Severity
from agentguardian.scoring import score


def public_active_credential_finding() -> Finding:
    return Finding("PUBLIC_ACTIVE_CREDENTIAL", RiskDomain.EXPOSURE, Severity.CRITICAL, "public-1", ())


def high_credential_finding(root: str) -> Finding:
    return Finding("API_KEY", RiskDomain.CREDENTIALS, Severity.HIGH, root, ())


def test_public_active_credential_caps_total_at_39():
    result = score([public_active_credential_finding()], coverage=1.0)
    assert result.total == 39
    assert result.cap_reason == "public_active_credential"


def test_duplicate_root_only_deducts_once():
    finding = high_credential_finding(root="same")
    assert score([finding, finding], coverage=1.0).total == 93
```

- [ ] **Step 2: Implement domain-capped deductions**

Severity deductions are `{critical: 12, high: 7, medium: 3, low: 1}`. Deduplicate by `(domain, root_fingerprint)`, cap each domain at its weight, then apply the 39/59 hard caps. Coverage and confidence are separate fields and never increase the score.

- [ ] **Step 3: Test masked JSON and HTML reports**

Assert report output contains rule IDs, masked evidence, coverage, confidence, limits, and score cap reason; assert it does not contain the synthetic raw secret.

- [ ] **Step 4: Implement standard-library reporting and commit**

Use `json.dumps(..., ensure_ascii=False, indent=2)` and `html.escape` with a static HTML template. Do not add a template engine.
Run: `rtk pytest tests/test_scoring.py tests/test_reporting.py -q`
Expected: all pass.
Commit: `rtk git commit -am "Add explainable scoring and local reports"`

## Task 6: Manual Remediation Guidance and Verification Limits

**Files:**
- Create: `src/agentguardian/guidance.py`
- Create: `tests/test_guidance.py`

- [ ] **Step 1: Test provider-specific guidance and no-write behavior**

```python
from pathlib import Path
from agentguardian.guidance import guidance_for


def test_public_credential_guidance_is_manual_and_does_not_write(tmp_path: Path):
    target = tmp_path / "share.txt"
    target.write_text("synthetic", encoding="utf-8")
    plan = guidance_for("PUBLIC_ACTIVE_CREDENTIAL", target)
    assert plan.mode == "manual"
    assert "revoke" in plan.steps[0].lower()
    assert target.read_text(encoding="utf-8") == "synthetic"
```

- [ ] **Step 2: Implement read-only guidance**

Return an immutable guidance object containing risk, provider-neutral manual steps, verification steps, and a `manual` mode. Do not rename, delete, chmod, edit, open a URL, invoke a shell, elevate, or mutate the target. Keep the target path only as a redacted display name in reports.

- [ ] **Step 3: Verify and commit**

Run: `rtk pytest tests/test_guidance.py -q`
Expected: all pass.
Commit: `rtk git commit -am "Add manual remediation guidance"`

## Task 7: Minimal PySide6 Audit UI

**Files:**
- Create: `src/agentguardian/app.py`
- Create: `src/agentguardian/__main__.py`
- Create: `tests/test_app_smoke.py`

- [ ] **Step 1: Write offscreen UI smoke test**

```python
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from agentguardian.app import create_window


def test_window_exposes_trust_state():
    app = QApplication.instance() or QApplication([])
    window = create_window()
    try:
        assert "本地模式" in window.local_mode_label.text()
        assert window.scan_button.text() == "开始审计"
    finally:
        window.close()
        app.processEvents()
```

- [ ] **Step 2: Implement one-window workflow**

Use a left navigation list and a stacked content area. Alpha pages are Scope, Findings, and Report; a compact trust strip always shows local-only mode, network capability, rule version, and Alpha status. The scan button opens a folder chooser, runs bounded discovery in a worker thread, passes results to pure detectors/scoring, and updates the overview. Do not implement accounts, cloud sync, animations, theming engines, plugin marketplaces, embedded web pages, or remediation controls.

- [ ] **Step 3: Apply fixed design tokens**

Use Obsidian, Cloud, Trust, Signal, Warning, and Critical from the design spec; neutral black, white, and gray establish hierarchy, Trust marks verified states, Warning and Critical mark risk, and Signal remains auxiliary; 6px maximum corner radius; 0 letter spacing; system font fallback; no gradients and no decorative cards.

- [ ] **Step 4: Smoke test and commit**

Run: `rtk pytest tests/test_app_smoke.py -q`
Expected: pass offscreen.
Commit: `rtk git commit -am "Add minimal local audit interface"`

## Task 8: CI, Minimal Self-Audit, and Alpha Release Gate

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `src/agentguardian/self_audit.py`
- Create: `tests/test_self_audit.py`
- Create: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `README.md`

- [ ] **Step 1: Test self-audit output**

Assert the output includes version, executable path, rule-bundle SHA-256, local-only mode, and `network_capability: absent`. It must not enumerate environment variable values. The binary must contain no update, telemetry, LLM, share-verification, or network client module.

- [ ] **Step 2: Add Windows CI**

CI installs `.[dev]`, runs `rtk pytest -q` when RTK is available or `pytest -q` on GitHub-hosted runners, runs `python scripts/check_brand_assets.py`, and fails on uncommitted generated artifacts.

- [ ] **Step 3: Run complete release gate**

Run: `rtk pytest -q`
Run: `rtk python scripts/check_brand_assets.py`
Run: `rtk git diff --check`
Expected: all tests pass, brand validator exits 0, no whitespace errors, and `rtk git status --short` lists only intentional release-report changes.

- [ ] **Step 4: Independent read-only review**

Reviewer confirms no raw evidence in logs/reports, no network calls in the binary, no arbitrary command execution, no user-data writes, no browser/clipboard collection, and README says Founder Alpha rather than production-safe.

- [ ] **Step 5: Commit and push**

Run: `rtk git add .github src tests docs README.md pyproject.toml rules`
Run: `rtk git commit -m "Prepare AgentGuardian 0.1.0 Founder Alpha"`
Run: `rtk git push -u origin agent/founder-alpha`

## Execution Order and Ownership

1. Task 1 is independent brand work and may complete first.
2. Task 2 freezes shared contracts; no implementation task starts before it passes.
3. Tasks 3 and 4 may run in parallel only after Task 2, with disjoint ownership.
4. Task 5 consumes contracts and findings; Task 6 consumes finding IDs and produces manual guidance.
5. Task 7 starts against frozen contracts and synthetic JSON, then integrates real data after Tasks 3 to 6.
6. Task 8 is serial and blocks release.

The main orchestrator owns shared contract changes, integration, and release. At most three write agents run concurrently. A separate reviewer remains read-only. Executable remediation, elevation, rollback, dynamic plugins, browser databases, clipboard, network verification, optional egress, and industry policy packs are explicitly deferred until a post-Alpha hardening plan.
