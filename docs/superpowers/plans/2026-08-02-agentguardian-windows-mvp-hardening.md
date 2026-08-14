# AgentGuardian Windows MVP Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the existing Windows Founder Alpha into a verifiable Windows MVP while keeping OpenAI Provider support local-first, manual, and free of default API calls.

**Architecture:** Keep the existing pure Python audit core and PySide6 shell. Add one bounded capability at a time behind synthetic tests, preserve the read-only scan boundary, and keep raw credentials, full paths, and endpoint values out of reports. Each hardening batch has its own acceptance gate and does not imply production safety.

**Tech Stack:** Python 3.12+, PySide6, pytest, standard library, Windows DPAPI in the later evidence-store batch, GitHub Actions on Windows, and the existing deterministic rule/report formats.

---

## Confirmed Product Boundary

- OpenAI Provider support means local configuration discovery, static detection, and provider-specific manual guidance.
- The default product path does not import an OpenAI SDK, create an HTTP client, call an API, verify a remote endpoint, revoke a key, or modify provider configuration.
- Tests use synthetic paths, keys, and endpoints only.
- Founder Alpha remains the current release label until every Windows MVP release gate passes.
- No milestone may be described as production-safe without a separate production threat model and release review.

## Windows MVP Roadmap

| Batch | Deliverable | Acceptance gate |
| --- | --- | --- |
| 0 | Supply-chain baseline | GitHub Actions pinned to commit SHAs; Node.js 24 Action runtime; Windows Python dependencies hash-locked; CI green. Completed in `63b1327`, `3afe5e6`, and the Node runtime refresh `fb01c2a`. |
| 1 | OpenAI local Provider hardening | Detect local OpenAI key and base-URL override evidence, cover the official Codex user config root, route OpenAI findings to manual OpenAI guidance, and retain zero network/LLM capability. |
| 2 | [Protected local evidence state](2026-08-02-agentguardian-protected-evidence-state.md) | Completed in `6f87445`, `8780a4d`, and `e8e01f9`; local gate, independent review, push CI `30715647491`, and Draft PR CI `30715649117` passed. Persists only rule IDs, fixed rule-owned summaries, scan metadata, and HMAC references under Windows DPAPI; never raw matches or scan keys; corrupted state fails closed. |
| 3 | [Finding disposition and exceptions](../specs/2026-08-02-agentguardian-finding-dispositions-design.md) | Remotely accepted Batch 3 implementation/evidence baseline: `50b74e6cc50dd7a4681a26b3084e7f312c096c47`. Exact local cross-scan false-positive/accepted-risk states use mandatory expiry, preserve technical scoring, add reviewed scoring, and keep report and local HMAC purposes separate. |
| 4 | Windows workflow and report hardening | Task 1-8 implementation is local; Task 9 historical evidence is bound to `991bf81bb520e7f2ec12f331fbbe714f03212507`. Task 10 independent review and dual-Python local gates are bound to `d1c3e9caa856812d0bdd3221b0c6a7083da937ff`; remote implementation/evidence baseline `a79995a7a6a950050d5628324f94a6b8a07e6308` has successful push and Draft PR CI evidence. |
| 5 | Packaging and release provenance | Portable development layer locally verified at `10e65322cd590f2028fb5946fff7125afd2e101d`: reproducible PyInstaller `onedir`, SBOM with the embedded bootloader as a runtime dependency, manifests, checksums, deterministic ZIP, and isolated launch/cleanup smoke. Trusted signing, native installation, clean-machine acceptance, and uninstall-residue evidence remain pending. |
| 6 | Windows MVP release candidate | Batch 6 gate hardening and unified local evidence are bound to `392ff64f3bcb3f978874e668a97e5a3f013b762e`. Independent review found 7 Important findings; local remediation is complete but independent re-review, current exact-SHA GitHub CI, fresh-runner provenance, signing, native install/uninstall, clean-machine acceptance, and license review remain pending. Release-candidate decision: `NO-GO`. |

Deferred beyond Windows MVP: default API calls, remote share verification, browser database or clipboard collection, runtime interception, automatic credential revocation, arbitrary command execution, dynamic plugins, macOS, enterprise control plane, and production-safety claims.

## Batch 3 Local Implementation and Gate Status

Batch 3 本地实现、自动门禁、独立安全复审和最终 SHA 远程验收已完成。Remotely accepted Batch 3 implementation/evidence baseline: `50b74e6cc50dd7a4681a26b3084e7f312c096c47`. At evidence-capture time, Draft PR #1 was `OPEN / DRAFT` at that SHA. `a38910b340631b2e78c33c9d7595cf98aa2f52b9` is a docs/tests-only evidence-sync commit that changes no runtime or package source, was not covered by the two cited CI runs for `50b74e6cc50dd7a4681a26b3084e7f312c096c47`, and is not claimed as remotely verified. 跨扫描精确匹配使用规则 ID、按 Windows 词法规则规范化的源路径，以及 NFKC 规范化的原始匹配。路径不做 NFKC。本地处置 HMAC 密钥与每次扫描随机生成的报告 HMAC 密钥彼此独立，报告 HMAC 仍限定于单次扫描。处置有效期必须有限且不超过 366 天。有效误报只从复核分排除；接受风险仍计入复核分；技术分不受处置影响。

schema v1 只读兼容，只有显式保存才迁移到 schema v2。损坏、不可解密或无效的受保护状态必须先获得明确确认，才允许替换。实现只支持本地静态操作和人工指引，不发起 API 调用，也不默认访问 OpenAI API。

DPAPI 不能抵御已经控制同一 Windows 用户会话的程序；主机时钟、路径别名或文件移动可能重新打开发现，但不会扩大处置范围。路径检查与 `os.replace` 之间仍有同用户竞态窗口，Python 不能保证清除所有不可变 bytes 或字符串副本，静态自审计只覆盖有界源码策略，不是对依赖或二进制的语义证明。Batches 4-6 仍待完成，当前产品仍为非生产 Founder Alpha，Windows MVP 尚未完成。

## Batch 4 Local Implementation Status

Task 1-8 已在本地实现。每次扫描都需要与当前范围绑定的明确同意，范围预览不遍历目录，扫描启动会再次校验并消费同意。覆盖状态固定为 `complete`、`limited` 和 `no_supported_files`，不完整结果不能用于确认安全。筛选仅影响界面可见行，导出仍包含完整当前审计，不改变 finding、分数、报告、处置或受保护状态。

报告比较仅支持 JSON 和用户显式选择的不超过 2 MiB 的本地普通文件。JSON 导出与导入共享最多 2,000 个 findings、4,000 条 evidence 和 2 MiB UTF-8 的预算。Renderers take required keyword-only `evaluated_at` with no hidden clock; identical inputs including that timestamp are byte deterministic. After bounded materialization they recompute the technical and reviewed scores exactly from findings, verified dispositions, and the declared coverage options; an omitted reviewed score uses the recomputed value. 新 report schema 1 使用规范 UTC 秒级 `evaluated_at` 绑定处置状态和复核分；缺少该字段的旧 schema 1 与 legacy schema 0 仅兼容全 `open` 报告，不可验证的非 `open` 处置失败关闭。规则版本、cap reason 和规则 ID 使用解析器兼容的安全校验；长 basename 省略显示且 tooltip 不含目录。校验不证明报告真实性。聚合比较结果只在内存中瞬态保留，不匹配单个 finding，不导出稳定的跨扫描 finding 标识符，也不保留完整路径或逐项证据。显式读取一个基线文件不会增加环境目录扫描、网络、API 调用或写入能力。

已知残余限制包括同一用户控制、路径竞态、主机时钟、路径别名、聚合碰撞，以及静态自审计不覆盖依赖和二进制。2026-08-03 的 Task 9 证据提交 `991bf81bb520e7f2ec12f331fbbe714f03212507` 在 Python 3.14 和以锁定 wheel 临时隔离的 Python 3.12 环境中均记录为 `1174 passed, 8 skipped, 0 failed`；自审均为 `findings=[]`、`local_only=true`、`network_capability=not_detected`。2026-08-13，Task 10 当前复审实现 `d1c3e9caa856812d0bdd3221b0c6a7083da937ff` 的独立规格复审和独立安全/质量复审均为零发现。Python 3.14.0 和使用 `requirements-dev.lock` 哈希锁定依赖临时隔离的 Python 3.12.2 完整门禁均为 `1264 passed, 8 skipped, 0 failed`。远程实现与证据基线 `a79995a7a6a950050d5628324f94a6b8a07e6308` 的本地 Python 3.14/3.12 完整门禁均为 `1269 passed, 8 skipped, 0 failed`；push run `31714716636` 和 Draft PR run `31714721274` 均成功且各记录 `1277 passed`。该实现基线之后的文档/测试证据同步提交不由上述运行自动覆盖。

Batch 5 便携开发包层已完成本地验证。实现证据绑定 `10e65322cd590f2028fb5946fff7125afd2e101d`：两个全新输出目录中的 208 个文件逐项一致，确定性 ZIP SHA-256 均为 `216936f89d9a8b8352e3a58ce8c2602dbb26e7d450ddfcb0959d289e0755ef7b`；SBOM 将嵌入 EXE 的 PyInstaller Bootloader 记录为运行时依赖，隔离副本的 GUI 存活、受控终止与声明目录零残留已通过。该产物是附带 SBOM、清单和校验和的未签名开发产物。当前本地提交尚未获得 GitHub CI 验证。可信代码签名、原生安装、干净机器验收和卸载残留检查仍未完成；Batch 6 仍待完成，Windows MVP 尚未完成，未形成生产安全结论。

**Batch 6 local gate status.** 实现与统一本地证据基线 `392ff64f3bcb3f978874e668a97e5a3f013b762e` 新增并修复了 AG-T01 至 AG-T12 威胁模型、隔离精选安全门禁、双 Python 固定合成性能门禁、lock 依赖快照和 portable smoke 持久证据；该增量不修改产品运行时。独立只读复审已完成并发现 7 项 Important findings，修复后复审仍待完成。当前本地证据只支持这些门禁的实现和运行，不支持远程或外部发布验收。Release-candidate decision: `NO-GO`. Windows MVP remains incomplete. Production safety is not established.

## Completed Batch: OpenAI Local Provider Hardening

### Task 1: Lock the OpenAI Detection Contract

**Files:**
- Modify: `tests/test_detectors.py`
- Modify: `tests/test_discovery.py`
- Modify: `tests/test_guidance.py`
- Modify: `tests/test_app_smoke.py`

- [x] **Step 1: Add a failing rule-contract test**

Require rule bundle `1.1.0` to contain `OPENAI_BASE_URL_OVERRIDE` in the supply-chain domain with low severity. A synthetic `OPENAI_BASE_URL` assignment must produce fixed masked evidence and an HMAC fingerprint without retaining the endpoint.

```python
def test_openai_base_url_override_is_masked() -> None:
    endpoint = "https://synthetic-provider.invalid/v1"
    finding = detect_text(
        f"OPENAI_BASE_URL={endpoint}",
        ".env",
        scan_key=SCAN_KEY,
    )[0]

    assert finding.rule_id == "OPENAI_BASE_URL_OVERRIDE"
    assert finding.domain is RiskDomain.SUPPLY_CHAIN
    assert finding.severity is Severity.LOW
    assert finding.evidence[0].masked == "OpenAI API base URL override configured"
    assert endpoint not in repr(finding)
```

- [x] **Step 2: Add failing integration tests**

Require `%USERPROFILE%\.codex` to be a known config root; require `.env` and `.toml` to be scanned; require `OPENAI_API_KEY` and `OPENAI_BASE_URL_OVERRIDE` findings to display OpenAI-specific manual guidance.

- [x] **Step 3: Verify the red state**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_detectors.py tests/test_discovery.py tests/test_guidance.py tests/test_app_smoke.py`

Expected: failures show missing rule `OPENAI_BASE_URL_OVERRIDE`, missing `.codex` root, unsupported `.env`/`.toml`, or generic guidance.

### Task 2: Implement the Minimum Local Adapter

**Files:**
- Modify: `rules/default.json`
- Modify: `src/agentguardian/detectors.py`
- Modify: `src/agentguardian/discovery.py`
- Modify: `src/agentguardian/guidance.py`
- Modify: `src/agentguardian/app.py`

- [x] **Step 1: Add the endpoint-override rule**

Add `OPENAI_BASE_URL_OVERRIDE` with a named URL match, `supply_chain` domain, `low` severity, and `endpoint` kind. Bump the rule bundle to `1.1.0`.

```json
{
  "rule_id": "OPENAI_BASE_URL_OVERRIDE",
  "domain": "supply_chain",
  "severity": "low",
  "kind": "endpoint",
  "pattern": "(?im)^\\s*(?:OPENAI_BASE_URL|openai_base_url)\\s*[:=]\\s*[\\\"']?(?P<value>https?://[^\\s\\\"'#]+)",
  "match_group": "value"
}
```

- [x] **Step 2: Mask endpoint evidence with fixed text**

Permit `endpoint` in rule validation and return exactly `OpenAI API base URL override configured` from `_mask`. The endpoint remains only as input to the scan-scoped HMAC.

- [x] **Step 3: Cover local OpenAI config surfaces**

Add `%USERPROFILE%\.codex` to known roots. Add `.env` and `.toml` to the UI's bounded suffix set. Do not auto-select or auto-scan any directory.

- [x] **Step 4: Route OpenAI findings to manual guidance**

For rule IDs beginning with `OPENAI_`, pass `provider="openai"` to `guidance_for`. Add a dedicated manual checklist for `OPENAI_BASE_URL_OVERRIDE`: confirm endpoint ownership, restore the built-in provider or document an approved exception, rotate credentials if an untrusted endpoint received them, and rerun the read-only audit.

- [x] **Step 5: Verify the green state**

Run: `python -B -m pytest -q -p no:cacheprovider tests/test_detectors.py tests/test_discovery.py tests/test_guidance.py tests/test_app_smoke.py`

Expected: all focused tests pass; no raw endpoint or credential appears in finding, guidance, or report text.

### Task 3: Synchronize Status and Security Evidence

**Files:**
- Modify: `README.md`
- Modify: `docs/reports/alpha-0.1.0-stage-report.md`
- Modify: `docs/superpowers/specs/2026-08-01-agentguardian-design.md`
- Modify: `tests/test_self_audit.py`

- [x] **Step 1: Add failing documentation assertions**

Require the README and stage report to name Windows MVP hardening batch 1, describe endpoint overrides as review findings rather than proof of malicious ownership, and state that no API call or endpoint verification occurs.

- [x] **Step 2: Update status documents**

Link this plan from the README. Record batch 0 as complete and batch 1 as the current verified increment. Keep the explicit Founder Alpha and non-production-safe labels.

- [x] **Step 3: Run the complete local gate**

Run: `python -B -m pytest -q -p no:cacheprovider`

Run: `python -B scripts/check_brand_assets.py`

Run: `python -B -m compileall -q src`

Run: `git diff --check`

Expected: zero test failures, brand validator exit 0, compile exit 0, and no whitespace errors.

- [x] **Step 4: Review the source-capability boundary**

Confirm `collect_self_audit()` still reports no network, LLM, telemetry, updater, shell, clipboard, or unexpected user-data-write capability. Confirm all tests use synthetic values.

- [x] **Step 5: Commit and push the verified batch**

Run: `git add rules/default.json src/agentguardian tests README.md docs/superpowers docs/reports`

Run: `git commit -m "Harden local OpenAI provider detection"`

Run: `git push origin agent/founder-alpha`

Remote CI success is reported separately from the local gate. A green batch does not complete the remaining Windows MVP roadmap.
