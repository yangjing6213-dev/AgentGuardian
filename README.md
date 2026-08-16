![AgentGuardian](assets/brand/agentguardian-cover.svg)

# AgentGuardian

## Current control-core status

- Personal v1 is a local, static audit product for explicitly selected Windows data. It retains static detectors, local scoring, redacted reports, and the explicitly declared public-share verifier only.
- Enterprise policy, service, control-plane, signing, and adapter runtime modules are removed and unsupported. Personal v1 has no enterprise administration page, tenant service, remote enrollment, or hosted policy distribution.
- High-sensitivity product mode and dynamic MCP execution are unsupported. Historical implementation and test references below are not current Personal v1 capabilities or release evidence.
- Personal v1 only parses MCP configuration as local static data. It flags a server that combines shell, filesystem-write, and network capabilities as `MCP_DANGEROUS_COMBINATION`; findings retain only masked evidence and local fingerprints.
- Personal v1 permanently excludes MCP runtime integration. It does not download, load, launch, broker, isolate, sign, package, or execute MCP extensions or user-selected executables, and there is no disabled compatibility route.
- Historical pre-removal validation for implementation/test revision `1da903465f463d1421e7af2b20971da3d8c149bd` recorded `1563 passed, 11 skipped`; those runs covered the deleted MCP runtime surface and are not current Personal v1 evidence. Exact-SHA push CI `31929152189`, push Windows `31929152263`, Draft PR CI `31929154481`, and Draft PR Windows `31929154483` remain historical only.
- The browser audit now snapshots approved SQLite `-wal`, `-shm`, and `-journal` sidecars read-only under one total size cap, while retaining fixed counts only. Clipboard auditing now requires an explicit one-time Yes/No confirmation and returns before reading on cancel. The acceptance script supports an absolute, local, non-reparse user-supplied sanitized sample via `--sample-root`; the sample is scanned for acceptance evidence but its path and contents are excluded from JSON, HTML, and export output.
- Portable builds retain clean exact-HEAD checks, reproducible PyInstaller output, SBOM, notices, provenance, checksums, payload manifests, source-policy layout validation, and non-elevated execution. No MCP payload or runtime metadata is accepted or emitted.
- The release gate currently validates bundle path safety, exact source SHA, trusted package signature evidence when requested, fresh-user-state evidence, SBOM and notices, and license review. It does not read `SHA256SUMS` or `PAYLOAD-MANIFEST.json`. Standalone checksum and release-manifest binding remains pending Store-candidate work. MSIX verification retains install, launch, same-identity upgrade, process termination, uninstall, app-data residue checks, and sanitized evidence.
- The final release gate now additionally requires an approved `windows-license-review.json` bound to the exact source commit and SBOM SHA-256, with one reviewed record per CycloneDX component. The repository worksheet remains `pending`; it is a preparation artifact, not legal approval or a release claim.
- Release evidence inputs are now rejected when relative, symlinked, UNC, or reparse/junction-backed, so the source/SBOM/smoke/license binding cannot silently follow a redirected path.
- The desktop flow now exposes one allowlisted fixed remediation for `OPENAI_BASE_URL_OVERRIDE`: preview, scope check, explicit confirmation, target hash recheck, atomic replacement, same-directory backup, and same-session rollback. It does not execute arbitrary commands or generate edits with an LLM.
- The deleted signed-package workflow is not release evidence. Store candidate automation, trusted signing, approved `windows-license-review.json`, real sanitized-sample human signoff, and independent clean-machine install/upgrade/run/uninstall evidence remain pending for later tasks. Remote enterprise console, device enrollment, and distribution remain unimplemented.
- Residual work includes evidence-output parent-path TOCTOU and synchronous AppX operations bounded only by workflow timeout. No production safety, support for highly sensitive real-world data, or legal approval is claimed.
- Fresh verification for code SHA `6c0043b5dc3551d4950f814a82a4c7484004d722`: local `1377 passed, 11 skipped`; push and Draft PR CI plus Windows package runs all succeeded (`31873363929`, `31873363921`, `31873365733`, `31873365732`). The Windows evidence remains unsigned CI smoke only.
- Previous fixed-remediation slice SHA `20cac6c6b9c8384ba298e07b534d2186d9ec65ca`: local `1383 passed, 11 skipped`; its push CI, push Windows, Draft PR CI and Draft PR Windows all succeeded. The Windows evidence remains unsigned CI smoke only.
- Previous high-sensitivity network-boundary slice SHA `f7ca1c5b8c1c1e896950d9998cbc5576dea72c5c`: local `1390 passed, 11 skipped`; its push CI, push Windows, Draft PR CI and Draft PR Windows all succeeded. That removed historical mode is not part of Personal v1, and its old share-verification behavior is not current product evidence.
- Previous MSIX acceptance slice SHA `0ac5ff748f16578a86a3662b8fddd8f6fb94def3`: local `1391 passed, 11 skipped`; its push CI, push Windows, Draft PR CI and Draft PR Windows all succeeded. Windows evidence recorded install, launch, same-identity upgrade `0.1.0.0 -> 0.1.0.1`, termination, uninstall, and `package_residue=false`; signature mode remained `unsigned_ci_smoke`.
- Previous verification for code SHA `6829f25f70294161c6b4efe4392fa8417e0edc56`: local `1396 passed, 11 skipped`; push CI, push Windows, Draft PR CI and Draft PR Windows all succeeded (`31878697776`, `31878697703`, `31878698579`, `31878698586`). GitHub Windows full suite reported `1406 passed, 1 skipped`; the synthetic high-sensitivity gate reported `passed=true`, no raw marker in JSON/HTML/export/findings, browser temporary copy removed, and workspace cleanup true. The MSIX evidence recorded install, same-identity upgrade `0.1.0.0 -> 0.1.0.1`, termination, uninstall, and `package_residue=false`; signature mode remained `unsigned_ci_smoke`.
- Previous verification for code SHA `253b77d1f46b63f1761fd8ac56c9fb6f49555d22`: local `1404 passed, 11 skipped`; push CI, push Windows, Draft PR CI and Draft PR Windows all succeeded (`31881025303`, `31881025442`, `31881028230`, `31881028238`). GitHub Windows full suite reported `1414 passed, 1 skipped`; the then-current synthetic privacy gate reported `passed=true`, raw markers absent from JSON/HTML/export/findings, browser temporary copy removed, and workspace cleanup true. That historical gate predates the Personal v1 acceptance and does not establish support for highly sensitive real-world data. The Windows package evidence recorded install, same-identity upgrade `0.1.0.0 -> 0.1.0.1`, termination, uninstall, and `package_residue=false`; the package remains `unsigned_ci_smoke`. This is historical package-smoke evidence, not production safety.

**AI Agent 守护者（AG）** 是一款面向 Windows 个人用户和小团队的本地优先 AI Agent 数据安全审计工具。

当前版本为 `0.1.0 Founder Alpha`。Windows 本地只读发现、敏感数据与 MCP 静态检测、可解释评分、脱敏 JSON/HTML 报告、人工修复指引、桌面界面和保守自审计已经形成合成数据闭环。本版本仍是内部 Alpha，不代表生产安全等级。

## 为什么可以信任

- Founder Alpha 以普通用户权限运行，不提权、不执行修复、不修改扫描目标。
- 包源码策略检查明确标记受限的联网分享适配器；未发现遥测、LLM、更新器或动态插件模块。该结论不覆盖依赖和二进制。
- 完整聊天、完整凭据、完整路径和完整分享链接不得进入普通报告。
- 证据只保留短显示名、脱敏摘要和扫描级 HMAC 指纹。
- 跨扫描处置使用独立的本地 HMAC 引用；该引用和密钥不进入报告或界面。
- 修复默认提供人工步骤；唯一桌面固定动作必须预览、确认、目标重查、备份和回滚，其他修复仍显示为人工步骤。
- 自审计固定返回规则 SHA、Python 版本、权限状态、能力 findings 和未覆盖范围。
- 扫描规则、评分、报告格式和安全边界在公开仓库中接受检查。

安全分数必须与审计覆盖率、证据置信度、限制项一起阅读。`100` 分只表示在用户选择的范围内没有发现当前规则可识别的问题，不等于绝对安全。

## Founder Alpha 范围

已实现：

- 用户明确选择的本地目录和少量已知 Windows AI 配置位置。
- 常见密钥、基础隐私数据、个人定制关键词和 MCP 危险权限组合的本地静态检查。
- 可解释的六领域评分，以及只含脱敏证据的本地 JSON/HTML 报告。
- 带原因、复核人和有限有效期的本地误报/接受风险处置，以及技术分和复核分。
- 范围、发现、报告三个页面组成的极简 PySide6 桌面流程。
- 用户确认产品边界和当前范围后逐项选择的 Chrome/Edge/Firefox 浏览器数据库元数据只读审计；只保留固定计数，不保留 URL、Cookie、密码或页面正文。
- 用户确认产品边界和当前范围后一次性点击触发的剪贴板内存检测；只保留脱敏 findings，不写回、不保存原文。
- 独立的公开 HTTP(S) 分享可达性验证；只读取受限公开响应，不发送扫描文件、凭据或聊天内容。
- Personal v1 不支持高敏感现实数据，不提供对应的产品模式或就绪证据。JSON、HTML 和导出报告仍只保留脱敏证据；剪贴板原文不留存、浏览器临时副本删除和临时工作区清理均有验收测试。联网分享验证仅在用户显式输入公开 URL 后执行，只读取受限公开响应且不发送任何审计数据；报告导出由用户显式选择保存路径，并保留 UNC、reparse、父目录稳定性、扫描根目录外和独占创建保护。
- 受控自动修复内核的固定单文件替换动作：dry-run、显式确认、目标哈希重查、同目录备份、原子替换和条件回滚；不执行任意命令。
- 桌面端对 `OPENAI_BASE_URL_OVERRIDE` 提供受限固定地址替换和同会话回滚；修改后旧报告失效，必须重新审计。

明确不包含：密钥自动撤销、云同步、远程企业控制台、MCP 动态执行，以及生产级安全承诺。桌面本地管理页只覆盖离线租户/设备/角色/策略状态，不等于远程企业服务。MCP 配置仅作为静态数据解析，不下载、不加载、不启动、不代理、不隔离、不签名、不打包、不执行任何 MCP 扩展或用户选择的可执行文件；浏览器数据库与剪贴板能力仍默认关闭且需要用户逐项触发；联网分享验证不判断链接内容、分享权限或搜索引擎收录安全。固定修复桌面流程尚未完成签名包、独立干净机器、真实 Windows 权限和竞态验收。UNC 路径被拒绝；映射网络盘无法可靠识别，属于已知残余风险。

## Windows MVP 硬化进度

供应链基线批次已完成 GitHub Actions commit SHA 固定、Node.js 24 Action 运行时刷新和 Windows Python 依赖哈希锁定。Windows MSIX 验收器现已覆盖干净 runner 前置检查、安装、启动、同身份高版本升级、终止、卸载和残留检查；Store 候选和正式签名流程留待后续任务。**OpenAI Provider 本地适配批次**也已完成：覆盖 `%USERPROFILE%\.codex` 已知配置目录、`.env`/`.toml` 静态扫描、`OPENAI_API_KEY` 脱敏发现、`OPENAI_BASE_URL`/`openai_base_url` 覆盖配置提示，以及 OpenAI 专用人工修复指引。

端点覆盖发现只表示该配置需要人工复核，不证明端点属于恶意第三方。AgentGuardian 只在用户授权的本地范围读取静态配置，不发起 API 调用或联网验证端点，也不自动修改 Provider、撤销密钥或轮换凭据。

**DPAPI 保护的本地证据状态批次**已实现当前 Windows 用户范围 DPAPI、最小化快照、原子替换和损坏状态失败关闭。只有用户点击“保存加密状态”才会写入；扫描、启动和报告导出都不会自动保存状态。状态只使用固定规则摘要，不复制 detector 的自由文本；不保存原始匹配、扫描密钥、完整路径或证据来源文件名。版本化 SHA-256 完整性封装、DPAPI、JSON 和 schema 任一验证失败时返回固定 `PROTECTED_STATE_INVALID`。

DPAPI 不能抵御已经控制同一 Windows 用户会话的程序，状态也不能跨用户或跨设备恢复。路径检查与最终 `os.replace` 之间仍存在同用户可利用的竞态窗口；当前批次通过祖先 reparse/UNC 重查缩小风险，但未实现句柄级目录约束。该功能不发起 API 调用、不增加云同步或自动修复，当前 Founder Alpha 仍不代表 Windows MVP 完成或生产安全。

**发现处置与到期例外 Batch 3 状态。** Batch 3 本地实现、自动门禁、独立安全复审和最终 SHA 远程验收已完成。跨扫描精确匹配只使用规则 ID、按 Windows 词法规则规范化的源路径，以及 NFKC 规范化的原始匹配。Windows 路径按 `ntpath.abspath`、`ntpath.normpath`、`ntpath.normcase` 处理，不做 Unicode 规范化。本地处置 HMAC 密钥与每次扫描随机生成的报告 HMAC 密钥彼此独立；报告 HMAC 仍限定于单次扫描，本地引用和密钥不导出。

每项处置都需要原因、复核人和到期时间，处置有效期必须有限且不超过 366 天。有效误报只从复核分排除；接受风险仍计入复核分；技术分不受处置影响。受保护状态保持 schema v1 只读兼容，只有显式保存才迁移到 schema v2。损坏、不可解密或无效的受保护状态必须先获得明确确认，才允许替换。

该能力只提供本地静态操作和人工指引，不发起 API 调用，也不默认访问 OpenAI API。主机时钟、路径别名或文件移动可能重新打开发现，但不会扩大处置范围。Python 不能保证清除所有不可变 bytes 或字符串副本；静态自审计只覆盖有界源码策略，不是对依赖或二进制的语义证明。当前状态仍是非生产 Founder Alpha；Batches 4-6 仍待完成。

**工作流与报告硬化 Batch 4 当前状态。** Task 1-8 已在本地实现；Task 9 保留按 SHA 绑定的历史本地证据；Task 10 的本地独立复审和双 Python 完整门禁已绑定 `d1c3e9caa856812d0bdd3221b0c6a7083da937ff`。远程实现与证据基线 `a79995a7a6a950050d5628324f94a6b8a07e6308` 已由精确绑定的 push 与 Draft PR 运行验证；后续文档/测试证据同步提交必须单独验证。独立规格复审和独立安全/质量复审中 Critical、Important、Minor 均为 0。每次扫描都需要与当前范围绑定的明确同意；范围变化会撤销同意并清除旧结果，扫描启动前会再次校验并消费本次同意。范围预览不遍历目录，只显示短名称、支持的选择器和固定扫描上限。

覆盖结果明确分为 `complete`、`limited` 和 `no_supported_files`。不完整结果不能用于确认安全；`complete` 也只表示配置范围完成，不能证明系统、账户、Provider 或端点安全。严重性、风险领域和处置状态筛选仅影响界面可见行，导出仍包含完整当前审计，分数、受保护状态和报告内容不会因筛选改变。

报告比较仅支持 JSON，由用户显式选择不超过 2 MiB 的本地 AgentGuardian 报告。JSON 导出与导入共享最多 2,000 个 findings、4,000 条 evidence 和 2 MiB UTF-8 的预算；HTML 共享前两项数量上限。新 report schema 2 固定写入 `supported_use_boundary=personal_non_regulated_configuration` 和规范 UTC 秒级 `evaluated_at`；`evaluated_at` 是无默认值的 keyword-only 必填参数，生成器不读取隐藏时钟，相同输入（包括该时点）必须生成逐字节相同的 JSON 和 HTML。生成器先有界物化 findings 和处置，再以声明分数的 coverage、confidence、limits 精确复算技术分和复核分；省略 reviewed score 时使用复算值，任何声明矛盾固定失败。schema 2 导入按同一时点重新验证每项非 `open` 处置及复核分；旧 schema 1 和 legacy schema 0 仅在所有处置均为 `open`、复核分可独立重算时兼容。解析摘要保留 schema 与边界验证状态；历史基线明确标记边界未验证，界面仅比较聚合数据。规则版本、cap reason 和规则 ID 使用与解析器一致的安全元数据契约。聚合比较结果只在内存中瞬态保留，不保存完整路径、原始 JSON、证据、指纹或处置详情；长基线文件名只在界面省略显示，tooltip 仅含完整 basename。校验不证明报告真实性，也不匹配单个 finding，不导出稳定的跨扫描 finding 标识符。显式读取一个基线文件不会增加环境目录扫描、网络、API 调用或写入能力。

残余限制包括同一用户控制、路径竞态、主机时钟、路径别名、聚合碰撞，以及静态自审计不覆盖依赖和二进制。2026-08-03 的 Task 9 证据提交 `991bf81bb520e7f2ec12f331fbbe714f03212507` 记录了 Python 3.14 和隔离的 Python 3.12 完整门禁均为 `1174 passed, 8 skipped, 0 failed`；该结果是绑定该提交的历史证据，不是当前 HEAD 的新鲜完整门禁。8 项真实 symlink 用例当时因本机 symlink 创建权限不足而跳过，junction 已测试；这些 skip 不算对应 symlink 场景通过。

2026-08-13，`d1c3e9caa856812d0bdd3221b0c6a7083da937ff` 在 Python 3.14.0 和使用 `requirements-dev.lock` 哈希锁定依赖临时隔离的 Python 3.12.2 中均重新验证为 `1264 passed, 8 skipped, 0 failed`；`tests/test_self_audit.py tests/test_packaging.py` 聚焦门禁为 `152 passed`。两个解释器的品牌校验、源码编译和 package-source self-audit 均通过。该 SHA 之后的文档/测试证据同步提交不由这些本地结果自动覆盖。远程实现与证据基线 `a79995a7a6a950050d5628324f94a6b8a07e6308` 的 push run `31714716636` 与 Draft PR run `31714721274` 均为 `SUCCESS`；该实现基线的本地 Python 3.14/3.12 门禁均为 `1269 passed, 8 skipped, 0 failed`。

**Batch 5 便携开发包层已完成本地验证（历史快照）。** 实现证据绑定 `10e65322cd590f2028fb5946fff7125afd2e101d`：使用哈希锁定的 Windows Python 3.12 构建环境生成 PyInstaller `onedir` 未签名开发产物、CycloneDX 1.6 SBOM、载荷清单、构建元数据、第三方声明、校验和与确定性 ZIP；SBOM 将嵌入 EXE 的 PyInstaller Bootloader 记录为运行时依赖，并把 PyInstaller 工具保留为构建时组件。两个全新输出目录的 208 个文件逐项一致，ZIP SHA-256 均为 `216936f89d9a8b8352e3a58ce8c2602dbb26e7d450ddfcb0959d289e0755ef7b`；复制后的 GUI 离屏存活 4 秒、受控终止且声明目录零残留。当前本地提交尚未获得 GitHub CI 验证。可信代码签名、原生安装、干净机器验收和卸载残留检查仍未完成；Batch 6 仍待完成，Windows MVP 尚未完成，未形成生产安全结论。

**Batch 6 local gate status（历史快照）。** 当前实现与统一本地证据基线为 `90e6edad53bee48adca58d508d193fc855c1db7d`；它补强了门禁环境隔离、collection/runtime skip fail-closed、性能/构建 SHA 复核、lock 依赖绑定和 portable smoke 进程树确认。首轮独立只读复审发现 7 项 Important findings、2 项 Minor；第二轮又发现 2 项 Important findings、3 项 Minor；聚焦第三轮复审未发现 Critical/Important、记录 1 项 Minor，当前已识别的 Important 均已修复。该增量未修改 `src/agentguardian`，OpenAI Provider 仍只做本地检测与人工指引，不默认调用 API。当前精确 SHA 的 GitHub CI、fresh-runner provenance、可信签名、原生安装/卸载和许可复核仍待完成。Release-candidate decision: `NO-GO`. Windows MVP remains incomplete. Production safety is not established.

## 开发与验证

```powershell
python -m pip install -e ".[dev]"
pytest -q
python scripts/check_brand_assets.py
python -m agentguardian
```

项目按失败测试、最小实现、规格审查、代码质量审查、原子提交的顺序推进。测试只使用合成数据；视频、转写、浏览器记录、本机密钥和真实审计证据不会提交到仓库。

## 文档

- [Founder Alpha 实施计划](docs/superpowers/plans/2026-08-01-agentguardian-founder-alpha.md)
- [Windows MVP 硬化实施计划](docs/superpowers/plans/2026-08-02-agentguardian-windows-mvp-hardening.md)
- [Windows MVP 威胁模型](docs/security/windows-mvp-threat-model.md)
- [Historical Windows MVP release-candidate snapshot](docs/reports/windows-mvp-release-candidate-report.md) - exact-SHA retired implementation evidence, not current release evidence.
- [Windows MVP Batch 6 实施计划](docs/superpowers/plans/2026-08-14-agentguardian-windows-mvp-release-candidate.md)
- [产品完成与交付计划](docs/superpowers/plans/2026-08-15-agentguardian-product-completion.md)
- [DPAPI 证据状态实施计划](docs/superpowers/plans/2026-08-02-agentguardian-protected-evidence-state.md)
- [DPAPI 证据状态设计](docs/superpowers/specs/2026-08-02-agentguardian-protected-evidence-state-design.md)
- [发现处置实施计划](docs/superpowers/plans/2026-08-02-agentguardian-finding-dispositions.md)
- [发现处置设计](docs/superpowers/specs/2026-08-02-agentguardian-finding-dispositions-design.md)
- [产品与安全设计规范](docs/superpowers/specs/2026-08-01-agentguardian-design.md)
- [系统架构与数据流](docs/architecture.md)
- [Founder Alpha 阶段报告](docs/reports/alpha-0.1.0-stage-report.md)

## 品牌

中文名称：AI Agent 守护者

英文名称：AgentGuardian

英文缩写：AG

品牌源文件和导出资产位于 [`assets/brand`](assets/brand)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
