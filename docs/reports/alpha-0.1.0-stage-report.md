# AgentGuardian 0.1.0 Founder Alpha 阶段报告

报告日期：2026-08-01

分支：`agent/founder-alpha`

状态：Founder Alpha 发布门禁通过（内部 Alpha）

## 1. 阶段目标

在 Windows 普通用户权限下形成一个可验证的本地只读审计闭环：发现用户授权范围内的 AI 相关文件，检测合成敏感数据和 MCP 危险权限组合，计算可解释安全分数，生成脱敏报告，并提供不执行动作的人工修复指引。

Founder Alpha 不访问浏览器数据库、浏览器历史或剪贴板，不联网验证分享状态，不包含遥测、LLM、更新器、动态插件、提权、自动修复或回滚。

## 2. 已交付能力

- 冻结的 `Asset`、`Evidence`、`Finding`、`Score`、`RemediationPlan` 和 `VerificationResult` 契约。
- 有界 Windows 本地文件发现，拒绝稳定 symlink/junction/reparse 越界。
- 密钥、基础隐私、定制关键词和 MCP 危险组合静态检测。
- 扫描级 HMAC-SHA256 证据指纹、短来源名和脱敏证据。
- 六领域可解释评分、根因去重、39/59 分硬封顶、覆盖率和 incomplete 状态。
- 标准库 JSON/HTML 报告；仅允许用户选择位置后独占新建，拒绝覆盖和扫描根内导出。
- 人工修复步骤，验证状态固定为 `not_performed`。
- 三页 PySide6 桌面流程：审计范围、风险发现、审计报告。
- Windows CI、自审计源码策略、品牌资产校验和 clean-tree 门禁。

## 3. 验收证据

最新本地发布门禁：

- `rtk pytest -q`：`236 passed, 5 skipped`。
- `rtk python scripts/check_brand_assets.py`：退出码 0。
- `rtk proxy python -m compileall -q src`：退出码 0。
- 本轮新增文件 Ruff 检查：退出码 0。
- `rtk git diff --check`：退出码 0。
- Task 7 规格与代码质量审查：通过。
- Task 8A 规格与代码质量审查：通过。
- 最终全仓只读安全复核：`APPROVED / GO`；两个发现阶段 P2 已关闭并复审通过。
- GitHub Actions：2/2 checks passed，0 failed。

五项 skip 均与普通 Windows 用户无法创建测试 symlink 有关；Windows junction 测试已执行通过。skip 不被计为对应 symlink 场景的验证证据。

## 4. 自审计结果

自审计固定字段结果：

- 版本：`0.1.0`
- 规则 SHA-256：`f3ad7370e9792b81968bbc8c895d1a7093f190d794452a96b8c52fd59fcbfd36`
- 普通用户模式：`true`
- 源码策略 findings：空
- 网络能力：`not_detected`
- `local_only`：`false`
- 能力范围：`package_source_policy`
- 语义分析：`not_performed`
- 依赖和二进制：`not_scanned`
- 映射网络盘：`not_reliably_detected`

`not_detected` 仅表示当前包源码遵守固定能力策略，不表示依赖、二进制或操作系统路径绝对没有网络能力。自审计因此不会把自身标记为 `local_only=true`。

## 5. 信任设计

- 默认普通用户、只读扫描、无自动修复。
- 报告只含掩码证据；测试只使用运行时构造的合成敏感值。
- 自审计失败关闭：危险导入返回固定 capability code，敏感别名、重绑定和模糊写 API 返回 `SOURCE_POLICY_VIOLATION`。
- UI 明示包源码检查范围、依赖未覆盖和映射网络盘残余风险。
- 所有发布门禁、规则、评分和报告实现可在公开仓库复核。

## 6. 已知限制与安全债务

- 仅支持 Windows Founder Alpha；未生成安装包、代码签名、SBOM 或正式发布物。
- 自审计是源码策略检查器，不是完整 Python 语义分析器，也不扫描依赖和二进制。
- UNC 路径被拒绝；映射网络盘仍无法可靠识别。
- 报告导出未实现目录句柄相对创建；主动本地 reparse replacement race 仍是 Alpha 残余风险。
- GitHub Actions 已固定到 commit SHA；Windows CI Python 依赖已通过 `requirements-dev.lock` 锁定哈希。
- Python 3.12 GitHub-hosted CI 已通过；本地门禁运行于当前开发解释器。
- 自动修复、回滚、联网验证和自动复审均未实现。
- GitHub Milestone/Issue 创建及 Draft PR 标题/正文更新被当前凭据权限阻止：`Resource not accessible by personal access token`。代码推送、现有 Draft PR 读取和 CI 正常。

## 7. 阶段决策

当前为 **GO（内部 Founder Alpha）**：本地发布门禁、GitHub CI、Task 7/8 双阶段审查和最终全仓只读安全复核均已通过。该结论只允许标记为内部 `0.1.0 Founder Alpha`，不允许表述为生产安全、公开稳定版或自动修复产品；第 6 节限制和安全债务继续有效。

## 8. Windows MVP 硬化续接

本报告第 1 至 7 节记录 Founder Alpha 历史门禁；其中测试计数、规则 SHA 和 CI 结果不自动代表后续提交已重新验证。Windows MVP 硬化从 2026-08-02 起按独立批次继续：供应链基线与 OpenAI Provider 本地适配、检测和人工指引批次已完成。下一批为 DPAPI 保护的本地证据状态，目前尚未实现。

当前增量覆盖 `%USERPROFILE%\.codex`、`.env` 和 `.toml`，识别 `OPENAI_API_KEY` 与 `OPENAI_BASE_URL`/`openai_base_url` 覆盖配置。端点覆盖发现只表示配置需要人工复核，不证明端点属于恶意第三方。实现不导入 OpenAI SDK 或网络客户端，不发起 API 调用或联网验证端点，不读取或输出真实密钥，不自动修改 Provider 或凭据。

本批次验收必须重新运行全量测试、品牌校验、源码编译、自审计能力检查和差异检查；通过后仍只代表 Windows MVP 硬化中的一个可验证增量，不改变非生产安全结论。

2026-08-02 当前工作树重新验证结果：

- `python -B -m pytest -q -p no:cacheprovider`：`245 passed, 5 skipped`。
- `python -B scripts/check_brand_assets.py`：退出码 0。
- `python -B -m compileall -q src`：退出码 0。
- `git diff --check`：退出码 0。
- 自审计：`network_capability=not_detected`、`findings=[]`、`local_only=false`。
- 当前规则 SHA-256：`83a14590d59f61a3c6aede084644fdbbd9f5cff6f55794b9af60e385e053ccba`。
- 独立只读代码复审：首轮 `With fixes` 的两项 Important 和一项 Minor 已关闭；最终结论 `Ready`，无剩余问题。
- CI Action Node.js 24 运行时刷新提交：`fb01c2a51a57c1f2ad87e486f0a4cfe280b8392b`。
- GitHub CI：push run `30712075199` 与 PR run `30712076712` 均成功；两个 check-run 的 annotations 均为 0，先前 Node.js 20 弃用告警已消失。

本地门禁与 GitHub CI 为不同证据面；以上远程结果只覆盖所列提交和运行，不自动代表后续提交或整个 Windows MVP 已通过。

## 9. Windows MVP 硬化 Batch 2：受保护证据状态

Batch 2 在 Founder Alpha 之上增加当前 Windows 用户范围 DPAPI 状态：最小 schema 只保留规则 ID、固定规则摘要、扫描元数据和扫描级 HMAC 引用，不复制 detector 自由文本；不保存原始匹配、扫描密钥、完整路径或证据来源文件名。文件层使用固定本地文件名、1 MiB 上限、全部现存祖先 reparse/symlink 拒绝、解析后 UNC 重查、同目录临时文件和原子替换。密文内另有版本化 SHA-256 完整性封装，损坏或不兼容状态统一失败为 `PROTECTED_STATE_INVALID`。

只有用户点击“保存加密状态”才会写入；启动、扫描完成和报告导出都不自动保存。实现不发起 API 调用，不导入 OpenAI SDK 或网络客户端，不增加云同步、自动修复或后台任务。DPAPI 不能抵御已经控制同一 Windows 用户会话的程序，也不支持跨用户或跨设备恢复。路径检查与最终 `os.replace` 之间仍有同用户竞态窗口，当前批次未实现句柄级目录约束。

本批次的完整本地门禁、独立只读复审和功能提交 GitHub CI 已分别记录。该增量不代表整个 Windows MVP 完成或生产安全。

2026-08-02 Batch 2 当前工作树重新验证结果：

- `python -B -m pytest -q -p no:cacheprovider`：`288 passed, 6 skipped`，包含本机真实 DPAPI bytes 与文件往返测试。新增的真实祖先 symlink 用例因本机创建权限跳过；确定性祖先 reparse 模拟已通过，远程 Windows CI 仍需复核该用例。
- `python -B scripts/check_brand_assets.py`：退出码 0。
- `python -B -m compileall -q src`：退出码 0。
- `git diff --check`：退出码 0。
- 自审计：`network_capability=not_detected`、`findings=[]`、`ordinary_user_mode=true`、`local_only=false`。
- 当前规则 SHA-256：`83a14590d59f61a3c6aede084644fdbbd9f5cff6f55794b9af60e385e053ccba`。
- 独立只读复审最初为 `Not Ready`，发现固定摘要边界、DPAPI 调用约束、写入调用约束、祖先 reparse/UNC 检查及 AST 别名旁路等 Important 问题。修复后复审者重放直接、下标、动态属性和别名探针，最终结论为 `Ready`，未发现剩余 Critical/Important；该结论只覆盖约定的静态 AST 策略，复审者未运行全量测试。

功能提交 `e8e01f9415d3c2b6f21eb73d826eb36ea0655473` 的 GitHub 远程证据：

- push CI run `30715647491`：success，Windows Server 2025、Python 3.12.10，`294 passed`，check-run 注解 0。
- Draft PR CI run `30715649117`：success，同一提交，check-run 注解 0。
- 远程测试无 skip，因此本机因创建权限跳过的真实祖先 symlink 用例已在托管 Windows runner 上执行通过。

以上证明 Batch 2 当前约定门禁通过；状态同步提交自身的 CI 仍需在提交后独立验证。Batches 3-6 仍未实现。
