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
