# AgentGuardian 0.1.0 Founder Alpha 阶段报告

报告日期：2026-08-01

更新日期：2026-08-03

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

本报告第 1 至 7 节记录 Founder Alpha 历史门禁；其中测试计数、规则 SHA 和 CI 结果不自动代表后续提交已重新验证。第 8 节为已被第 9 至 10 节取代的历史交接记录：它只描述进入 Windows MVP 硬化时的状态，不代表当前批次进度。供应链基线与 OpenAI Provider 本地适配、检测和人工指引在该历史时点已完成，当时尚未进入受保护证据状态实施。

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

以下为 Batch 2 历史远程证据，只覆盖功能提交 `e8e01f9415d3c2b6f21eb73d826eb36ea0655473`：

- push CI run `30715647491`：success，Windows Server 2025、Python 3.12.10，`294 passed`，check-run 注解 0。
- Draft PR CI run `30715649117`：success，同一提交，check-run 注解 0。
- 远程测试无 skip，因此本机因创建权限跳过的真实祖先 symlink 用例已在托管 Windows runner 上执行通过。

以上证明 Batch 2 当时的约定门禁通过；这些运行不覆盖后续 Batch 3 提交。状态同步提交自身的 CI 仍需在提交后独立验证。

## 10. Windows MVP 硬化 Batch 3：发现处置与到期例外

Batch 3 本地实现、自动门禁、独立安全复审和最终 SHA 远程验收已完成。跨扫描精确匹配只使用规则 ID、按 Windows 词法规则规范化的源路径，以及 NFKC 规范化的原始匹配。路径使用 `ntpath.abspath`、`ntpath.normpath` 和 `ntpath.normcase`，不做 NFKC。规则、路径、原始匹配或本地密钥任一变化都会重新打开发现。本地处置 HMAC 密钥与每次扫描随机生成的报告 HMAC 密钥彼此独立；报告 HMAC 仍限定于单次扫描，且本地引用和密钥不导出。

每项处置都需要安全的原因、复核人、创建时间和到期时间；处置有效期必须有限且不超过 366 天。有效误报只从复核分排除；接受风险仍计入复核分；技术分不受处置影响。过期记录保留审计上下文但重新打开发现。状态读取保持 schema v1 只读兼容，只有显式保存才迁移到 schema v2。损坏、不可解密或无效的受保护状态必须先获得明确确认，才允许替换。

操作边界仍是本地静态检查、桌面处置和人工指引，不发起 API 调用，也不默认访问 OpenAI API。DPAPI 不能抵御已经控制同一 Windows 用户会话的程序。主机时钟、路径别名或文件移动可能重新打开发现，但不会扩大处置范围。路径检查与 `os.replace` 之间仍有同用户竞态窗口；Python 不能保证清除所有不可变 bytes 或字符串副本。

当前静态自审计严格加载随包分发的 `source_policy.json` schema 1，并要求精确模块集合以及每个已复核 `.py` 文件的 canonical source SHA-256 完全匹配。源码先将原始 ASCII newline bytes 中的 CRLF 和 CR 确定性规范化为 LF，再通过 `tokenize.detect_encoding` 按 PEP 263 编码声明解码，并对规范化 Unicode 的 UTF-8 表示取哈希；注释和编码 cookie 因而被证明。换行表示被有意忽略，UTF-8 BOM 按解码语义被消费，所以该清单不是原始字节身份的证明。未经规范化的原始 bytes 还独立交给 `ast.parse(..., filename=...)`，保证 Python 实际执行的语法通过检查，UTF-7 编码中的运行时注入也会对扫描可见。新增、删除、未知编码、语法错误或 canonical source 变化都会以固定 finding 失败关闭；已复核包不再进入启发式。有限启发式仅对清单外的合成未知模块运行，检查代表性的网络导入、动态执行和用户数据写入能力，而不是 Python 表达式解释器。这不是语义、依赖或二进制证明。清单未签名，同一用户控制代码和清单时可以同时替换两者；生产来源和签名仍待 Batch 5。

仓库顶层 `rules/default.json` 仍是权威规则来源；wheel 使用 byte-identical 的 `agentguardian/rules/default.json` 副本，并由包数据、`RECORD` 和无网络直接解压探针约束其来源与可用性。

### Batch 3 历史远程失败证据

- 失败提交：`d719e0fb79eae9132fabc713e23f5256d0c1f70c`。
- push workflow `30759350802` 和 Draft PR workflow `30759352079` 均失败，不能作为 Batch 3 远程验收证据。
- 源码策略失败根因：Python 3.12 与本地 Python 3.14 的 `ast.dump` 输出不同，所有模块的 canonical AST digest 均不一致，触发 `SOURCE_POLICY_VIOLATION` 和 6 项测试失败。
- 打包失败根因：测试使用 `python -m build`，但 `build` 不在哈希锁定的 CI 开发依赖中。

### Batch 3 当前本地证据

2026-08-03 在当前工作树重新运行：

- `py -3.12 -m pytest -q`：`681 passed, 6 skipped`，0 failed；按不安装要求，通过 `PYTHONPATH` 使用机器上既有的测试依赖。
- `py -3.14 -m pytest -q -p no:cacheprovider`：`681 passed, 6 skipped`，0 failed。
- Python 3.12 与 3.14 对全部包模块产生相同 canonical source 清单；LF 与 CRLF/CR 的 digest 相同，编码 cookie 或解码后源码变化的 digest 不同。
- `rtk proxy python scripts/check_brand_assets.py`：退出码 0。
- `rtk proxy python -m compileall -q src`：退出码 0。
- 打包测试复制最小源码树后直接调用已锁定的 `setuptools.build_meta.build_wheel`，不调用打包或安装前端；wheel `RECORD` 包含 `agentguardian/source_policy.json` 和 byte-identical 的 `agentguardian/rules/default.json`，并对两项资源逐一解码、比较 URL-safe base64 SHA-256 与记录的字节大小。由 `zipfile` 直接解压后，隔离探针中的 `load_rules()`、`static_capability_findings()` 和 `collect_self_audit()` 均成功，原工作树不承载构建输出。
- `rtk git diff --check`：退出码 0，无输出。
- 使用 `PYTHONPATH=src` 调用 `collect_self_audit()`：`findings=[]`、`local_only=true`、`network_capability=not_detected`、`ordinary_user_mode=true`；范围仍为 `package_source_policy`，依赖和二进制未扫描。

### Batch 3 最终 SHA 远程验收证据

- Batch 3 远程验收的实现与证据基线 SHA：`50b74e6cc50dd7a4681a26b3084e7f312c096c47`。
- push run `30762254791` / job `91534776936`：`SUCCESS`；Windows Full test suite：`687 passed`；[运行与 job](https://github.com/hqwzhu/AgentGuardian/actions/runs/30762254791/job/91534776936)。
- PR run `30762256518` / job `91534781660`：`SUCCESS`；Windows Full test suite：`687 passed`；[运行与 job](https://github.com/hqwzhu/AgentGuardian/actions/runs/30762256518/job/91534781660)。
- 两次运行的 Install、Full test suite、Brand validator、Compile source、Verify clean tree 均通过；annotations：0/0。
- 证据采集时，Draft PR #1 在该 SHA 上为 `OPEN / DRAFT`，head 指向该 SHA；[PR 链接](https://github.com/hqwzhu/AgentGuardian/pull/1)。
- `a38910b340631b2e78c33c9d7595cf98aa2f52b9` 是仅修改文档与文档断言测试的证据同步提交，不更改运行时或包源码；该提交未被上述两次针对 `50b74e6cc50dd7a4681a26b3084e7f312c096c47` 的 CI 运行覆盖，因此不声明 `a38910b340631b2e78c33c9d7595cf98aa2f52b9` 已远程验证。

### Batch 3 当前独立安全复审状态

- 历史复审对象 `537b3d9ba9829f1e85e5eec5671e90e1853c030e` 在 canonical AST 模型下曾得到 `READY`，发现计数为 Critical 0、Important 0、Minor 1；该结果已由当前 canonical source 模型复审取代。
- 复审对象 SHA：`ef7808975879bea153172c09e647e04d0bf48e9b`。
- 结论：`APPROVED / READY`。
- 发现计数：Critical：0；Important：0；Minor：0。
- canonical source 证明规范化后的解码源码，包括注释和编码 cookie；它有意不区分 LF、CRLF 和 CR，也不等同于原始字节、依赖、二进制或完整语义证明。
- 残余限制不变：清单未签名，同一用户可同时替换代码和清单；有限启发式不是语义证明；依赖和二进制未扫描；DPAPI 同用户、主机时钟、路径别名、文件移动、路径检查竞态和不可变 bytes 副本限制继续存在。

当前证据支持 Batch 3 本地实现、自动门禁、独立安全复审和最终 SHA 远程验收，Batch 3 已完成。该验收不构成生产安全结论。Batches 4-6 仍待完成；Founder Alpha 继续保持非生产、Windows MVP 不完整状态，不建立生产安全结论。

## 11. Windows MVP 硬化 Batch 4：工作流与报告硬化

Batch 4 Task 1-8 已在本地实现。每次扫描都需要与当前范围绑定的明确同意；范围预览不遍历目录，扫描回调会重新校验并消费同意。覆盖状态固定为 `complete`、`limited` 和 `no_supported_files`，不完整结果不能用于确认安全。严重性、风险领域和处置状态筛选仅影响界面可见行，导出仍包含完整当前审计，不改变分数、报告、处置或受保护状态。

基线比较仅支持 JSON。用户必须显式选择一个不超过 2 MiB 的本地 AgentGuardian 报告；加载器拒绝 UNC、reparse、非普通文件和超限读取。当前 Task 10 修复树已让 JSON 生成与导入共享最多 2,000 个 findings、4,000 条 evidence 和 2 MiB UTF-8 的预算；HTML 只共享两项数量上限。新 report schema 1 写入规范 UTC 秒级 `evaluated_at`；`evaluated_at` 是无默认值的 keyword-only 必填参数，不存在隐藏时钟路径，相同输入（包括该时点）生成逐字节相同的 JSON 和 HTML。生成器先有界物化 findings 和处置，再以声明分数的 coverage、confidence、limits 精确复算技术分和复核分；省略 reviewed score 时使用复算值，任何矛盾固定失败。解析器按同一时点重新验证非 `open` 处置和复核分；缺少该时点的旧 schema 1 与 legacy schema 0 只接受所有处置均为 `open` 的可独立重算报告。规则版本、cap reason 和规则 ID 使用同一安全元数据契约；长基线 basename 省略显示，tooltip 不含目录。上述实现已完成当前 SHA 的 Task 10 独立复审和完整本地门禁，但 Task 10 最终 SHA 的 push/Draft PR CI 证据仍待执行，不构成远程验收。校验不证明报告真实性。比较仅保留类别聚合；聚合比较结果只在内存中瞬态保留，不匹配单个 finding，不导出稳定的跨扫描 finding 标识符，也不保留完整路径、原始 JSON、证据、指纹或处置详情。显式读取一个基线文件不会增加环境目录扫描、网络、API 调用或写入能力。

残余限制仍包括 DPAPI 无法抵御同一用户控制、文件检查后的路径竞态、主机时钟与路径别名影响、类别聚合碰撞，以及静态自审计不覆盖依赖和二进制。OpenAI Provider 仍仅做本地适配、检测与人工指引，不默认调用 API。

### Batch 4 按 SHA 记录的本地证据

- 2026-08-03 的 Task 9 证据提交为 `991bf81bb520e7f2ec12f331fbbe714f03212507`，其父提交为 Task 8 的 `71cdc81fdf372f3deace33005137d69e5a0cd6bc`；Task 9 只修改文档、文档断言和精确源码清单，不修改运行时 `.py` 代码。
- 文档 RED：`rtk pytest -q -p no:cacheprovider tests/test_self_audit.py -k batch_4` 首次为 `1 failed`，缺少 README Batch 4 状态；文档更新后为 `1 passed`。
- 该提交的 Python 3.14 门禁：Python `3.14.0`；`rtk pytest -q -p no:cacheprovider` 为 `1174 passed, 8 skipped, 0 failed`。
- 该提交的 Python 3.12 门禁：Python `3.12.2`，使用隔离的本地锁定 wheelhouse；先通过 `--dry-run --no-index --require-hashes` 与 `requirements-dev.lock` 校验，再只解压到临时目录，并用 `-S` 禁用系统 site-packages。未安装或混用 Python 3.14 包。完整测试为 `1174 passed, 8 skipped, 0 failed`，测试后已删除临时解压目录。
- 8 项 skip 均因当前 Windows 用户缺少 symlink 创建权限：app smoke 目录/文件 symlink 2 项、discovery 3 项、report comparison 2 项、state store 1 项。junction 已测试；skip 不构成对应 symlink 场景通过证据。
- 该提交的 `tests/test_self_audit.py tests/test_packaging.py` 聚焦门禁：`132 passed`；精确清单包含全部 16 个包内 `.py` 模块和 `workflow.py`、`report_comparison.py`。
- Python 3.14 与隔离 Python 3.12 的品牌校验、`compileall -q src` 均退出 0；`git diff --check` 退出 0，无输出。
- 两个解释器使用 `PYTHONPATH=src` 的自审结果均为 `findings=[]`、`local_only=true`、`network_capability=not_detected`、`ordinary_user_mode=true`；规则 SHA-256 为 `83a14590d59f61a3c6aede084644fdbbd9f5cff6f55794b9af60e385e053ccba`。范围仍是 `package_source_policy`，依赖和二进制未扫描。
- 2026-08-13，Task 10 当前复审实现为 `d1c3e9caa856812d0bdd3221b0c6a7083da937ff`。独立规格复审和独立安全/质量复审结论均绑定该 SHA，发现计数为 Critical：0；Important：0；Minor：0。
- 该 SHA 的 Python 3.14.0 完整门禁和使用 `requirements-dev.lock` 哈希锁定依赖临时隔离的 Python 3.12.2 完整门禁均为 `1264 passed, 8 skipped, 0 failed`；聚焦 `tests/test_self_audit.py tests/test_packaging.py` 门禁为 `152 passed`。
- 两个解释器的品牌校验、`compileall -q src` 和 package-source self-audit 均通过；自审仍为 `findings=[]`、`local_only=true`、`network_capability=not_detected`。
- 本节不把该 SHA 之后的文档/测试证据同步提交声明为被这些本地结果覆盖，也不形成自证循环。
- 远程实现与证据基线为 `a79995a7a6a950050d5628324f94a6b8a07e6308`；本地与远端 `agent/founder-alpha` 在取证时均指向该 SHA。
- push run `31714716636` / job `94496371022`：`SUCCESS`；Draft PR run `31714721274` / job `94496388008`：`SUCCESS`。两个 GitHub-hosted Windows Python 3.12 运行均为 `1277 passed`，Install、Full test suite、Brand validator、Compile source、Verify clean tree 均通过，annotations：0/0。
- 取证时 Draft PR #1 保持 `OPEN / DRAFT`，base 为 `agent/design-baseline`，head 为 `agent/founder-alpha`。该 PR 未合并、未标记 ready，也未部署。
- 实现基线 `a79995a7a6a950050d5628324f94a6b8a07e6308` 的本地 Python 3.14 与使用 `requirements-dev.lock` 哈希锁定依赖隔离的 Python 3.12 完整门禁均为 `1269 passed, 8 skipped, 0 failed`；品牌校验、源码编译、差异检查和干净树检查均通过。
- 本节的后续文档/测试证据同步提交不由上述针对 `a79995a7a6a950050d5628324f94a6b8a07e6308` 的两次远程运行自动覆盖，必须在推送后单独验证。

## 12. Windows MVP 硬化 Batch 5：便携开发包层

Batch 5 便携开发包层已完成本地验证。实现证据绑定 `10e65322cd590f2028fb5946fff7125afd2e101d`。构建使用独立的哈希锁定 Windows Python 3.12 环境，产物为 PyInstaller `onedir` 未签名开发产物；包内包含 CycloneDX 1.6 SBOM、载荷清单、构建元数据、Apache-2.0 许可证、第三方声明和 SHA-256 校验和。机器可读 SBOM 将嵌入 `AgentGuardian.exe` 的 PyInstaller Bootloader 6.16.0 记录为 `required` 运行时依赖，并把 PyInstaller 打包工具记录为 `excluded` 构建时组件。Qt 商业许可证没有被验证，PySide6/Qt 的 LGPL/GPL/商业许可选择仍须由发布方确认；Microsoft Visual C++ Runtime 和 Universal C Runtime 在当前 SBOM 中为 `NOASSERTION`。

同一源码 SHA 与固定时间 `2026-08-14T08:00:00Z` 在两个全新输出目录生成 208 个文件，逐项 SHA-256 完全一致；两个 ZIP SHA-256 均为 `216936f89d9a8b8352e3a58ce8c2602dbb26e7d450ddfcb0959d289e0755ef7b`。产物含 206 个载荷清单条目，总目录约 92.87 MB、ZIP 约 36.03 MB。隔离复制后的 GUI 在 `QT_QPA_PLATFORM=offscreen` 下存活 4 秒，随后受控终止；隔离的 `APPDATA`、`LOCALAPPDATA`、`TEMP`、`TMP` 与包副本已删除，声明目录零残留。过早退出负向探针同样失败关闭并删除测试目录，原始包保持不变。该冒烟只证明本机受控存活和声明目录清理，不是干净机器验收或卸载器证明。

当前本地提交尚未获得 GitHub CI 验证。可信代码签名、原生安装、干净机器验收和卸载残留检查仍未完成；Batch 6 仍待完成，Windows MVP 尚未完成，未形成生产安全结论。

## 13. Windows MVP 硬化 Batch 6：本地发布候选门禁

**Batch 6 local gate status.** 修复后的实现与统一本地证据基线为 `392ff64f3bcb3f978874e668a97e5a3f013b762e`。精选安全门禁当前重新验证为 `47 passed, 1 skipped`；唯一允许的 skip 是 AG-T09 目录 symlink 不可用，不能计入完整通过。完整 Python 3.14 门禁为 `1321 passed, 8 skipped`，哈希锁定 Python 3.12 开发环境为 `1320 passed, 9 skipped`。Python 3.12 的额外 skip 仍来自仅存在于构建锁中的 CycloneDX 集成。独立只读复审已完成并发现 7 项 Important findings，修复后独立复审仍待完成。

性能证据只覆盖固定合成工作负载，不覆盖 10,000 文件功能上限、整进程 RSS、慢盘、杀毒软件差异、原生安装器启动或 fresh runner。独立只读复审、当前精确 SHA 的 GitHub CI、fresh-runner provenance、可信签名、原生安装/卸载、干净机器和许可/再分发复核仍待完成。详细证据见 `windows-mvp-release-candidate-report.md`。Release-candidate decision: `NO-GO`. Windows MVP remains incomplete. Production safety is not established.
