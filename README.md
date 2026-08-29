![智能体守护宣传图](assets/brand/agentguardian-readme-zh.png)

[English version](README.en.md)

# AgentGuardian｜智能体守护

面向 AI 智能体工作流的本地优先数据安全审计工具。AgentGuardian 在数据交给智能体处理之前，帮助你先看清本地配置、浏览器数据、剪贴板内容和公开分享入口可能暴露的风险。

> 当前下载渠道：Windows 11 x64 · 0.3.0 Public Preview · 未签名

## 一、这个仓库是什么？

这是 AgentGuardian 的公开源码仓库，也是 Windows Public Preview 的下载与说明入口。

项目采用一个本地审计核心和三个使用入口：

- 桌面 GUI：适合直接在 Windows 上选择范围、查看授权摘要和阅读报告。
- Codex Skill：独立分发的智能体 Skill，负责检查本地 MCP 能力、收集用户确认并调用已配置的本地工具。
- STDIO MCP 本地代理：让 Codex 或其他支持 MCP 的宿主在本机调用 AgentGuardian 扫描工具。

三个入口共享相同的数据访问边界。当前审计范围是用户明确选择的本地配置数据，运行过程以只读检查为主，并在实际读取或验证前要求人工确认。

## 二、适合谁用？

### 1、特别适合

- 在 Windows 11 x64 上使用 Codex 或其他智能体，并希望在智能体接触本地数据前做一次检查的个人用户。
- 使用个人、非监管的 AI 配置、工作流文件、浏览器元数据或临时剪贴板内容的创作者、开发者和 AI Builder。
- 希望通过 GUI、独立 Skill 或本地 STDIO MCP 选择适合自己宿主环境的使用方式的人。
- 需要可读、可留存、经过脱敏处理的审计报告作为人工判断辅助的人。

### 2、不适合

- 医疗、金融、身份、生物识别、法律特权、客户数据、国家秘密、受监管数据或其他高敏感真实数据。
- 需要企业控制台、集中策略、动态 MCP 沙箱、自动修复、遥测或后台服务的组织。
- 需要已签名安装程序、正式代码签名、合规认证或生产安全承诺的场景。
- 把扫描结果当作“系统、账号、智能体或数据绝对安全”证明的场景。

## 三、它会产出什么？

- 按当前规则生成的脱敏 JSON 和 HTML 审计报告。
- 按范围整理的发现项、严重程度、可解释评分和人工处置指引。
- 在执行前展示的授权摘要，以及用于核对本次范围的摘要信息。
- 对文件、浏览器、剪贴板或公开 URL 的有限检查结果，并标明未覆盖、截断或需要人工复核的部分。

报告是决策辅助材料，不是安全认证、法律意见或合规证明。

## 四、具有什么价值？

- 在智能体读取数据之前增加一个清晰的本地检查和人工确认环节。
- 让 GUI、Codex Skill 和 STDIO MCP 使用同一套审计边界，减少不同入口之间的行为差异。
- 将复杂的本地发现整理成更容易阅读和复核的报告。
- 对 OpenAI Provider 配置提供本地适配、检测和人工指引，帮助用户识别风险配置；默认不调用 Provider API。
- 让用户知道一次检查看到了什么、没有看到什么，以及下一步应由谁做决定。

## 五、使用效果


## 六、安装方法

[下载 Windows x64 单文件安装程序](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-Windows-x64.exe)

这是 AgentGuardian 0.3.0 Public Preview 的未签名安装程序。它面向 Windows 11 x64 的个人、非监管配置数据，可能显示 Unknown Publisher 或 SmartScreen 警告。

安装前请先下载并核对 [SHA256SUMS](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/SHA256SUMS) 中对应的哈希值：

1. 下载上面的单文件 EXE。
2. 使用 Windows 的文件哈希工具计算 SHA-256，并与 SHA256SUMS 对照。
3. 确认文件来源和哈希后再运行；Windows 的发布者警告不会因为本项目开源而自动消失。
4. 按安装向导选择需要的组件。安装程序提供桌面 GUI，并可选择安装独立 Codex Skill、启用本地 MCP 以及创建桌面快捷方式。
5. 安装完成后，在目标宿主中确认本地 MCP 工具已经出现，再开始审计。

其他下载入口：

- [查看 0.3.0 Public Preview](https://github.com/yangjing6213-dev/AgentGuardian/releases/tag/v0.3.0-preview.1)
- [Windows x64 便携 ZIP](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-0.3.0-preview.1-windows-x64.zip)
- [版本化 Windows x64 安装程序](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Setup-0.3.0-preview.1-x64.exe)
- [独立 AgentGuardian Skill ZIP](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/AgentGuardian-Skill-0.2.0.zip)
- [下载清单与元数据](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/DOWNLOAD-METADATA.json)
- [第三方通知](https://github.com/yangjing6213-dev/AgentGuardian/releases/latest/download/THIRD_PARTY_NOTICES.md)

安装程序采用当前用户目录安装，不要求管理员权限。宿主的 Skill 或 MCP 配置仍可能需要用户按宿主规则明确确认；AgentGuardian 不会静默下载 Provider、MCP 适配器或其他远程组件。

## 七、如何使用

### 桌面 GUI

1. 启动 AgentGuardian。
2. 选择一个明确的审计操作和最小范围：files、browser、clipboard 或 public_share。
3. 查看授权摘要，确认数据分类为 personal_non_regulated。
4. 在人工确认后运行检查。
5. 查看脱敏报告，并对发现项采取人工决定的后续行动。

### Codex Skill

1. 从 Release 下载独立 Skill ZIP，或使用安装程序中的 Skill 选项。
2. 将 Skill 安装到当前宿主约定的位置，例如 %USERPROFILE%\.agents\skills\agentguardian。
3. 让宿主检查是否同时提供 prepare_audit 和 run_prepared_audit 两个本地 MCP 工具。
4. 按 Skill 的提示选择一个操作、确认数据范围，并在宿主的批准提示中决定是否继续。

Skill 本身不会替代本地运行时，不会自行修改宿主配置，也不会用 Shell、浏览器或网络工具绕过 MCP 能力检查。

### STDIO MCP 本地代理

在支持本地 STDIO MCP 的宿主中，将本地控制台程序配置为：

~~~text
AgentGuardianMcp.exe --stdio-mcp
~~~

配置完成后，宿主应能看到：

- prepare_audit
- run_prepared_audit

先调用 prepare_audit 查看范围和授权摘要，再由用户明确确认，最后调用 run_prepared_audit。不要把窗口 GUI 程序当作 STDIO 命令，也不要把本地代理改成远程 URL。

三个入口的访问能力相同，但每次审计仍以用户选择的范围和人工确认结果为准。

## 八、项目工作流程

1. 选择一个操作和最小审计范围，并确认数据属于个人、非监管配置数据。
2. 执行前置检查，校验路径、操作类型和当前宿主能力。
3. 展示授权摘要、可能进入宿主模型上下文的脱敏参数与结果说明。
4. 用户明确选择继续后，执行本地只读审计或公开 URL 可达性检查。
5. 生成脱敏 JSON/HTML 报告，记录发现项、覆盖边界和截断情况。
6. 用户或其他人工负责人复核报告，再决定是否手动调整配置。

浏览器检查使用临时本地副本；剪贴板检查只在用户明确请求时读取当前值；public_share 只检查用户明确输入的公开 URL，不通过该操作上传审计数据。项目不执行自动修复，不在后台持续监听，也不动态加载或执行任意 MCP 插件。

## 九、项目目录结构

~~~text
src/agentguardian/       本地审计核心、报告、Provider 指引和 MCP 服务
skills/agentguardian/    独立 Codex Skill
packaging/windows/       Windows 便携版、PyInstaller 和 Inno Setup 配置
release_profiles/        Public Preview 发布配置与边界
scripts/                 构建、校验、打包和证据脚本
tests/                   单元、集成和 Windows 打包相关测试
docs/                    架构、安全边界、发布和开发记录
assets/brand/            README、品牌和作者展示素材
.github/workflows/       GitHub CI 与 Windows 工作流
~~~

## 十、注意事项

- 当前版本是未签名的 Windows 11 x64 Public Preview，不是生产安全版本。
- 仅限个人、非监管配置数据；禁止使用高敏感真实数据。这个限制不是 AgentGuardian 能正确分类所有内容的保证。
- 不要把报告当作安全、合规、隐私或企业控制能力的证明。当前不提供企业控制台、动态 MCP 沙箱、自动修复、遥测、后台服务或通用安全保证。
- OpenAI Provider 只执行本地适配、检测和人工指引，默认不调用 OpenAI 或其他 Provider API。
- Skill 传递给宿主的脱敏参数和结果可能进入宿主模型上下文；覆盖不完整、权限不足或结果截断时，不能据此判断安全。
- 静态 MCP 检测器只分析配置风险，不下载、启动、代理或执行 MCP 软件。
- 运行安装程序前核对 SHA-256；无法核对哈希时不要运行文件。
- 源码采用 Apache License 2.0；第三方组件与再分发说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。未签名状态和当前预览边界仍以对应 Release 说明为准。

### 预览状态与发布校验标识

以下状态标识与仓库发布配置保持一致。它们描述预览成熟度和门禁状态，不改变公开下载链接：

- 0.3 Integrations Preview is the active development track；当前成熟度标识为 INTEGRATIONS-PREVIEW-NOT-READY。
- NO-GO 表示尚未宣称生产安全或正式安全交付，不表示 Release 页面不可访问。
- This is an unsigned Public Preview.
- 支持边界是 personal non-regulated configuration；high-sensitivity real data is unsupported。
- production-safety：not claimed；enterprise control-plane：unsupported。
- The runtime must not call OpenAI or another Provider API by default.
- AgentGuardian does not silently download or enable a Provider API.
- 主安装文件是 AgentGuardian-Setup-Windows-x64.exe；本地代理是 AgentGuardianMcp.exe；安装包包含独立 Skill payload。
- 0.2.0-beta.1 的 frozen exact SHA 记录只作历史证据，不作为当前版本证明。
- Personal v1 不支持高敏感现实数据。
- 联网分享验证仅在用户显式输入公开 URL 后执行。

<details>
<summary>开发治理与历史证据</summary>

本仓库的治理文件用于 govern development；它们是 not product capability claims or release evidence：

- [approved active product specification](docs/superpowers/specs/2026-08-16-agentguardian-personal-v1-design.md)
- [active implementation plan](docs/superpowers/plans/2026-08-21-agentguardian-personal-exe-private-beta.md)
- canonical partial status ledger：[personal-exe-private-beta-status.json](docs/security/personal-exe-private-beta-status.json)
- Frozen private-beta candidate 8ad46e31486d05a2b4572ef8bd7442eb22a7b5b6 remains PRIVATE-BETA-NOT-READY；formal public release remains `NO-GO` because external license and Qt approval, two-machine acceptance, and operations/security gates are pending.
- OpenAI Provider local adaptation, detection, and manual guidance only. The runtime must not call OpenAI or another provider API by default.
- 源码运行信息中的 Python 版本可以显示，但不会暴露 interpreter path。
- 旧记录中的 traditional unsigned offline EXE installer 路线是历史门禁语境；No installer candidate has passed the required gates 只描述该历史记录，不表示当前 Release 下载链接不可用。
- older Windows MVP reports are historical planning or evidence snapshots。

</details>

当前 Release 的八个公开资产名称为：

~~~text
AgentGuardian-0.3.0-preview.1-windows-x64.zip
AgentGuardian-Setup-0.3.0-preview.1-x64.exe
AgentGuardian-Setup-Windows-x64.exe
AgentGuardian-Skill-0.2.0.zip
DOWNLOAD-METADATA.json
LICENSE
SHA256SUMS
THIRD_PARTY_NOTICES.md
~~~

### 预览状态与发布校验标识

以下状态标识与仓库发布配置保持一致。它们描述预览成熟度和门禁状态，不改变公开下载链接：

- 0.3 Integrations Preview is the active development track；当前成熟度标识为 INTEGRATIONS-PREVIEW-NOT-READY。
- NO-GO 表示尚未宣称生产安全或正式安全交付，不表示 Release 页面不可访问。
- This is an unsigned Public Preview.
- 支持边界是 personal non-regulated configuration；high-sensitivity real data is unsupported。
- production-safety：not claimed；enterprise control-plane：unsupported。
- The runtime must not call OpenAI or another Provider API by default.
- AgentGuardian does not silently download or enable a Provider API.
- 主安装文件是 AgentGuardian-Setup-Windows-x64.exe；本地代理是 AgentGuardianMcp.exe；安装包包含独立 Skill payload。
- 0.2.0-beta.1 的 frozen exact SHA 记录只作历史证据，不作为当前版本证明。
- Personal v1 不支持高敏感现实数据。
- 联网分享验证仅在用户显式输入公开 URL 后执行。

当前 Release 的八个公开资产名称为：

~~~text
AgentGuardian-0.3.0-preview.1-windows-x64.zip
AgentGuardian-Setup-0.3.0-preview.1-x64.exe
AgentGuardian-Setup-Windows-x64.exe
AgentGuardian-Skill-0.2.0.zip
DOWNLOAD-METADATA.json
LICENSE
SHA256SUMS
THIRD_PARTY_NOTICES.md
~~~

## 十一、相关项目

无

## 十二、关于作者

<img src="assets/brand/author-avatar.png" alt="Enhe（恩禾）作者信息" width="720">

**Enhe（恩禾） - 产品设计师 - 一人公司实践者 - AI Builder**

用AI打造一个人公司。

- GitHub: [yangjing6213-dev](https://github.com/yangjing6213-dev)
- X/Twitter: [Amenenhe_ai](https://x.com/Amenenhe_ai)
- 网站: [www.enhe-tech.com.cn](https://www.enhe-tech.com.cn/)
- 微信: Hu-Amen
- 邮箱: [amen.enhe@gmail.com](mailto:amen.enhe@gmail.com)

## 十三、继续探索

这个项目是我用 AI 搭建的个人生成系统里的一个工具。如果你也在用 AI 做内容、知识库、工作流或产品化，可以登录我的网站 [www.enhe-tech.com.cn](https://www.enhe-tech.com.cn/) 查看更多资料。

---

源码许可证：[Apache License 2.0](LICENSE)。
