![AgentGuardian](assets/brand/agentguardian-cover.svg)

# AgentGuardian

**AI Agent 守护者（AG）** 是一款面向 Windows 个人用户和小团队的本地优先 AI Agent 数据安全审计工具。

当前版本为 `0.1.0 Founder Alpha`。Windows 本地只读发现、敏感数据与 MCP 静态检测、可解释评分、脱敏 JSON/HTML 报告、人工修复指引、桌面界面和保守自审计已经形成合成数据闭环。本版本仍是内部 Alpha，不代表生产安全等级。

## 为什么可以信任

- Founder Alpha 以普通用户权限运行，不提权、不执行修复、不修改扫描目标。
- 包源码策略检查未发现网络、遥测、LLM、更新器或动态插件模块；该结论不覆盖依赖和二进制。
- 完整聊天、完整凭据、完整路径和完整分享链接不得进入普通报告。
- 证据只保留短显示名、脱敏摘要和扫描级 HMAC 指纹。
- 修复仅提供人工步骤，验证状态明确显示为 `not_performed`。
- 自审计固定返回规则 SHA、运行解释器路径、权限状态、能力 findings 和未覆盖范围。
- 扫描规则、评分、报告格式和安全边界在公开仓库中接受检查。

安全分数必须与审计覆盖率、证据置信度、限制项一起阅读。`100` 分只表示在用户选择的范围内没有发现当前规则可识别的问题，不等于绝对安全。

## Founder Alpha 范围

已实现：

- 用户明确选择的本地目录和少量已知 Windows AI 配置位置。
- 常见密钥、基础隐私数据、个人定制关键词和 MCP 危险权限组合的本地静态检查。
- 可解释的六领域评分，以及只含脱敏证据的本地 JSON/HTML 报告。
- 范围、发现、报告三个页面组成的极简 PySide6 桌面流程。

明确不包含：浏览器数据库、浏览器历史、剪贴板、联网分享验证、自动修复、回滚、云同步、企业控制台和生产级安全承诺。UNC 路径被拒绝；映射网络盘无法可靠识别，属于已知残余风险。

## Windows MVP 硬化进度

供应链基线批次已完成 GitHub Actions commit SHA 固定和 Windows Python 依赖哈希锁定。当前进入 **OpenAI Provider 本地适配批次**：覆盖 `%USERPROFILE%\.codex` 已知配置目录、`.env`/`.toml` 静态扫描、`OPENAI_API_KEY` 脱敏发现、`OPENAI_BASE_URL`/`openai_base_url` 覆盖配置提示，以及 OpenAI 专用人工修复指引。

端点覆盖发现只表示该配置需要人工复核，不证明端点属于恶意第三方。AgentGuardian 只在用户授权的本地范围读取静态配置，不发起 API 调用或联网验证端点，也不自动修改 Provider、撤销密钥或轮换凭据。

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
- [产品与安全设计规范](docs/superpowers/specs/2026-08-01-agentguardian-design.md)
- [系统架构与数据流](docs/architecture.md)
- [Founder Alpha 阶段报告](docs/reports/alpha-0.1.0-stage-report.md)

## 品牌

中文名称：AI Agent 守护者

英文名称：AgentGuardian

英文缩写：AG

品牌源文件和导出资产位于 [`assets/brand`](assets/brand)。
