# AgentGuardian Product Completion Plan

状态：执行中。当前版本仍为 `0.1.0 Founder Alpha`，本计划不提前改变生产安全结论。

## 目标

把当前本地 Founder Alpha 推进为可交付的 Windows MVP，再按产品路线补齐扩展审计、受控修复、团队能力和动态 MCP 隔离。每个阶段必须有实现、测试和独立验收证据；历史报告不能替代当前精确 SHA 的验证。

## 阶段一：Windows MVP 交付链

### A1 精确 SHA 的远程 CI

- [x] 增加 Windows MSIX 验证 workflow，固定 checkout 和 Python Action SHA。
- [x] 使用 `requirements-dev.lock` 与 `requirements-build.lock` 哈希安装。
- [x] 当前分支已推送并完成精确 SHA 的基础 CI 与 Windows MSIX smoke；每次交付以该 SHA 对应的 GitHub job 结果为准。

完成条件：当前候选 SHA 的完整测试、品牌校验、源码编译、便携构建和 MSIX 契约均在 GitHub-hosted Windows Runner 通过。

当前记录（2026-08-15）：功能代码提交 `c5ef30f73e8897cab7feb3e0efea605d23a26f67` 的 push CI run `31871630792` 与 Windows run `31871630758` 均为 `success`；Draft PR 同一 SHA 的 CI run `31871632626` 与 Windows run `31871632639` 也均为 `success`。随后仅同步本段证据的文档提交为 `3c38339ad5d0b661b621503d5eb814ea32ba2088`。本地完整回归为 `1362 passed, 11 skipped`；GitHub job 日志在当前 API 权限下无法下载，因此不把远程测试数量写成已验证数字。Windows Runner 继续执行 MakeAppx staging、无签名 OID namespace 包安装/启动/卸载和残留检查；该烟测证据为 `signature_mode=unsigned_ci_smoke`，对应 Windows job 会输出并绑定该 SHA 的包 SHA-256；它不是可信签名或公开发布证据。

最新复核（2026-08-15）：功能代码提交 `6c0043b5dc3551d4950f814a82a4c7484004d722` 的 push CI run `31873363929` 与 Windows run `31873363921` 均为 `success`；Draft PR 同一 SHA 的 CI run `31873365733` 与 Windows run `31873365732` 也均为 `success`。本地当前完整回归为 `1377 passed, 11 skipped`；远程 job 日志数量仍不作为已验证数字。Windows 运行仍是 `signature_mode=unsigned_ci_smoke`，因此不能替代可信签名、干净机器验收或生产安全证据。

最新复核（2026-08-15，固定修复桌面流程）：提交 `20cac6c6b9c8384ba298e07b534d2186d9ec65ca` 的本地完整回归为 `1383 passed, 11 skipped`；push CI `31874528529`、push Windows `31874528521`、Draft PR CI `31874530033` 和 Draft PR Windows `31874530037` 均为 `success`。Windows 运行仍是 `signature_mode=unsigned_ci_smoke`，只能证明仓库烟测，不替代可信签名、干净机器、真实 Windows 权限或生产安全证据。

最新复核（2026-08-15，高敏感网络边界）：提交 `f7ca1c5b8c1c1e896950d9998cbc5576dea72c5c` 的本地完整回归为 `1390 passed, 11 skipped`；push CI `31876302302`、push Windows `31876302334`、Draft PR CI `31876305303` 和 Draft PR Windows `31876305388` 均为 `success`。高敏感模式现在禁止联网分享验证；Windows 运行仍是 `signature_mode=unsigned_ci_smoke`，只能证明仓库烟测，不替代可信签名、干净机器、真实 Windows 权限或生产安全证据。

最新复核（2026-08-15，MSIX 安装升级卸载）：提交 `0ac5ff748f16578a86a3662b8fddd8f6fb94def3` 的本地完整回归为 `1391 passed, 11 skipped`；push CI `31876853579`、push Windows `31876853553`、Draft PR CI `31876855289` 和 Draft PR Windows `31876855292` 均为 `success`。Windows job `94993768289` 的 smoke JSON 明确记录 `upgrade_attempted=true`、`upgraded=true`、版本 `0.1.0.0 -> 0.1.0.1`、`termination=true`、`uninstalled=true`、`package_residue=false`；签名模式仍为 `unsigned_ci_smoke`，不替代可信签名或独立干净机器证据。

最新复核（2026-08-15，企业控制面与高敏感数据 Windows 发布门禁）：提交 `6829f25f70294161c6b4efe4392fa8417e0edc56` 的本地完整回归为 `1396 passed, 11 skipped`；push CI `31878697776`、push Windows `31878697703`、Draft PR CI `31878698579` 和 Draft PR Windows `31878698586` 均为 `success`。Windows full suite 为 `1406 passed, 1 skipped`；合成高敏感 gate 记录 `passed=true`、JSON/HTML/导出/剪贴板无原始标记、浏览器临时副本删除和工作区清理通过；MSIX 安装升级卸载继续通过。签名模式仍为 `unsigned_ci_smoke`，不替代可信签名、真实脱敏样本或独立干净机器证据。

最新复核（2026-08-15，Windows AppContainer 与 MCP 适配器签名门禁）：提交 `253b77d1f46b63f1761fd8ac56c9fb6f49555d22` 的本地完整回归为 `1404 passed, 11 skipped`；push CI `31881025303`、push Windows `31881025442`、Draft PR CI `31881028230` 和 Draft PR Windows `31881028238` 均为 `success`。Windows full suite 为 `1414 passed, 1 skipped`；合成高敏感 gate 记录 `passed=true`、报告/剪贴板/浏览器临时副本/工作区无原始残留；MSIX 安装升级卸载继续通过。native MCP 适配器现在在启动前执行 SHA-256 和本地 Authenticode 校验，未通过时拒绝启动。签名包仍为 `unsigned_ci_smoke`，组织发布者白名单、正式签名、真实脱敏样本和独立干净机器证据仍未完成。

最新复核（2026-08-15，本地管理控制面与严格用户状态门禁）：提交 `a6a75c27e20d329a32f9e1ef2473f35b23deb198` 的本地完整回归为 `1407 passed, 11 skipped`；push CI `31882264849`、push Windows `31882264755`、Draft PR CI `31882266953` 和 Draft PR Windows `31882266834` 均为 `success`。桌面新增离线本地管理页，可注册租户/设备、授予角色、导入经校验策略、撤销设备并展示无原文运营摘要；MSIX verifier 新增 `RequireFreshUserState`，要求可信签名、安装前空用户状态并检查卸载后的用户状态残留。该脚本尚未在独立干净 Windows 机器执行，签名模式仍未改变。

### A2 原生安装器与安装/卸载验收

- [x] 生成 MSIX manifest、资源、MakeAppx 命令和 SignTool 校验命令。
- [x] 编写不主动提权的安装、启动、有限存活、终止、卸载和包残留检查脚本；普通用户可用性仍需签名包和干净机复核。
- [x] CI 执行无签名 MSIX 的安装、启动和卸载烟测；证据明确标记为 `unsigned_ci_smoke`，不代表签名或发布可信度。
- [x] 验收器拒绝已有同名安装，并覆盖同身份高版本升级、升级后启动、终止、卸载和残留检查；正式签名 workflow 复用同一升级契约。
- [x] 增加 `RequireFreshUserState` 严格模式：只允许可信签名包，安装前要求 `LOCALAPPDATA\AgentGuardian` 不存在，卸载后检查用户状态残留；该模式仍需独立干净 Windows 机器执行。
- [x] 增加最终发布证据门禁 `scripts/verify_windows_release_candidate.py`：绑定构建来源、`trusted_release` 元数据、CycloneDX/第三方声明、可信签名 smoke 和完整安装卸载证据；未知许可证或 unsigned 状态默认失败。
- [ ] 在 Windows Runner 执行正式证书签名和签名包安装卸载烟测；依赖组织证书或 Trusted Signing secret。
- [ ] 在独立干净 Windows 环境执行安装、升级、启动、卸载和残留验收。

无签名 smoke 的 MSIX SHA-256 由对应 Windows job 输出并绑定当次精确 SHA；该摘要只绑定测试包，不是发布包摘要。

完成条件：安装器在目标 Windows 版本上可由普通用户安装和卸载，验证结果绑定精确 SHA 与 MSIX SHA-256；所有声明状态清理完成。

### A3 可信代码签名与供应链

- [x] 增加手动触发的 trusted-signature workflow：缺少组织 PFX、密码或预期发布者时默认失败；私钥只通过 GitHub secret 进入临时证书存储，签名包安装前验证 Authenticode 状态、签名主体和可信时间戳。

- [ ] 取得组织批准的代码签名证书或 Trusted Signing 配置。
- [ ] 仅在 CI secret/store 中使用证书私钥，不提交、不打印、不写入报告。
- [ ] 使用 SHA-256、时间戳和 SignTool 验证链，记录证书主体、指纹、时间戳和包摘要。
- [ ] 复核 PySide6/Qt、PyInstaller、Visual C++ Runtime 和 Universal CRT 的再分发许可。

完成条件：发布包由目标组织身份签名，目标机器信任链通过，SBOM、许可证、构建来源和包摘要可追溯。

### A4 高敏感真实数据验收

- [x] 保持默认本地模式、无 OpenAI API 调用、无遥测、无自动云同步。
- [x] 报告只输出脱敏证据，不保存原始匹配、完整路径、扫描密钥或完整聊天。
- [x] 增加高敏感模式的显式开关和导出前二次确认；启用后策略强制关闭 API 访问、联网分享验证与原文持久化，切换模式会撤销当前范围同意并要求重新核对。
- [x] 增加独立合成高敏感验收脚本并接入 Windows CI：验证 JSON/HTML/导出报告不含原始标记、剪贴板不留原文、浏览器临时副本删除和临时工作区清理。
- [ ] 补充临时数据清理的独立证据与真实脱敏样本人工验收；当前实现没有把这两个条件伪装成已通过。
- [ ] 用用户提供的脱敏验收样本执行人工验收，不把真实密钥、聊天或病历提交到仓库、CI 或报告。
- [ ] 对依赖、冻结二进制和安装包执行独立供应链扫描与人工复核。

完成条件：安全边界、数据流、留存、删除和发布供应链均有当前版本证据。该条件仍不等于绝对安全或对已被同一用户控制的主机提供保护。

## 阶段二：扩展审计覆盖

### B1 浏览器数据

- [x] 已实现显式选择 Chrome/Edge/Firefox 数据库、临时只读副本、固定计数和清理验证；报告不保留 URL、Cookie、密码或页面正文。
- [x] 已接入桌面按钮，启动时不读取浏览器；当前测试使用合成数据库，真实浏览器配置文件的独立验收仍待执行。

只读、用户逐项选择、默认关闭。第一版只读取受支持浏览器的元数据和固定数据库字段，不复制密码、Cookie value、完整 URL 查询参数或页面正文；数据库复制到临时受控目录，解析失败关闭并清理。Chrome/Edge/Firefox 分别建立格式、锁文件、版本和权限测试。

### B2 剪贴板

- [x] 已实现一次性显式按钮、内存检测、大小上限和失败关闭；报告只保留脱敏 findings，不写回、不记录原文。
- [x] 已接入桌面按钮，启动和后台流程不读取剪贴板；Windows 权限/取消路径的独立验收仍待执行。

只允许用户点击一次性扫描，不在启动或后台读取；读取后立即做内存内规则匹配，只保留脱敏摘要和扫描级指纹，禁止写回剪贴板、日志或报告原文。必须增加取消、失败和 Windows 权限边界测试。

### B3 联网分享验证

作为独立显式网络适配器，不与 OpenAI Provider 共用默认路径。只接受用户粘贴的 URL，限制协议、重定向、响应大小、超时和内容类型，不发送扫描文件、凭据或聊天；结果只说明可达性和公开响应，不宣称搜索引擎索引结论。默认关闭并在 UI 中显示网络发生。

- [x] 已实现独立 `share_verification.py`：仅允许 HTTP(S) origin，拒绝 query、fragment、userinfo 和默认私有地址；限制重定向、响应大小、内容类型和超时。
- [x] 已实现桌面端显式 URL 输入按钮；验证结果只保留 origin、状态码、内容类型、读取字节数和固定限制码，不保留原始响应，也不发送扫描数据、凭据或聊天内容。
- [x] 已加入本地合成 HTTP 服务测试、失败关闭测试和静态自审计声明；本地测试不代表公网分享、代理、证书链或企业网络验收。

完成条件：每项能力都有显式授权、数据最小化、超时/大小上限、失败关闭和独立网络审计；默认本地扫描行为不改变。

## 阶段三：受控自动修复

只实现签名或源码固定的动作白名单：预览、用户逐项确认、目标身份重查、同目录备份、原子替换、回滚和复审。不得执行 LLM 自由生成命令，不得默认撤销密钥或访问 Provider API；密钥撤销只提供人工步骤或后续显式 Provider 适配器。动作失败必须保留原文件并给出 `not_performed`。

- [x] 已实现固定 `replace_fixed_file` 动作内核：dry-run、显式确认、预期 SHA-256 重查、reparse/UNC 拒绝、同目录备份、fsync 后原子替换和条件回滚。
- [x] 已加入目标变更、备份冲突、替换失败、回滚竞态、动作白名单和符号链接边界测试；结果只返回短名称、哈希和固定限制码，不返回完整路径或原文。
- [x] 已把 `OPENAI_BASE_URL_OVERRIDE` 绑定到桌面固定修复流程：同审计范围/同名目标校验、预览、二次确认、固定官方地址替换、原子应用、同会话回滚，以及应用后旧报告失效。
- [ ] 尚未完成真实 Windows 权限、竞态、签名包和独立安装包验收；本地 UI 测试不能替代 Windows MVP 发布验收。

完成条件：每个动作有 dry-run、备份、回滚、权限、竞态、失败和复审测试；动作清单之外一律拒绝。

## 阶段四：团队与企业能力

- [x] 实现离线企业策略控制核：规范 JSON、未知字段/重复键拒绝、角色能力白名单、有效期、操作员配置的 SHA-256 完整性指纹、高敏感二次确认，以及 `mcp_dynamic` 的隔离证明门禁。
- [x] 增加合成数据测试，覆盖策略篡改、过期、角色未授权、高敏感未确认和 MCP 未隔离时的默认拒绝。
- [x] 增加本地事务化企业控制面核心：组织/设备注册与撤回、RBAC 绑定、策略版本单调与撤回、按租户隔离的脱敏元数据导出和到期清理；实现位于 `enterprise_control_plane.py`，不等同于远程控制台、数字签名服务或租户级网络隔离。
- [x] 完成本地离线管理控制面：桌面入口可注册租户/设备、授予角色、导入经校验策略、撤销设备并展示不含原文的运营摘要。
- [x] 增加可选 Ed25519 策略包签名/验签与 `requirements-enterprise.lock`；控制面只有在提供公钥验签器通过后才接受签名策略，默认桌面路径不加载加密依赖。
- [x] 增加不监听网络的企业服务层：租户绑定的管理员 token 哈希/撤销、RBAC 路由、签名策略写入、设备撤销和脱敏审计导出。
- [ ] 完成真正的企业控制台：组织身份、远程设备注册、RBAC 管理、策略签名/版本、租户隔离、最小化遥测、保留/删除策略和管理员导出；当前本地管理页与离线策略核不等于这些服务端能力。
- [ ] 完成签名策略分发、撤销和真实企业网络/权限验收；当前 SHA-256 pin 不是数字签名。

企业控制台不能通过给桌面程序增加一个网络请求解决。需要独立服务边界：组织身份、RBAC、设备注册、策略签名/版本、租户隔离、最小化遥测、保留/删除策略、审计日志和管理员导出。原始敏感证据默认不上传；设备侧先脱敏聚合。该阶段必须先完成威胁模型、隐私评估、部署模型和安全评审，再实现服务端与桌面端协议。

## 阶段五：动态 MCP 隔离

- [x] 实现默认拒绝的动态 MCP 监督器：固定可执行文件和 argv、UNC/reparse 拒绝、显式确认、临时工作目录、请求/输出/运行时上限、无原始输出留存和失败关闭。
- [x] 增加无原生网络/进程树隔离证明时不启动子进程的测试；合成 attestation 仅用于单元测试。
- [x] 实现 Windows Job Object 进程树限制、单进程上限、超时回收和输出上限，并在当前 Windows 环境完成定向实测。
- [x] 提供真实 Windows AppContainer 网络拒绝边界并与 Job Object 进程树限制接通；本地回环连接拒绝和临时 profile 清理已验证。native Windows 路径现在还会在启动前重查 SHA-256 并拒绝未通过本地 Authenticode 信任校验的适配器。组织发布者白名单、正式签名产物、崩溃/重启验收、打包适配器文件可访问性和干净机器证明仍未完成，产品不得因此声称生产安全。

动态 MCP 不得在主进程加载。当前 Windows 路径已有独立受限 helper、固定协议、SHA-256 与嵌入式 Authenticode 校验、超时、输出/进程数上限、无网络默认策略和 Windows Job Object/AppContainer 隔离，并已完成回环拒绝测试。崩溃/重启、打包适配器文件访问、组织发布者白名单、审计日志扩展和独立干净机验收仍是发布门禁；不满足前述门禁时继续默认拒绝。

## 发布决策

以下任一项缺失，发布状态保持 `NO-GO`：可信签名、SBOM/许可证复核、独立干净机安装卸载、真实数据验收、关键安全复审、组织发布者白名单、适配器崩溃/重启证据或动态能力隔离的完整交付证据。无签名 CI 包只允许安装契约 smoke，不允许公开交付。
