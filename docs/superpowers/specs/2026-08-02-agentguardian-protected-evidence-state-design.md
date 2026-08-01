# AgentGuardian Protected Evidence State Design

状态：Windows MVP 硬化 Batch 2 设计，继承已确认的本地优先、无默认 API 调用边界。

## 1. 目标与非目标

AgentGuardian 为用户明确保存的审计快照提供 Windows 当前用户范围的 DPAPI 保护。持久化内容只包含规则 ID、脱敏摘要、扫描元数据和扫描级 HMAC 引用；原始匹配、扫描密钥、完整路径、证据来源文件名、Provider 端点和凭据不得进入状态明文或密文载荷。

本批次不增加 OpenAI SDK、HTTP 客户端、API 调用、云同步、自动修复、跨设备恢复、团队共享、后台自动保存或启动时自动加载。状态保存必须由用户显式触发；Founder Alpha、非生产安全结论保持不变。

## 2. 方案选择

采用标准库 `ctypes` 调用 Windows `CryptProtectData`/`CryptUnprotectData`，保存经过 DPAPI 保护的确定性 JSON。该方案不增加第三方依赖，能继续使用现有哈希锁和供应链门禁。

未采用的方案：

- `pywin32` 可简化调用，但会扩大运行时依赖、锁文件和供应链审查面。
- SQLite 适合复杂查询，但当前只有单用户单快照需求，会引入不必要的数据库格式、迁移和锁语义。
- 明文 JSON 即使只有脱敏内容，也不满足已确认的 DPAPI 保护要求。

## 3. 数据契约

明文载荷使用 UTF-8 JSON，schema version 固定为 `1`，键顺序和数组顺序确定。字段如下：

```json
{
  "schema_version": 1,
  "captured_at": "2026-08-02T00:00:00Z",
  "product_version": "0.1.0",
  "rule_version": "1.1.0",
  "scan": {
    "coverage": 1.0,
    "confidence": 1.0,
    "incomplete": false,
    "limits": []
  },
  "findings": [
    {
      "rule_id": "OPENAI_API_KEY",
      "root_hmac_fingerprint": "<64 lowercase hex>",
      "evidence": [
        {
          "hmac_fingerprint": "<64 lowercase hex>",
          "masked": "sk-…末四位"
        }
      ]
    }
  ]
}
```

载荷不保存 `Evidence.source`、扫描根目录、文件路径、原始发现文本、`scan_key`、环境变量值或端点值。finding 与 evidence 使用现有上限 2,000/4,000；序列化明文和 DPAPI 密文分别限制为 1 MiB。读取时重新验证 schema、类型、范围、HMAC 格式和脱敏文本安全规则，任何未知字段、超限或不合法值都拒绝整个状态。

## 4. 组件边界

- `evidence_state.py`：从现有 `Finding`/`Score` 生成不可变快照，执行最小化、排序、JSON 编解码和 schema 验证。它不访问文件系统或 DPAPI。
- `windows_dpapi.py`：只负责 bytes 到 bytes 的当前用户范围保护与解保护；使用 `CRYPTPROTECT_UI_FORBIDDEN`，不接收路径、不记录输入，不把 Windows 错误文本或载荷带入异常。
- `state_store.py`：后续切片负责固定本地路径、大小限制、reparse/symlink 检查、临时文件和原子替换。它组合前两个模块，不解释业务字段。
- `app.py`：后续切片只增加一次显式“保存加密状态”动作；扫描完成不会自动落盘。

自审计必须把上述精确 DPAPI 调用识别为声明过的受限能力，同时继续把其他 `ctypes`/原生调用报告为 `NATIVE_CAPABILITY`。不得用宽泛模块白名单隐藏新增原生能力。

## 5. 错误与恢复

非 Windows 平台返回固定 `DPAPI_UNAVAILABLE`；保护失败返回 `DPAPI_PROTECT_FAILED`；解保护、格式或 schema 失败统一对调用方返回 `PROTECTED_STATE_INVALID`。异常不得包含 Windows 错误文本、状态内容、路径或密钥材料。

损坏、截断、被替换或无法解密的状态不会返回部分数据，也不会自动覆盖。用户仍可继续当前内存中的只读扫描；只有再次显式保存才能创建新状态。

## 6. 验证

- 纯单元测试证明载荷确定、排序稳定、允许字段完整且禁用字段不存在。
- Windows 集成测试证明 DPAPI 往返成功、密文不含明文、篡改密文失败关闭、非 Windows 分支固定失败。
- 自审计回归测试证明只有精确 DPAPI 模块被允许，任意额外 DLL/API/ctypes 用法仍被报告。
- 文件存储测试使用临时目录和合成数据，覆盖超限、reparse/symlink、损坏文件、原子替换失败与原状态保留。
- UI 测试证明没有自动保存，只有明确动作才写入，错误只显示固定安全提示。

## 7. 明确限制

DPAPI 绑定当前 Windows 用户，不能跨用户或跨设备恢复，也不能抵御已经控制同一用户会话的恶意程序。扫描级 HMAC 每次扫描使用新密钥，因此历史状态不能据此稳定关联同一原始值。此批次不构成密钥保险库、备份系统、企业证据链或生产安全证明。
