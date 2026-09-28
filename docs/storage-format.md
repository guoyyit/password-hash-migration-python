# 存储格式与崩溃恢复

## 存储位置

所有凭据、锁定状态与审计事件保存在 **单个 JSON 文档** 中（默认
`credentials.json`，由 `CredentialService.open(path, ...)` 指定）。
不使用数据库，零外部依赖。

```json
{
  "version": 1,
  "audit_seq": 7,
  "accounts": {
    "alice": {
      "credential": {
        "algorithm": "pbkdf2_sha256",
        "version": 1,
        "disabled": false,
        "params": {
          "salt": "base64...",
          "iterations": 120000,
          "digest": "base64..."
        }
      },
      "lock": {
        "fail_count": 0,
        "locked_until": null,
        "last_fail_at": null
      },
      "rehash_epoch": 1
    }
  },
  "events": [
    {"seq": 1, "at": 1770000000.0, "kind": "password_set",
     "username": "alice", "detail": {"algorithm": "pbkdf2_sha256"}}
  ]
}
```

### 字段语义

| 字段 | 含义 |
| --- | --- |
| `version` | 存储格式版本，便于未来再次演进。 |
| `audit_seq` | 已持久化审计事件的最大单调序号。 |
| `accounts.<u>.credential.algorithm` | 哈希算法稳定标识，如 `pbkdf2_sha256`、`scrypt`、`legacy_sha256_salted`。 |
| `accounts.<u>.credential.params` | 算法参数（salt、cost、digest）。全部 base64/数字，JSON 安全。 |
| `accounts.<u>.credential.disabled` | 禁用标志；禁用后任何口令都不能通过验证。 |
| `accounts.<u>.lock.fail_count` | 连续失败次数，成功验证后清零。 |
| `accounts.<u>.lock.locked_until` | 锁定截止的 Unix 时间戳；过期后自动解锁。 |
| `accounts.<u>.rehash_epoch` | 已完成升级/改密的次数，用于检测“同一次升级被重复记账”。 |
| `events[].seq` | 进程内与持久化均单调递增的事件序号，重启后据此去重。 |

## 明文口令策略

- 明文口令只作为函数参数短暂存在于局部变量；Python 字符串不可变，
  无法被显式清零，因此实现保证 **不写入任何字段、不进入日志、不进入审计**。
- `params` 中只有 salt 与 digest，没有也无法还原明文（单向 KDF + 随机盐）。
- 审计写入路径会拒绝包含 `password`/`digest`/`hash`/`salt`/`token` 等
  键名的 detail（见 `credvault.audit.FORBIDDEN_DETAIL_KEYS`）。

## 原子写与崩溃恢复

每次提交执行：

1. 在目标目录创建临时文件 `.credvault-*.tmp`；
2. 写入完整 JSON → `flush()` → `fsync()`；
3. `os.replace()` 原子替换目标文件；
4. `fsync` 父目录，保证 rename 落盘。

因此崩溃时只能观察到“上一个完整版本”或“新版本”，**不会出现半升级**。
升级后的凭据、锁定状态、口令变更与对应审计事件在 **同一次提交** 中落盘，
二者不可能分离。重开服务时按 `rehash_epoch` 与事件 `seq` 判定升级已完成，
不会把同一次升级重复记账。
