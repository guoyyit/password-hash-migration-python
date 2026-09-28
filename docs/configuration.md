# 配置项说明（`ServiceConfig`）

| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `default_algorithm` | `str` | `pbkdf2_sha256` | 所有新设/修改口令与透明重算使用的算法名。 |
| `default_params` | `dict[str,int] \| None` | 很低成本 | 传给默认哈希器的成本参数（如 `{"iterations": 200000}`）。低于此成本的同算法凭据视为陈旧，可被升级。 |
| `max_failures` | `int` | `5` | 连续失败多少次后锁定账号。 |
| `lock_seconds` | `float` | `900.0` | 锁定时长（秒），跨重启持久。 |
| `migration_mode` | `MigrationMode` | `ALWAYS` | `ALWAYS` / `SAMPLED` / `OFF`。 |
| `migration_sample_rate` | `float` | `1.0` | `SAMPLED` 模式下每账号每次成功登录被抽中升级的概率。 |
| `batch_size` | `int` | `0` | 每个滚动窗口最多透明升级的账号数（0 表示不限）。调用 `CredentialService.reset_migration_window()` 或重启进程开启新窗口。 |

## 审计事件

`kind` 被白名单严格限定：

`verify_success`、`verify_failure`、`account_locked`、
`rehash_success`、`rehash_failure`、`password_set`、`password_changed`、
`password_reset`、`account_disabled`、`account_enabled`、`account_deleted`、
`batch_upgrade_considered`、`startup_recovery`。

事件随状态一起原子提交，带单调 `seq`，可以跨重启去重；
**不包含口令、salt、digest 或任何可还原口令的信息。**

## HTTP 接口（`main:app`）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康检查。 |
| POST | `/accounts` | 建号（默认算法哈希）。 |
| POST | `/verify` | 验证，返回是否发生透明迁移。 |
| POST | `/password/change` | 验旧口令后修改。 |
| POST | `/admin/reset` | 管理员重置口令并解锁。 |
| POST | `/admin/disable` / `/admin/enable` | 禁用/启用账号。 |
| DELETE | `/admin/accounts/{username}` | 删除账号。 |
