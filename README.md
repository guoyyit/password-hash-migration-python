# 本地口令凭据存储与平滑升级（Python）

一套纯 Python（FastAPI + SQLite）实现的本地口令凭据管理能力：登记多种
哈希算法、旧哈希在验证成功后透明升级、并发安全、失败锁定、审计与崩溃恢复。

## 快速开始

```bash
uv sync --group dev
uv run uvicorn main:app --reload
# 或跑测试
uv run pytest
```

内存库适用于演示；生产请用文件库并做好备份：

```bash
export CREDSTORE_DB=/var/lib/credstore/creds.db
uv run uvicorn main:app
```

## 核心 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/accounts` | 创建账号（**始终**用当前默认算法哈希） |
| POST | `/accounts/{id}/verify` | 验证；旧算法成功后按策略透明重算 |
| GET | `/accounts/{id}` | 账号状态（不含任何口令数据），含 `needs_upgrade` |
| PUT | `/accounts/{id}/password` | 修改口令（强制默认算法，清锁定） |
| POST | `/accounts/{id}/reset` | 管理员重置，旧口令立即失效 |
| POST | `/accounts/{id}/disable` `/enable` `/unlock` | 禁用 / 启用 / 解锁 |
| DELETE | `/accounts/{id}` | 删除账号，旧凭据不再可用 |
| GET | `/stats` | 总数、默认算法人数、待升级人数、按算法分布 |

验证响应：成功 `{"ok": true}`；口令错误 `{"ok": false}`；锁定返回
`423`；禁用返回 `403`。错误口令与账号不存在返回同构 `200 {"ok": false}`，
避免账号枚举。

## 升级语义

1. 哈希自描述（`$algo$params$salt$digest$`），新算法以**注册而非替换**
   方式加入，历史算法永远可验证。
2. 验证成功且 `needs_upgrade()` 为真（算法不同或成本低于当前配置）时，
   按 `UpgradePolicy` 决定是否立即重算为当前默认算法。
3. 重算在单事务内完成「换哈希 + 台账 + 审计」原子提交；`attempt_id`
   唯一保证同一次升级不重复记账；行版本 CAS 保证与改密/并发登录不互相
   覆盖。
4. 重算失败或被跳过都**不影响本次成功登录**，也不重置失败计数。
5. 未升级账号始终可以旧算法正常登录；新设施口令/改密/重置一律使用默认
   算法。

## 节奏与成本控制（避免突发负载）

`UpgradePolicy`：

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `True` | 关闭后只验证不重算 |
| `rollout_fraction` | `1.0` | 每次登录触发重算的概率（0~1），按比例灰度 |
| `max_upgrades_per_minute` | `None` | 每进程每分钟重算上限（滑窗限流） |
| `rehash_cost` | `None` | 升级时使用的成本（PBKDF2 迭代数），可分批抬升 |

`CredentialService.pending_upgrades(limit)` / `stats()` 可用于按批次观察
与推进迁移；受成本预算限制，限流/采样被跳过时会记录 `rehash_skipped`
事件，账号登录不受影响。

## 锁定策略 `LockoutPolicy`

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `max_failures` | `5` | 连续失败多少次后锁定 |
| `lockout_seconds` | `900` | 锁定时长，到期自动解锁 |
| `failure_window_seconds` | `None` | 失败计数滑动窗口；超时连失败清零 |

锁定状态持久化，跨重启保持；锁定过期是惰性的，无需后台任务。

## 审计

所有验证成功/失败、锁定、重算成功/失败/跳过、改密、重置、禁用、启用、
删除均记录事件（内存 sink 与 SQLite `audit_log` 双写）。事件禁止携带
`password/hash/digest/salt` 等敏感键（写入前强校验抛错），仅记录算法 id、
版本、计数、原因等非敏感字段。

## 代码结构

```
src/credential_store/
  errors.py    # 领域异常
  hashers.py   # 自描述编码、PBKDF2/SHA256/SHA512、legacy SHA-1、注册表
  config.py    # UpgradePolicy / LockoutPolicy / CredentialConfig
  storage.py   # SQLite：CAS 行版本、升级台账、审计表、即时事务
  audit.py     # 事件类型、敏感字段守卫、sink
  service.py   # 验证/透明升级/锁定/限流编排
  app.py       # FastAPI
tests/         # 哈希、存储、并发、锁定、持久化、新算法兼容、HTTP
docs/storage-format.md
```

## 安全说明

* 明文口令仅作为方法入参短暂存在于栈上，不写日志、不缓存、不落库。
* 哈希比对使用 `hmac.compare_digest` 常量时间比较。
* 盐值每哈希独立随机；同一口令两次编码结果不同。
* 重置、禁用、删除后旧凭据立即失效（重置会换哈希并清锁定；禁用直接拒绝；
  删除行不存在）。
