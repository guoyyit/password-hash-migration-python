# credvault — 本地口令凭据存储、验证与哈希平滑升级

一套零外部服务依赖（纯标准库哈希 + 单个 JSON 文件持久化）的口令凭据管理库，
支持多哈希算法并存、旧口令登录时**透明升级**、失败锁定、账号生命周期管理、
升级节奏控制、可审计事件与崩溃恢复。

## 能力总览

1. **多算法/多参数版本并存**：每个账号记录各自的算法与成本；新增算法不破坏旧数据。
2. **验证后透明重算**：旧算法验证成功即在同一原子事务内重算为当前默认算法；
   并发登录/改密/重试交错时无半升级；重算失败不回退本次成功验证。
3. **口令生命周期**：新设/修改口令强制使用默认算法；支持禁用、删除、管理员重置；
   重置或禁用后旧凭据立即失效。
4. **升级节奏可控**：按比例（`SAMPLED`）、按批次（`batch_size`）或显式批量
   （`run_upgrade_batch`）控制升级速度与哈希成本；未迁移账号照常登录。
5. **失败锁定**：连续失败计数、自动锁定、锁定过期；锁定状态跨重启保持；
   重算过程不重置也不绕过失败计数。
6. **审计**：验证失败、锁定、重算成功/失败等全部事件持久化；日志绝不含口令、
   salt、digest 等敏感数据。
7. **崩溃恢复**：临时文件 + `fsync` + 原子 rename；升级、锁定、改密与审计事件
   同事务落盘，重启不丢失、升级不重复记账。
8. **自动化测试与文档**：49 个测试覆盖旧算法验证、并发重算、锁定/重置、
   中断恢复、新增算法兼容等；详见 `docs/`。

## 快速开始

```python
from credvault import CredentialService, ServiceConfig, MigrationMode

config = ServiceConfig(
    default_algorithm="pbkdf2_sha256",
    default_params={"iterations": 200_000},
    max_failures=5,
    lock_seconds=900,
    migration_mode=MigrationMode.SAMPLED,   # 按比例平滑升级
    migration_sample_rate=0.1,              # 每次登录 10% 概率升级
    batch_size=100,                         # 每窗口最多 100 个
)
svc = CredentialService.open("credentials.json", config)

svc.create_account("alice", "initial-password")   # 始终用默认算法
result = svc.verify("alice", "initial-password")  # 旧账号成功后自动透明升级
print(result.migrated)                             # 本次登录是否完成升级

svc.change_password("alice", "initial-password", "new-password")
svc.reset_password("alice", "admin-set-password")
svc.disable_account("alice")
svc.delete_account("alice")
```

运行 HTTP 服务：`uv run fastapi dev main.py`（接口见 `docs/configuration.md`）。

## 注册新算法（平滑演进示例）

```python
from credvault import default_registry, CredentialService, ServiceConfig

svc = CredentialService.open("credentials.json",
                             ServiceConfig(default_algorithm="scrypt",
                                           default_params={"n": 2**15}))
svc.register_algorithm(my_brand_new_hasher, set_default=True)
# 旧账号依旧可登录，并在登录时逐步迁移到新算法
```

## 测试

```bash
uv run pytest
```

## 文档

- [`docs/storage-format.md`](docs/storage-format.md) — 存储格式、敏感数据策略、崩溃恢复。
- [`docs/upgrade-semantics.md`](docs/upgrade-semantics.md) — 透明升级、并发与节奏语义。
- [`docs/configuration.md`](docs/configuration.md) — 配置项、审计事件与 HTTP 接口。

## 安全说明

本库不做密钥派生结果的内存清零（Python 字符串不可变），而是保证明文口令
不落盘、不入日志/审计、不被返回；所有哈希均使用随机 salt（遗留无盐算法仅用于
验证历史数据并会被尽快升级），并通过 `hmac.compare_digest` 做常量时间比较。
