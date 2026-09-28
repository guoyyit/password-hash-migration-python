# 存储格式与持久化语义

持久层使用单个 SQLite 数据库（默认 `:memory:`，可用环境变量 `CREDSTORE_DB`
或构造参数指定文件路径），开启 `WAL` 日志模式与 `synchronous=FULL`。
所有写操作通过 `BEGIN IMMEDIATE` 显式事务 + `commit` 落盘，崩溃时事务
要么完整可见、要么完全不可见，不存在部分写入。

## 1. 自描述口令哈希

每条哈希字符串完全自描述，不依赖任何全局配置即可还原算法与参数：

```
$<algorithm-id>$<k=v,k=v 参数段>$<salt base64url>$<digest base64url>
```

| 段 | 含义 |
| --- | --- |
| `algorithm-id` | 算法族 + 版本标识，如 `pbkdf2_sha256`、`legacy_sha1`、`argon_future` |
| 参数段 | 算法参数，如 `i=200000,v=1`（PBKDF2 迭代次数与版本） |
| salt | 每次加盐随机生成（`secrets.token_bytes`） |
| digest | 密钥派生结果，base64url 无填充编码 |

内置算法：

* `pbkdf2_sha256`（默认，200_000 轮，可配置覆盖）
* `pbkdf2_sha512`（并行登记的备选默认）
* `legacy_sha1`（仅为验证历史数据保留：salt + SHA-1）

新增算法只需实现 `PasswordHasher` 协议并 `registry.register(...)`；
旧算法实现必须一直保留注册，旧数据因此永远可被验证。把新算法设为默认
（`set_default` 或 `default_algorithm_id` 配置）不影响历史行。

明文口令绝不落库；审计日志与任何返回值中也不包含明文或哈希值。

## 2. 表结构

### `credentials`

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `account_id` | TEXT PK | 账号 |
| `encoded_hash` | TEXT | 自描述哈希（**唯一**与口令相关的持久数据） |
| `algorithm_id` / `algo_version` | TEXT/INT | 冗余算法标识，便于统计与扫描 |
| `disabled` | INT | 禁用位；禁用后验证一律拒绝 |
| `failed_count` | INT | 当前连续失败次数 |
| `last_failure_at` | REAL | 最近一次失败时间（滑动窗口用） |
| `locked_until` | REAL | 锁定截止时间；过期即自动解锁 |
| `row_version` | INT | 乐观锁版本，每次变更 +1（CAS） |
| `created_at` / `updated_at` | REAL | 时间戳 |

### `upgrade_ledger`（升级台账）

| 列 | 说明 |
| --- | --- |
| `attempt_id` | **主键**，每次升级尝试生成 UUID；同一次升级重复提交返回 no-op，不重复记账 |
| `account_id`, `from_algorithm`, `to_algorithm` | 升级来源/目标 |
| `committed_at` | 提交时间 |

### `audit_log`

`event_type / account_id / ts / detail(JSON)`。`detail` 中的键名经过
敏感词校验（`password`、`hash`、`digest`、`salt` 等一律拒绝写入），
因此日志不可能泄露口令或可用于离线猜测的哈希。

## 3. 原子升级与并发

透明重算在**单个** `BEGIN IMMEDIATE` 事务内完成：

1. 读取当前行并核对 `row_version`（CAS）；
2. 检查 `attempt_id` 是否在台账中（幂等去重）；
3. 更新哈希、算法标识，`row_version + 1`；
4. 插入台账记录，并在同一事务插入审计事件；
5. `commit`。

* 并发登录：进程内每账号一把锁串行化同账号验证；跨进程由 SQLite 写锁
  与 CAS 兜底，失败者安全重试（账号仍可登录）。
* 验证成功但重算失败/被限流：**验证结果不回退**，只写 `rehash_failed`
  / `rehash_skipped` 审计；旧哈希原样保留，下次登录再试。
* 与改密交错：改密与重算都以 `row_version` 做 CAS，先到者提交，后到者
  检测到版本变化后放弃/重试，不会互相覆盖。
* 升级事务**不触碰** `failed_count`/`locked_until`，只有“验证成功”本身
  才清空失败计数；锁定的账号不会进入重算分支。

## 4. 锁定语义

失败计数与锁定时间持久化在 `credentials` 行内，重启后保持。达到
`max_failures` 写 `locked_until = now + lockout_seconds`，验证路径上
惰性过期（过期立即解锁）。可选 `failure_window_seconds`：超过窗口没有
新失败则旧连失败作废。重置口令、管理员解锁、启用账号都会清空锁定状态。

## 5. 崩溃恢复

* 已提交的升级（行更新 + 台账 + 审计同一事务）在重启后完整存在；
* 崩溃发生在提交之前：台账无记录、行未变，账号仍以旧哈希正常登录，
  登录成功后再次尝试升级，天然不重复记账；
* 锁定、禁用、口令变更均为独立已提交事务，同样跨重启保持。
