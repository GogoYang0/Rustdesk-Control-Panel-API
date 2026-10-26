# 部署指南（Deployment Guide）

> 适用版本：v0.10.0（M6 波次 1：交互式验证码；上一基线 v0.9.0）。本文档随版本演进持续更新——每次发布前必须复核一遍。
> 配套文档：[运维指南](operations.md) · [后端 API 规范](api-spec.md)

---

## 1. 系统要求

| 项 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Linux（推荐）或 Windows | panel 本身是单一 Go 二进制 |
| Go | 1.27+ | 仅构建时需要；发布产物为静态二进制 |
| Docker | 20.10+；**生产使用 rootless Docker 或受限的 Docker socket proxy**（见 §8） | 使用 provisioning 功能时需要（默认每组织自动供应，可用 `PUT /api/v1/orgs/{orgId}/provisioning` 按组织关闭）：panel 经 Docker CLI 操作容器，实际地址用 `DOCKER_HOST` 环境变量或 Docker CLI context 指定，**不要默认依赖 rootful 原始 socket** |
| 数据库 | SQLite（默认）/ PostgreSQL / MySQL | 生产建议 PostgreSQL |
| 端口 | `:8080`（panel API）、`21116–22115`（hbbs/hbbr，可配；逐端口协议分布见 §7——仅每组织的 `HbbsPort+1` 同时用 TCP+UDP，其余 TCP） | 反代后面只需暴露 panel 的 443 |

> **provisioning 开关与端口探测**：不需要 RustDesk 服务端的组织，由 owner 调用
> `PUT /api/v1/orgs/{orgId}/provisioning`（`enabled=false`）关闭并下线，避免占用端口与容器。
> panel 启动时探测 `provision.portStart..portEnd`（跳过已有 `ServerGroup` 预留块），把面板外
> 占用写入告警日志；部署前还会对本块端口做预检，冲突错误包含具体端口。探测绑定**本机 IPv4**
> 端口（IPv6-only 监听不在探测范围），默认部署假定 panel 与 Docker 同宿主；`DOCKER_HOST`
> 指向远端时探测结果不适用，需以端口规划为准。

---

## 2. 构建

```bash
go build -o panel ./cmd/server
```

发布产物为单二进制；不依赖任何运行时。配置固定从工作目录下的 **`configs/config.yaml`** 读取（`config.Load("configs/config.yaml")`）——部署时保留 `configs/` 目录结构并按需修改，**不要拍平到工作目录**。

---

## 3. 配置全表

下表六个敏感项只从环境变量注入，禁止写入配置文件：

### 3.1 环境变量（敏感项，禁止写入配置文件）

| 变量 | 必须 | 说明 |
|---|---|---|
| `PANEL_AUTH_SECRET` | 是 | JWT 签名密钥。未设置时进程拒绝启动（`auth.secret must be configured`）。用 `openssl rand -base64 48` 生成；**泄漏等于任何人可伪造令牌** |
| `PANEL_SMTP_PASSWORD` | 条件 | `mail.devMode=false` 且设置了 `mail.smtp.username` 时必须；否则启动即失败 |
| `PANEL_WEB_BASE_URL` | 条件 | 覆盖 `web.baseURL`；`devMode=false` 时必须是公网 https origin，否则启动失败（验证码/邀请链接会嵌入此地址） |
| `PANEL_CAPTCHA_ALTCHA_KEY` | 条件 | `captcha.enabled=true` 且 `provider=altcha` 时必须，且**长度 ≥32 字节**（建议用 `openssl rand -base64 48` 生成）；缺失或过短均启动失败 |
| `PANEL_CAPTCHA_GEETEST_KEY` | 条件 | `captcha.enabled=true` 且 `provider=geetest` 时必须 |
| `PANEL_CAPTCHA_CAP_SECRET` | 条件 | `captcha.enabled=true` 且 `provider=cap` 时必须 |

### 3.2 配置节

| 节 | 键 | 默认 | 说明 |
|---|---|---|---|
| `server.addr` | | `:8080` | HTTP 监听地址 |
| `auth.accessTTL` / `auth.refreshTTL` | | `15m` / `168h` | 管理 JWT 的访问/刷新令牌有效期；刷新令牌轮换 + 重放撤销 |
| `database.driver` | | `sqlite` | `sqlite` \| `postgres` \| `mysql` |
| `database.dsn` | | `file::memory:?cache=shared` | **加载器默认是共享内存 SQLite（重启即失数据）**——生产必须显式设置持久化 DSN，如 `file:data/panel.db`；生产建议 PostgreSQL |
| `log.level` / `log.format` | | `info` / `json` | zap 结构化日志；`json` 便于采集 |
| `provision.portStart/End` | | `21116–22115` | 每组织占用**连续 5 个**主机端口（`PortBlockSize=5`，见 §7 协议分布）；默认范围最多支持 200 个组织 |
| `provision.relayHost` | | — | **必须是客户端可达的公网地址**，无回退 |
| `provision.orgLabel` / `provision.roleLabel` | | `com.rustdesk-panel.org` / `com.rustdesk-panel.role` | 容器标签键 |
| `provision.image` | | —（无加载器默认，未配置时供应失败） | 必须显式配置并**使用固定 tag**（运行时仅校验非空）；推荐 `rustdesk/rustdesk-server:1.1.11`——**日志采集规则按此镜像的日志格式编写**，换镜像必须重新校准规则 |
| `provision.dataDir` | | `./data/servergroups` | 各组织 hbbs/hbbr 的密钥与数据目录（挂载进容器） |
| `provision.maxOrgsPerUser` / `workers` | | `5` / `2` | 单用户组织上限 / 供应队列并发 |
| `mail.devMode` | | `true` | `true` 时邮件打印到 stdout（开发）；生产必须 `false` |
| `web.baseURL` | | `http://localhost:5173` | 前端 origin，用于构造邮件链接 |
| `logcollect.enabled` | | `false` | 日志采集总开关（见运维指南 §4） |
| `logcollect.containerPrefix` | | `panel-org` | 容器命名前缀，实际为 `panel-org-<orgId>-hbbs/hbbr` |
| `logcollect.retentionSweepInterval` | | `6h` | 日志事件保留期（30 天）的清扫间隔，最小 `1m`；`0` 表示**完全停用保留期清理**。非 0 时启动即清扫一次并按间隔周期执行，与 `logcollect.enabled` 无关，见运维指南 §4.2 |
| `logcollect.rules` | | **空（无内置默认）** | 省略即零规则：所有行按 unparseable 计数丢弃。必须显式配置（示例 `configs/config.yaml` 含 4 条经 1.1.11/1.1.16 实测的规则）；规则按序匹配、首条命中即停；命名捕获组 `device` 关联设备。断开事件（`kind: disconnected`）默认不配置，原因与加法见 §6 第 6 条 |
| `compat.accessTTL` | | `720h` | compat 会话（RustDesk 客户端令牌）的有效期；成员失去组织访问时应通过会话撤销立即失效（见运维指南 §2.1/#39） |
| `session.idleTimeout` | | `10m` | 会话空闲超时：open 会话超过该时长无活动（无活动记录则回退 `started_at`）由空闲清扫任务置 `closed`（`end_reason=idle_timeout`）；契约的"部署可配置"项。**必须为正**：`0`/负值不是禁用清扫，而是记 warning 并回退默认 `10m` |
| `audit.archiveDir` | | `./data/audit-archive` | 按组织归档审计文件的根目录（`org-<orgId>/audit-<minId>.jsonl` + `.sha256`）。组织设置 `audit_retention_days > 0` 时每小时先归档校验、后删除；**备份范围必须包含该目录**（见运维指南 §3、§7） |
| `captcha.enabled` | | `false` | 公开凭据入口（登录 / 2FA 校验 / 邀请接受）的交互式验证码总开关（v0.10.0，见运维指南 §2.4） |
| `captcha.provider` | | `altcha` | `altcha`（自托管 proof-of-work，无外部依赖）\| `geetest` \| `cap` |
| `captcha.failMode` | | `closed` | `closed`：提供商不可达 → `503`；`open`：放行并打 error 日志，**仅限临时运维窗口**（提供商判定失败永不因该值放行） |
| `captcha.challengeTTL` | | `5m` | 挑战有效期，必须在 `1m–10m` 之间 |
| `captcha.altcha.maxNumber` | | `100000` | PoW 解题上限（`10000–5000000`）：越高越难被批量爆破，也越考验低端客户端 CPU |
| `captcha.geetest.captchaId` | | — | GeeTest v4 的 captcha id（启用且选择 geetest 时必填） |
| `captcha.cap.instanceUrl` / `siteKey` | | — | 自托管 Cap Standalone 的地址与 site key（启用且选择 cap 时必填） |

---

## 4. 数据库与迁移

### 4.1 首次启动

启动序列（`cmd/server/main.go`）按以下顺序执行，任何一步失败都会 `Fatal` 退出：

1. 加载配置 → 构建 logger
2. 校验 `PANEL_AUTH_SECRET` → 打开数据库
3. **AutoMigrate** 全部模型（GORM 自动建表/加列）
4. **一次性回填**：`email_verified` 历史数据回填，成功后写迁移标记（MigrationMark）；已有标记则跳过
5. **角色与访问控制收敛**：`MigrateRoles` 把旧 `role` 字符串一次性回填为 `role_id`（有标记则跳过）；`MigrateAccessPermission` 每次启动按当前内置权限目录**重写**内置 owner/admin 角色的整个权限集（owner 为全集、admin 为内置集合，因此都包含 `access.manage`；自定义角色不动）；`access.Migrate` 每次启动按组织幂等收敛——缺 `everyone` 用户组的组织补建该组与默认规则（组已存在但默认规则被删除时**不会**重建）
6. 校验邮件配置（`mail.devMode=false` 时的三项检查）
7. 启动后台 worker（日志采集 tailer、provision 队列、**worker 调度器**（保留期清扫等周期任务）、对账 reconciler）
8. 监听

### 4.2 升级

- 新版本新增列时 AutoMigrate 自动处理（**含新增索引**——已有大表的 MySQL/PostgreSQL 上首次启动会执行建索引 DDL，可能短暂持写锁，请避开业务高峰）；**删除列/收窄列不会自动执行**（如 `Device.BoundUUID` 保持 255 的原因）
- **升级期间禁止并行启动实例**：回填会把当前所有未验证账户标为已验证——若另一实例在回填完成前启动并创建了新的未验证账户，该账户也会被误标为已验证，**绕过邮箱验证边界**。正确流程：先停止或隔离其他实例 → 启动一个实例完成回填并写入迁移标记 → 再启动其余实例
- 升级前备份 `panel.db`（或数据库快照）与 `data/servergroups/`
- **v0.9.0（访问控制）升级要点**：
  - 新增表 `user_groups` / `user_group_members` / `device_groups` / `access_rules` 与列 `devices.device_group_id`，由 AutoMigrate 建表/加列/建索引。
  - 启动收敛会按当前内置权限目录**重写**内置 owner/admin 角色的权限集（因此包含 `access.manage`；是整套重写而非单纯追加，自定义角色不受影响）。该权限**不可委派**，自定义角色在任何情况下都无法获得（不是“需要授权”，而是被目录禁止）。**v0.9.0 之前签发的个人 API Token 权限集不含 `access.manage`**，必须重建令牌后才能在令牌身份下管理访问控制（令牌权限是申请集 ∩ 当前角色权限集的硬上限）。
  - 存量组织自动生成 `everyone` 用户组与 `everyone → 全部设备` 默认规则，**未停用设备**的访问范围不变；停用设备从 v0.9.0 起不再出现在客户端设备列表（管理面仍可见）。删除默认规则后重启不会复活，按运维指南 §2.3 收紧。
  - 多实例并行启动仍按 §4.2 的既有约束（角色回填是一次性标记，先由单实例完成）。
- **v0.10.0（交互式验证码）升级要点**：
  - 无数据库结构变化；`captcha.enabled` 默认 `false`，升级后行为与 v0.9.0 完全一致。
  - 启用前必须选定提供商并注入对应秘密（见 §3.1）；启用后**所有**管理面登录、2FA 校验与邀请接受都需要验证码，脚本化登录应改用个人 API Token（v0.8.0）。
  - 验证码**挑战本身无状态（签名可在任意实例校验）**，但「已消耗凭据」与登录限流都在**进程内存**。两者是**不同**的约束，不要混为一谈：
    - **单次消费**的键是凭据标识、**与客户端 IP 无关**，按 IP 粘性路由**不能**提供跨实例的全局单次消费保证——攻击者从不同源 IP 重放同一凭据就可能命中未记录该凭据的实例并再次进入密码/TOTP 校验。需要该保证时必须**单副本**部署，或改用共享消费存储（本版本未提供，属后续扩展）。
    - **登录限流**（每 IP 每分钟桶、账号+IP 失败计数）按 IP 计费，粘性路由对它是有效的。
  - 进程重启同样会清空消费表：重启窗口内的重放只能靠提供商的自身限制与 IP 桶约束。
  - `provider=cap` 需要单独部署并运维 Cap Standalone；`closed` 模式下 Cap 不可用等于三个入口不可登录。`provider=geetest` 依赖境外服务，部署前确认网络可达。
- **v0.10.0（组模型下半场：归属 / 组→组规则 / 组级地址簿授权 / 旧列清理）升级要点**：
  - **不可回滚点**：启动时删除 `memberships.role` 字符串列（迁移顺序为「先把旧字符串映射到 `role_id`，再删列」，顺序不可交换）。**升级前必须备份数据库**——回滚到旧版本需要恢复数据库快照，旧版本无法在缺少该列的库上正常授权。迁移由标记守护且可重试：映射失败（例如出现未知角色字符串）会**中止启动**，此时列尚未删除，修数据后重启即可。
  - 新增列/索引：`devices.owner_user_id`（索引）、`devices.note`；地址簿授权的唯一索引由三列**重建**为四列（`book_id, subject_kind, subject_user_id, subject_group_id`）——该重建由迁移标记守护、**只在首次启动执行一次**（大表首启会执行一次索引重建 DDL，请避开业务高峰），此后每次启动直接跳过。
  - **归属（`owner_user_id`）不自动回填**：存量设备升级后均未归属。此后**首次**登录（成功认领）的设备自动归属给登录用户，**前提是登录请求携带的 `uuid` 与该设备的绑定一致**；未带 `uuid` 的登录不会产生归属（归属是持久授权，只凭 rustdesk id 不得取得），这类设备需管理员 `PATCH` 改派或让客户端正常带 uuid 重新登录。已归属设备不会被登录改写。希望立即按「本人只看自己设备」收敛的部署，请在管理面批量改派（`PATCH .../devices/{deviceId}`）或让用户各登录一次。
  - **访问范围变化（加宽）**：普通成员现在**始终**能看到并连接自己归属的设备（停用设备/停用会籍除外），这与默认 `everyone → 全部设备` 规则叠加不产生新暴露；但如果组织已收紧到精确规则，请知悉「本人设备」这条兜底路径不受规则约束（要收走需改派归属或停用设备，见运维指南 §2.3.1）。
  - 若客户端使用 `rustdesk --assign`：需要为该客户端所属账号签发**个人 API Token**（`device.write`）并配置到客户端；`--strategy`、`--address-book-*`、`--device-username` 会被面板 `400` 拒绝（未实现，属有意行为）。
  - 客户端 `--device-name`/`--note` 以及管理面归属变更**不撤销已建立的 compat 会话**（与规则变更一致）。

- **v0.10.0（控制角色 / 客户端审计上报 / compat 2FA）升级要点**：
  - **无新增配置键**：控制角色的三态权限、日志保留期都复用既有配置（保留期用 `organizations.audit_retention_days`）。升级后行为与波次 2 一致。
  - 新增表 `control_roles` / `connection_logs` / `file_logs` / `audit_nonces` / `compat_login_challenges` 与新列 `memberships.control_role_id`、`tickets.control_role_id` / `control_permissions` / `control_role_snapshot`、`sessions.control_permissions`，全部由 AutoMigrate 建表/加列/建索引（大表首启会有建索引 DDL，请避开业务高峰）。
  - 启动时为每个组织补齐内置 `default` 控制角色（幂等，按 `(organization_id, name)` 唯一索引兜底并发启动）；**新组织在创建事务里同步播种**，不存在「重启前没有回退角色」的窗口。
  - **控制角色不约束原生客户端会话**：权限位图由 hbbs 注入，面板不在信令链路。升级后可以在管理面配置并拿到票据快照，但不要向业务方承诺客户端已强制执行（详见 API 规范 §3.12、运维指南 §2.5）。
  - compat 登录 2FA 依赖 `auth.secret`：**未配置或不一致时 2FA 操作 fail closed**；轮换 `auth.secret` 会让既有 TOTP 秘密无法解密，须先重置用户 2FA。多实例共享同一 `auth.secret`，否则挑战与 TOTP 校验会随机失败。
  - `compat_login_challenges` 与 `audit_nonces` 都有内置清扫：过期挑战由 `compat-2fa-sweep` 每小时清理（保留 1 小时余量），nonce 由 `audit-nonce-sweep` 每 10 分钟清理。两项都无需人工干预。

- **v0.10.0（客户端策略下发与心跳断连）升级要点**：
  - **无新增配置键**：策略内容存库，下发搭在客户端已有的 `POST /api/heartbeat` 上（客户端只要连得到 API server 就能拿到）。升级后行为与波次 3 一致。
  - 新增表 `strategies` / `device_disconnects` 与新列 `devices.strategy_id`、`device_groups.strategy_id`、`memberships.strategy_id`、`device_heartbeats.conn_ids`，全部由 AutoMigrate 建表/加列/建索引（`devices`/`device_groups`/`memberships` 会各加一个索引，大表首启请避开业务高峰）。另给 `device_heartbeats` —— **最高写入量的表** —— 加一列 `conn_ids`，MySQL 上是 instant DDL，PostgreSQL 上是元数据变更，但请按大表操作安排窗口。
  - **没有默认策略、不回填**：升级后所有设备「无策略」，行为与升级前完全一致；需要下发的组织自行创建并分配。
  - 新增权限 `strategy.manage`、`device.disconnect`（均不可委派，owner 全量、admin 由内置集合授予）。内置集合每次启动重写，存量组织自动获得。
  - 新增 worker `disconnect-expiry`（每 5 分钟）清理超时未消费的断连请求。策略没有后台任务。
  - **`--assign strategy_name` 由拒绝改为支持**（波次 2 的 D5 反转）：客户端可用策略名分配，大小写不敏感，未知名字 404。
  - **生效边界**：策略只在客户端下次心跳后生效（≤30 秒），断连最长同样等一个心跳周期；面板不在信令链路，不保证即时。详见 API 规范 §3.14/§3.15、运维指南 §2.7。

### 4.3 选择生产数据库

SQLite 的 `occurred_at` 等时间列按**文本比较**（UTC 格式化），行为已与 MySQL/PostgreSQL 对齐测试（`test-db` CI）。生产选 PostgreSQL：

```yaml
database:
  driver: postgres
  dsn: "host=127.0.0.1 user=panel password=... dbname=panel port=5432 sslmode=disable"
```

> ⚠️ 上面带 `sslmode=disable` 的片段**仅适用于 panel 与 PostgreSQL 同机的场景**。PostgreSQL 在其他主机时凭据与数据会明文传输（CWE-319），必须启用 TLS 校验：
> `sslmode=verify-full`（校验证书链与主机名），并提供 `sslrootcert=/path/to/ca.crt` 指向受信任 CA、确认 `host` 与证书 SAN 匹配。

---

## 5. 邮件投递

- `mail.devMode=true`：所有邮件写 stdout（开发/内网体验）
- 生产：`devMode=false` + 填 `mail.smtp.{host,port,username,from}` + 环境变量 `PANEL_SMTP_PASSWORD`
- 投递语义（运维含义见 [运维指南 §5](operations.md)）：
  - **非 465 端口**的服务器不支持 STARTTLS → 不发送（拒绝明文凭据）
  - **465 端口使用隐式 TLS**，不要求 STARTTLS（两种受支持形态）
  - 5xx 永久错误 → 不重试
  - 结果不明（连接中断）→ 保留验证码/令牌，可重发
- 验证码有效期与一次性语义见 [API 规范 §4.4](api-spec.md)

---

## 6. 日志采集启用清单

`logcollect.enabled=true` 前逐项确认：

1. panel 进程能访问 Docker（`docker ps` 可用）
2. `provision.image` 是 `rustdesk/rustdesk-server:1.1.11`（或已按其真实日志格式校准规则）
3. 用 `docker logs -t panel-org-<id>-hbbs` 抽样验证规则能匹配真实行（本地可跑 `TestExampleConfigRules_MatchServerFormat` 参照）
4. 首次连接只跟随新行（`--tail 0`），历史日志不会回灌——需要历史数据请在启用前导出
5. 启用后 30 天内的事件自动保留，超期事件在启动时及每个 `logcollect.retentionSweepInterval` 周期清扫——与采集启停无关（见运维指南 §4.2）
6. **断开事件（`disconnected` 规则）默认不配置**：rustdesk-server 在默认日志级别下不打印任何连接结束日志（其唯一 close 行是 debug 级且只含 socket 地址、无设备 id——已对照 rustdesk-server `src/rendezvous_server.rs` 核实），因此没有可匹配的真实格式。无法产生结束事件的会话由空闲清扫兜底关闭（窗口 `session.idleTimeout`，默认 10 分钟）。若你的日志源确实产生可识别的断开行（改过日志级别或自定义服务端），在 `configs/config.yaml` 的 `connection` 规则**之前**添加 `kind: disconnected` 规则（规则按序首匹配，否则会被宽泛的 connection 规则吞成连接事件）

---

## 7. 反向代理与 TLS

panel 自身只出 HTTP；对外必须经反向代理终止 TLS：

```nginx
server {
    listen 443 ssl;
    server_name panel.example.com;
    ssl_certificate     /etc/nginx/tls/panel.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/panel.example.com.key;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-Proto https;
    }
}

# Web client websocket entries: one TLS server block per entry, shown for the
# first organization (HbbsPort+2 = 21118, HbbrPort+1 = 21120); repeat per
# organization port with distinct server names or listen addresses.
# Upgrade/Connection are mandatory -- nginx does not forward hop-by-hop
# headers by default, and the handshake fails without them. X-Forwarded-For is
# deliberately set to $remote_addr: it overwrites any client-supplied chain,
# so a forged header cannot poison the address the RustDesk server records.
server {
    listen 443 ssl;
    server_name hbbs-ws.example.com;
    ssl_certificate     /etc/nginx/tls/hbbs-ws.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/hbbs-ws.example.com.key;
    location / {
        proxy_pass http://127.0.0.1:21118;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name hbbr-ws.example.com;
    ssl_certificate     /etc/nginx/tls/hbbr-ws.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/hbbr-ws.example.com.key;
    location / {
        proxy_pass http://127.0.0.1:21120;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

证书指令是每 server 必需的（不跨 `server` 块继承）；路径为示例，按部署替换，并以完整配置运行 `nginx -t` 验证。

- `web.baseURL`（或 `PANEL_WEB_BASE_URL`）必须是用户浏览器可达的 **https** 地址——邮件里的验证码/邀请链接指向它
- `provision.portStart..portEnd` 分配的主机端口需要直接暴露，不经反代。每个组织占用连续 5 个端口，协议分布不同：`HbbsPort`（TCP，nat-test）、`HbbsPort+1`（**TCP+UDP**，id registry/heartbeat）、`HbbsPort+2`（TCP，web client websocket）、`HbbrPort`（TCP，relay）、`HbbrPort+1`（TCP，web client relay ws）。默认端口从 21116 起、每组织连续 5 个——第一个组织就需要 `21116–21120`，**缺 21120 时第一个组织的 `HbbrPort+1` 即不可用**；完整放行范围以 `portStart..portEnd` 为准
- **例外——两个 WebSocket 端口建议经反向代理暴露**：`HbbsPort+2` 与 `HbbrPort+1` 是 web 客户端的 WebSocket 入口。RustDesk 服务端信任这些连接上的 `X-Real-IP` / `X-Forwarded-For` 头，直接暴露时真实客户端 IP 的还原依赖直连来源，基于 IP 的限制也可能被伪造头绕过（CWE-16）。建议与 panel 一致地经反代终止 TLS 并透传这两个头

---

## 8. 安全清单（上线前）

- [ ] `PANEL_AUTH_SECRET` 已轮换生成，且不在任何版本库/镜像层
- [ ] `mail.devMode=false`，SMTP 凭据走环境变量
- [ ] `web.baseURL` 是公网 https
- [ ] 数据库口令、`data/servergroups/`（含各组织密钥）权限已收紧
- [ ] **禁止直接挂载 rootful Docker 的原始 socket**（`/var/run/docker.sock`）：拿到它即可控制宿主机。生产环境使用 rootless Docker，或经由受限的 docker socket proxy（按需白名单 API）授予 panel 访问
- [ ] 审计表与 `panel.db` 的备份策略已建立（审计是安全证据，见运维指南 §7）
- [ ] 已按需收紧默认 `everyone → 全部设备` 访问规则（v0.9.0，步骤见运维指南 §2.3）；内置 owner/admin 角色已确认持有 `access.manage`
- [ ] 如需启用验证码（v0.10.0）：已选定提供商、注入对应秘密、**单副本部署**（或已接入共享消费存储，本版本未提供；粘性路由只能辅助登录限流，不能保证验证码单次消费），并在上线前用真实客户端走通一次登录（见运维指南 §2.4）

---

## 9. RustDesk 客户端接入

客户端需要填三个字段：**ID 服务器**、**中继服务器**、**API 服务器**。前两个指向该组织分配的 hbbs/hbbr 地址（provision 时按 `relayHost` + 分配端口生成）；第三个常被忽略，但填错会让客户端启动时白等约 40 秒。

| 客户端字段 | 取值 |
|---|---|
| ID 服务器 | `<hbbs 宿主地址>:<id 端口>`（provision 端口块中的 hbbs 映射端口） |
| 中继服务器 | `<hbbr 宿主地址>:<relay 端口>` |
| API 服务器 | **显式填** `https://<面板域名>`（经反向代理终止 TLS 的面板 compat 入口）；仅在同网段/受保护的直连部署才用 `http://<面板地址>:8080` |

**API 服务器为什么必须显式填**：客户端在 `api-server` 为空时会自动推导为「ID 服务器端口 − 2」（源码 `rustdesk/src/common.rs::get_api_server_`）。这个端口通常没有 HTTP 服务，客户端会先 `POST /api/sysinfo` 被拒、再走 TCP proxy fallback，**启动被拖慢约 40 秒**。注册（`register_pk`）发生在探测之前，所以**注册**不受该等待影响；UI 就绪与心跳会被推迟。

- **显式指向面板**（推荐）：生产用反向代理的 `https://<面板域名>`（§7 要求 panel 对外经反代终止 TLS，仅暴露 443）；同网段且面板直连 `:8080` 时才用 `http://<面板地址>:8080`。面板已提供 `POST /api/sysinfo` 与 `POST /api/heartbeat`，语义是「不可信活跃提示」。
- **留空不解决问题**：仍会推导到那个端口（见上）。客户端批量部署时建议在配置预置里一并下发。
- **不要用「映射 ID 端口 − 2」来省事**：该派生端口不在每组织连续 5 端口的分配范围内；它还可能与前一个组织的端口重合（第二块的 ID 端口是 `HbbsPort+1` = 21122，派生到 21120，正是首块的 `HbbrPort+1`——relay WebSocket），因此既不在本部署文档的监听/防火墙清单里，也可能与既有组织端口冲突。硬映射会让端口规划跨组织串位。

其余接入规则：

- 登录凭据 = 面板账号（邮箱 + 密码）+ 组织；首次登录会认领设备（rustdesk id + uuid 绑定）
- 换机器/重装后 uuid 变化会报 403「设备已绑定」。v0.5.0 起由管理员在面板/API 调
  `POST /api/v1/orgs/{orgId}/devices/{deviceId}/rebind`（填理由）重置绑定，客户端重新登录即重新认领；
  **旧机需先退出登录/离线**——重新认领是先到先得，在线的旧机会抢先。仍不提供删除设备端点。
  **不要直接改库**（只改 `bound_uuid` 不动代数会让旧会话继续驱动设备）

详细协议见 [API 规范 §4](api-spec.md)。

> 跟踪：[#65](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/65)。本文档先给出「显式配置 API 服务器」的运维口径；由面板在 provision/接入信息里**下发** API 服务器地址（免手填）属于契约变更，尚未实现。
