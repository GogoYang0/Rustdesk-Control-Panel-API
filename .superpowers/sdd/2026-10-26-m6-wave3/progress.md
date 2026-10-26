# M6 波次 3 执行台账（Control Role / 客户端审计上报 / compat 2FA）

> 起点：develop `1c74e87`（v0.9.0 已发布，契约 0.10.0）
> 设计：`<工作区>/docs/superpowers/specs/2026-10-26-m6-wave3-control-role-client-audit-2fa-design.md`（工作区根，不在本仓库内）
> 计划：`<工作区>/docs/superpowers/plans/2026-10-26-m6-wave3-control-role-client-audit-2fa.md`（同上）
> 工作区：`.worktrees/m6-w3-control-role-client-audit-2fa`，分支 `feature/m6-w3-control-role-client-audit-2fa`

## 执行状态

| Task | 状态 | 提交 |
|---|---|---|
| T1 模型、迁移、租户注册 | ✅ 完成 | `bfe130c` |
| T2 Control Role 服务层（Normalize/Mask/CRUD/Assign/EffectiveFor） | ✅ 完成 | `8d10644` |
| T2 契约 + handler + 成员分配端点 | ✅ 完成 | `16ee672` |
| T3 票据/会话快照接线 | ✅ 完成 | `898474a` |
| T4 客户端审计上报 | ✅ 完成 | `56ba80d` |
| T5 日志查询导出与保留期 | ✅ 完成 | `8f33e42` |
| T6 compat 登录 2FA | ✅ 完成 | `71ed6aa` |
| T7 文档与全仓验证 | ✅ 完成 | 见下方提交 |

## Ruling 记录

**R1 控制角色不对原生会话执行，本刀只交付管理面 + 快照。**
- 理由：`control_permissions` 由 hbbs 注入 `PunchHole`/`RequestRelay`/`FetchLocalAddr`（`libs/hbb_common/protos/rendezvous.proto` 81/173/204 行），本项目 D10 不在信令链路，provision 起的是 stock rustdesk-server，不认角色表。
- 代价：功能价值依赖 M7 网页客户端；文档/文案若暗示已限制即为欺骗。已写入设计 §1.1、反目标第一条。

**R2 权限键以客户端协议 14 位为准（含 `usb`），不用 Pro 文档的「12/13 项」。**
- 理由：未来执行方要的是 `ControlPermissions.permissions` bitmask，协议是唯一可执行形状。
- 代价：与 Pro 文档字面数量不一致，需在 api-spec 说明来源。

**R3 客户端审计上报免凭据，用 `(id, uuid)` 与设备绑定比对。**
- 理由：客户端 `post_request(url, body, "")` 第三参为空，不发 Authorization（`src/common.rs:1635`、`src/server/connection.rs` 的 `post_audit_async`）。
- 代价：知道 id+uuid 者可伪造记录，与 heartbeat 同级风险，记入设计 §9。

**R4 nonce 去重窗口 5 分钟。**
- 理由：上游注释「api server only remembers a record's nonce for five minutes」+ 客户端重试窗口 120 秒。
- 代价：超过 5 分钟的重放会产生第二行；清扫任务按 10 分钟窗口删除 nonce。

**R5 不建模 Pro 的 `not_logged` 内置角色。**
- 理由：本面板所有 compat 会话都必须登录，该角色永远解析不到。
- 代价：与 Pro 角色列表少一项，需在 api-spec 标注为有意偏离。

**R6 built-in `default` 角色可改权限，不可改名/删除。**
- 理由：启动播种与「未分配即 default」的回退都绑定该行，改名会让两处漂移。

**R7 删除自定义角色同事务清空 `memberships.control_role_id`。**
- 理由：悬空 id 会被读成「未分配」却仍指向不存在的行，排障时误导。

## 验证证据

### T1
```
go test ./internal/controlrole/ -run TestMigrate_ -count=1
--- PASS: TestMigrate_CreatesDefaultRolePerOrganization (0.02s)
--- PASS: TestMigrate_DefaultRolePermissionsAreUseClient (0.00s)
ok  .../internal/controlrole 0.164s
```
- 变异验证：在 `Migrate` 中提前 `return nil`（禁止播种）→ 两个用例转红（record not found）；恢复后 `git diff` 为空、用例转绿。
- 基线：`go test -count=1 ./...` 全绿（21 包，1m14s），见 2026-10-26 会话记录。

### T2（服务层）
```
go test ./internal/controlrole/ -count=1
ok  .../internal/controlrole 0.249s   （19 个顶层测试）
```
- 变异验证：`Mask()` 把 `StateDisable` 也置位 → `TestMask_OnlyEnableBits` 转红（actual 0x2009 vs expected 0x9）；恢复后转绿。
- 覆盖：未知键/非法状态拒绝、缺失键补 `use_client`、bitmask 只置 enable、重复名、空名、builtin 不可删/不可改名、删除清空分配、跨组织角色不可分配、EffectiveFor 回退 default、无 recorder 拒绝写。

**R8 成员分配走独立端点 `PUT /members/{userId}/control-role`，不改 `MemberUpdateRequest`。**
- 理由：`UpdateMemberRole` 的事务里同时处理角色变更、停用与 compat 会话撤销；把控制角色塞进去会让审计动作与失败回滚互相牵连。独立端点的语义只需「设/清」，失败面最小。
- 代价：契约多一条路径；客户端要分别调用。

**R9 组织创建时同事务播种 default 角色（`controlrole.EnsureDefaultsTx`），不只在启动时 Migrate。**
- 理由：测试里新建组织读不到 default 角色而失败（列表只有自定义角色），真实场景则是「新组织在下次重启前没有任何回退角色」。
- 代价：组织创建事务多一次写入；`Migrate` 仍需保留以覆盖存量组织。

## 流程偏差（如实记录）

- T2 的 handler 与契约**先于 handler 测试落地**：`go generate` 生成 `gen.ServerInterface` 后不实现即无法编译，属于契约驱动生成的结构性约束。补救：handler 测试补齐后用变异验证证明门禁确实有效（删除 `requirePerm` → `TestControlRole_RequiresManagePermission` 转红）。
- 其余任务恢复严格 RED→GREEN：先写失败测试、看到预期失败，再实现。

### T2（契约 + 管理面）验证证据

```
npx @redocly/cli lint openapi.yaml   → valid（3 条告警均为既有的 info/servers/healthz）
go generate ./... && git status --porcelain  → 空（零漂移）
go test ./internal/authz/ ./internal/api/ ./cmd/server/ -count=1
ok  internal/authz  0.336s
ok  internal/api   36.839s
ok  cmd/server      0.255s
```
- 新增契约路径：`GET|POST /control-roles`、`PATCH|DELETE /control-roles/{roleId}`、`PUT /members/{userId}/control-role`。
- 新增权限 `control_role.manage`（不可委派；admin 内置集合授予；`MigrateAccessPermission` 每次启动重写内置集合，存量组织自动获得）。
- 变异验证：删掉 `CreateControlRole` 的 `requirePerm` → `TestControlRole_RequiresManagePermission` 转红；恢复后转绿、`git diff` 为空。
- 覆盖：成员 403/列表 200、跨组织 404、default 不可改名/不可删（409）但可改权限、未知键与非法状态 400、分配与 `null` 清除、删除清空分配、审计恰好一条 `control_role.create` 且无 HTTP 回退行。

### T3（票据/会话快照）验证证据

```
go test ./internal/session/ ./internal/controlrole/ ./internal/api/ ./cmd/server/ -count=1
ok  internal/session      3.003s
ok  internal/controlrole  0.354s
ok  internal/api         37.137s
ok  cmd/server            0.236s
go generate ./... && git status --porcelain → 空（提交后复核）
```
- 契约：`Ticket.control_role_id`（nullable）、`Ticket.control_permissions`（required，bitmask）、`Session.control_permissions`（required）；说明文字明写「原生会话不执行该位图」。
- 接线：`session.Service.WithControlRoles`；签发事务内 `EffectiveForTx` 计算并落快照；兑换复制到会话；`api.NewAdminAPI` 与 `cmd/server` 均注入。
- 变异验证：把 `ticket.ControlPermissions = mask` 改成 `mask ^ mask` → `TestIssue_SnapshotsControlPermissions` 断言失败（expected 0xc, actual 0x0）；恢复后全绿、`git diff` 为空。
- 测试覆盖：启用位 bitmask、disable 不置位、未分配回退 default、改角色不回溯旧票据、兑换复制、未接线保持 0。

### T4（客户端审计上报）验证证据

```
go test ./internal/logquery/ ./internal/compatapi/ ./cmd/server/ -count=1
ok  internal/logquery   0.340s   （10 个顶层测试）
ok  internal/compatapi  6.823s
ok  cmd/server          0.272s
```
- 端点：`POST /api/audit/{conn,file,alarm}`，**不经** `requireSession`（客户端不发 Authorization），按 `(rustdesk_id, uuid)` 多候选匹配设备绑定；空 uuid/不匹配 → 403，未知设备 → 403，缺字段 → 400。
- 语义：`new` 建 open 行（唯一索引 `(org, rustdesk_id, conn_id, session_id)` 兜底重试）、`close` 只关自己那条（无匹配时写 orphan closed 行保留证据）、note 追加到最近一条 open 行（≤512）；`file` 的 `info` 原样存并解析 ip/name/num/files；`alarm` 走 `TxRecorder` 与 nonce 同事务落 `audit_logs`。
- nonce：唯一索引 + `ON CONFLICT DO NOTHING`，重复 nonce 返回 200 幂等；`SweepNonces` 由 `audit-nonce-sweep` worker 每 10 分钟清理。
- 变异验证：把 uuid 比对改成 `if true` → `TestIngest_RejectsUUIDMismatch` 转红；恢复后 logquery 与 compatapi 全绿。

**R10 客户端日志保留期用独立 worker（`client-log-retention`），不并入审计保留期任务。**
- 理由：审计保留期是「归档 → 校验 → 删行」三段的批处理，客户端日志没有归档面；并进去会让归档失败连带阻断日志清理。
- 代价：多一个 worker；两者的天数共用 `organizations.audit_retention_days`，语义一致。

### T5（查询/导出/保留期）验证证据

```
go test ./internal/logquery/ ./internal/api/ ./cmd/server/ -count=1
ok  internal/logquery 0.433s   （16 个顶层测试）
ok  internal/api     37.795s
ok  cmd/server        0.242s
go generate ./... 后 git status 无生成漂移（提交后复核）
```
- 契约 4 条路径：`GET connection-logs`、`GET connection-logs/export`、`GET file-logs`、`GET file-logs/export`；查询复用 `audit.read` 与 `audit_scope`。
- 语义：`individual` 只看自己拥有设备（`device_id IN (SELECT id FROM devices WHERE owner_user_id=?)`），`UserID=0` 返回空页而不是全量；导出先计数，超 1000 行返回 400 要求收窄；CSV 单元格做 `= + - @` 前缀转义；导出前后写 `connection_log.export` / `file_log.export` 审计。
- 变异验证：把 `applyViewer` 的 scope 判断改成 `if true` → `TestConnections_IndividualScopeOnlyOwnDevices` 转红；恢复后全绿、`git diff` 为空。

**R11 compat 2FA 复用 `auth.TOTPService.VerifyLogin`（TOTP 与恢复码都接受），只实现 TOTP，不做 `email_check`。**
- 理由：客户端对任何非 `email_check` 的 `tfa_type` 都显示「2FA code」（`src/ui/index.tis`），复用服务能少一套加密/重放逻辑。
- 代价：恢复码也能从客户端登录；与面板共用 `UserTOTP.LastStep`，同一 30 秒窗口内两处登录会互相判重放（安全语义正确，文档要写明）。

**R12 挑战记录第一步解析出的组织，第二步重新解析会籍。**
- 理由：客户端第二步只回传 `user.name`（email），不带 `#orgID` 后缀；不存组织就无法还原多组织账号的目标组织。
- 代价：两步之间若会籍被停用，第二步按 fail closed 拒绝。

### T6（compat TOTP 两步登录）验证证据

```
go test ./internal/compatapi/ -count=1        → ok 7.8s（含 8 个新增 2FA 用例）
go test ./internal/api/ ./cmd/server/ -count=1 → 全绿
gofmt -l internal cmd                          → 无输出
```
- 第一步：密码通过且 `Enabled` 为真 → 200 `{type:"email_check", tfa_type:"totp", secret, user}`，不发 token、不建会话、不绑定设备；`Enabled` 读失败按 500 fail closed。
- 第二步：`type=="email_code"` → 校验 `secret`（SHA-256 存库）、TTL 5 分钟、单次消费、设备 id+uuid 常量时间比对、失败 5 次作废；验证码走 TOTP（`LastStep` 防重放），成功后与密码路径共用 `finishLogin`。
- 失败计入 `Guard` 锁定计数；未启用 TOTP 的账号走 `email_code` 一律 401。
- 变异验证 1（设备绑定）：移除 DeviceID/UUID 常量时间比对 → `TestLogin_2FAChallengeBoundToDevice` 转红。变异验证 2（`if false &&`）不转红，因为 UUID 分支仍拦截——说明两个条件都需要，已记录。
- 测试基建：compat / CLI / rebind 三个脚手架补 `UserTOTP` 与 `CompatLoginChallenge` 表；harness 时钟保持**本地时基**（改 UTC 会让既有 `expires_at > time.Now()` 的字符串比较失真，revoke 用例转红）。

### T7（文档与全仓验证）证据

```
npx @redocly/cli lint openapi.yaml       → valid（3 条既有告警：info/servers/healthz）
go generate ./... && git status --porcelain -- gen openapi.yaml → 空（零漂移）
go vet ./...                              → 无输出
gofmt -l internal cmd                     → 无输出
go test -count=1 ./...                    → 22 个包全绿（api 43.0s、compatapi 10.5s）
顶层测试计数（^func Test，不含 t.Run）      → 810（波次 3 起点基线 748，+62）
```
- api-spec：新增 §3.12 控制角色（含「原生会话不执行」必读边界）、§3.13 客户端连接/文件日志、§4.1 两步登录说明、§4.5 客户端审计上报；版本历史补波次 2/3。
- operations：新增 §2.5 控制角色运维、§2.6 compat 2FA 运维、§3.2 客户端日志运维；故障速查补 4 行。
- deployment：新增「v0.10.0 控制角色/客户端审计/2FA」升级要点（无新配置键、新表与新列、default 角色播种、auth.secret 依赖）。
- INDEX：台账登记波次 3。

## 子代理独立评审与整改（PR 前，2026-10-26）

评审范围 `1c74e87..8c8744e`，输出「阻断 / 建议 / 疑问」分级。已修复（提交 `c56bf6d`）：

- **阻断：备注上报无租户条件**。`appendNote` 原按 `(rustdesk_id, session_id)` 全局命中并 `WithoutTenantScope` 更新，任何人都能往任意组织的连接记录追加文本。修复：先解析设备并要求**全平台唯一**（0 条 → 403，>1 条 → `ErrAmbiguousDevice` 403），再用 `ScopedByOrg` + `device_id` 更新；备注按 rune 截断（避免切断 UTF-8 被 PG 拒绝）。新增跨租户回归用例 `TestIngest_NoteScopedToOwningOrganization`。
- **重要：CSV 清洗器弱化复制**。本地 `sanitizeCSVCell` 只处理 `= + - @`，漏掉 `\t \r \n`；改为导出 `audit.EscapeFormula` 并删除本地副本，避免 M4 已修问题回归。
- **重要：成员读不到控制角色**。`Member` 增加可空 `control_role_id`（名称由 `GET /control-roles` 解析，避免逐行 JOIN），三处映射点同步；新增 `TestControlRole_MemberListExposesAssignment`。
- **重要：2FA 锁定键可被攻击者提供**。第二步原先用请求里的 `username` 作为 lockKey 且不校验与挑战用户一致；改为校验 email 必须等于挑战用户，失败一律记在 `compat-user-<id>` 桶。新增 `TestLogin_2FAUsernameMustMatchChallenge`。
- **重要：多组织同 id 歧义**。`resolveDevice` 命中 >1 条时 fail closed（`ErrAmbiguousDevice`），并给 `devices.rustdesk_id` 增加单列索引（原先按 id 全局查是全表扫描）。
- **重要：上报字段无长度校验**。按列宽校验 `id/uuid/nonce/ip/conn_audit_ref/peer_id/name`，超长 400 而不是 PG/MySQL 500；新增 `TestIngest_RejectsOversizedField`。
- **重要：`PUT control-role` 空体静默清空**。改为按原始 map 判键存在，缺 `control_role_id` → 400，只有显式 `null` 才清除；新增用例。
- **次要：挑战表无清扫**。新增 `logquery.SweepChallenges` + `compat-2fa-sweep` worker（每小时，删过期 1 小时以上的行）。
- **次要：403 文案区分设备不存在与 uuid 不符**。合并为同一文案，避免未认证端点变成注册探针。

**未修复、记入后续**（评审同意的低风险项，均不阻断）：
- `Assign` 与 `Delete` 竞态可能把已删角色 id 写回会籍（读取侧回退 default，仅排障噪音）→ 建议 `Assign` 对角色行加锁。
- 重名并发创建在 PostgreSQL 上可能返回 500 而非 409（事务 abort 后同事务重查失效）。
- `EnsureDefaultsTx` 的「缺 default」判定按 kind、插入冲突按 (org,name)：若手工删除 default 且存在同名自定义角色，播种会被静默跳过（签发随即 500，fail closed 但无 API 恢复）。
- `Migrate` 的 `now` 参数未使用；orphan close 未写 `orphan_close` 标记；`fakeRecorder.fail` 未覆盖「审计失败→回滚」用例。
- 上报端点未限流（设计 §10 已声明可后续加）。

### 整改后验证

```
npx @redocly/cli lint openapi.yaml → valid
go generate ./... 后 git status --porcelain -- gen openapi.yaml → 空
go test -count=1 ./... → 22 包全绿（api 43.9s、compatapi 9.8s）
```

## 遗留补记：CI、CodeRabbit 与合并（2026-10-26，波次 4 分支补）

> 本节在波次 3 合并后补写：当时特性分支已合并，按「不直接提交 develop」的规则没有为一段文档单独开 PR，随波次 4 的文档提交一并落账。

### CI（test-db / PostgreSQL）

三轮失败，根因都是 **CI 的 test-db 作业多包共享同一个 PostgreSQL 库**，而新测试按「每测试独立库」写：

1. `39d74cc`：`controlrole` / `session` / `logquery` 用固定邮箱（撞 `idx_users_email`）与固定 rustdesk id（撞本波次新增的「跨组织同 id 歧义」规则）。修复：邮箱原子计数、org 名与设备 id 带 fixture 序号、`Migrate` 计数限定本测试的组织。
2. `53a0188`：`logquery` 断言用 `WithoutTenantScope(f.db).Find(...)` 读到别的测试的行。修复：断言改 `ScopedByOrg(f.db, f.org.ID)`。
3. `ece801d`：nonce 清扫是全局表操作，断言 `removed == 1` 在共享库上不成立。修复：断言本 fixture 的行状态，全局计数只要求 `>= 1`。

教训已写入项目 MEMORY.md：共享测试库下 fixture 标识必须唯一、断言必须带租户条件，SQLite 绿灯不代表 test-db 绿灯。

### CodeRabbit（11 条内联 + 1 条正文 nitpick）

甄别结果：**8 条属实已修**（`57d93b3`）、**3 条已过时**（指向 `53a0188`/`ece801d` 已修的共享库问题，回复中引用 commit）。显式处理：

| 类别 | 内容 | 处理 |
|---|---|---|
| 枚举探针 | `ErrUnknownDevice` 与 mismatch/ambiguous 返回不同 403 文案 | 合并为同一条 |
| 竞态 | 2FA 次数上限「先读后加」并发可绕过 | `claimAttempt` 条件 UPDATE 原子占用 |
| 逻辑错配 | 失败记在 `compat-user-<id>` 桶、锁定检查用 `lockKey` | 统一用已校验的 `lockKey` |
| 可用性 | `default` 角色缺失导致签发票据 500 | 回退空权限（控制角色不决定能否连接） |
| 并发 | orphan close 撞唯一索引 500 | `ON CONFLICT DO NOTHING` |
| 文档 | GFM 表格 `\|` 未转义（MD056）、备注路径风险未单列、部署指南称挑战表需手工清理 | 三处均已修 |
| nitpick | 2FA 并发兑换与 5 次上限无测试 | 补两个用例（恰好一个 200、一个 401、一条会话；第 6 次正确码被拒） |

第二轮增量复审（13:57–13:58）全部是「已确认修复」与两条自我撤回，无新缺陷。

### 合并

- PR [#91](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/pull/91) `feat: control roles, client audit logs and compat 2FA (M6 wave 3)`，base `develop`，21 commits，+6176/−125。
- 合并前 `mergeStateStatus=CLEAN`、CI 全绿（build/lint/test/test-db/contract/vulncheck/CodeQL）。
- 合并方式 merge commit，结果 `1ef1e4d`（用户批准后执行）。
