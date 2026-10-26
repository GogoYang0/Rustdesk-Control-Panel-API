# M6 波次 3 执行台账（Control Role / 客户端审计上报 / compat 2FA）

> 起点：develop `1c74e87`（v0.9.0 已发布，契约 0.10.0）
> 设计：`docs/superpowers/specs/2026-10-26-m6-wave3-control-role-client-audit-2fa-design.md`
> 计划：`docs/superpowers/plans/2026-10-26-m6-wave3-control-role-client-audit-2fa.md`
> 工作区：`.worktrees/m6-w3-control-role-client-audit-2fa`，分支 `feature/m6-w3-control-role-client-audit-2fa`

## 执行状态

| Task | 状态 | 提交 |
|---|---|---|
| T1 模型、迁移、租户注册 | ✅ 完成 | `bfe130c` |
| T2 Control Role 服务层（Normalize/Mask/CRUD/Assign/EffectiveFor） | ✅ 完成 | `8d10644` |
| T2 契约 + handler + 成员分配端点 | ✅ 完成 | `16ee672` |
| T3 票据/会话快照接线 | ✅ 完成 | `898474a` |
| T4 客户端审计上报 | ⏳ 未开始 | — |
| T5 日志查询导出与保留期 | ⏳ 未开始 | — |
| T6 compat 登录 2FA | ⏳ 未开始 | — |
| T7 文档与全仓验证 | ⏳ 未开始 | — |

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
