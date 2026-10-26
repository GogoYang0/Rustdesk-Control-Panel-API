# M6 波次 4 执行台账（Strategy 下发 / 心跳断连）

> 起点：develop `1ef1e4d`（波次 3 已合并）
> 设计/计划：`<工作区>/docs/superpowers/{specs,plans}/2026-10-26-m6-wave4-strategy*.md`（工作区根，不在本仓库）
> 工作区：`.worktrees/m6-w4-strategy`，分支 `feature/m6-w4-strategy`

## 上游事实（决定波次形态）

- Strategy 走**心跳响应**下发：客户端 `src/hbbs_http/sync.rs:225-275` 每 30 秒 POST `{api-server}/api/heartbeat`，解析响应里的 `strategy{config_options,extra}`、`disconnect:[conn_id]`、`modified_at`、`sysinfo`。
- 客户端对 `config_options` **无白名单**套用（`handle_config_options`，同文件 292-309）—— 下发 `api-server`/`custom-rendezvous-server` 等于设备接管，面板必须白名单。
- `conns = Connection::alive_conns()` 只在非空时上报，且 `disconnect` 只能使用这些编号。

## 执行状态

| Task | 状态 | 提交 |
|---|---|---|
| T1 模型/迁移/租户注册 | ✅ 完成 | 见下方 |
| T2 白名单 + CRUD | ✅ 完成 | `f001fda` |
| T3 生效解析 + 心跳下发 | ✅ 完成 | `afb5c64` + `4f5d05c` |
| T4 断连 | ✅ 完成 | `fff8ecf` |
| T5 分配 + CLI strategy_name | ⏳ 未开始 | — |
| T6 文档 + 评审 | ⏳ 未开始 | — |

## Ruling 指针

本轮决定见设计 §4（D1–D10）。最关键三条：
- D2 白名单是安全边界（客户端无脑套用），未知键 400；
- D3 `modified_at` = 策略 version，相同不下发；
- D4 断连只作用于客户端本次自报的 conns，15 分钟过期。

### T1 证据

```
go test ./internal/model/ -run TestStrategy -count=1        → ok
go test ./internal/store/scopetest/ -count=1                → ok
go build ./...                                              → ok
```
- 新增 `strategies`、`device_disconnects`；`Device/DeviceGroup/Membership.StrategyID`；`DeviceHeartbeat.ConnIDs`。
- 两张新表注册 `store/defaults.go` + `scopetest`，api harness AutoMigrate 同步。
- 测试覆盖：`(organization_id,name)` 唯一（同组织重复失败、跨组织同名允许）、四处新列存在。

**R1 分配语义（AssignDevice/AssignGroup/AssignMember）随 T2 落地，T5 只补端点与 CLI。**
- 理由：Delete 必须在同一事务里清空三处分配，分配与清理是同一套语义；拆到 T5 会让 T2 的删除测试无法验证「悬空 id 已清除」。
- 代价：T2 的提交比计划大一点；T5 只剩契约、handler 与 CLI 解析。

**R2 改名/空转的 PATCH 不 bump 版本，也不写审计。**
- 理由：`version` 是客户端「是否需要重新套用」的唯一信号（`strategy_timestamp` 持久化在客户端本地），改名或重复提交同样的 `config_options` 会触发一次全量下发，把 30 秒一次的心跳变成无谓的配置重写。
- 代价：审计里看不到「有人点了一次没有变化的保存」。这是有意的：没有变化就没有变更可审计。

### T2 证据

```
go test ./internal/strategy/ -count=1                 → ok（22 个顶层测试）
go test ./internal/api/ -run TestStrategy_           → ok（6 个 HTTP 用例）
go test ./internal/api/ ./internal/authz/ ./internal/store/scopetest/ -count=1 → 全绿
npx @redocly/cli lint openapi.yaml                   → valid（3 条既有告警）
go generate ./... 后 git status --porcelain -- gen openapi.yaml → 空
```

- 白名单：20 个键集中在 `internal/strategy/options.go`，`TestAllowedOptions_MatchesDesignList` 逐字钉死顺序与内容；逐字匹配（不 trim、不 fold），`API-SERVER` / `" enable-audio"` / `enable-audio\t` 均 400。
- 值约束：≤256 **rune**、禁控制字符（值最终写进客户端配置文件）；键数上限 50 是防御性常量，白名单只有 20 个键，测试断言两者关系。
- CRUD：名称 1–64 字符、组织内**不区分大小写**唯一（CLI 按名解析）；`enabled=false` 是停用开关，保留分配；删除同事务清空 devices/device_groups/memberships 的 `strategy_id` 并写 `strategy.delete`。
- 权限：`strategy.manage`、`device.disconnect` 均为不可委派，admin 内置集合授予，owner 全量。
- 审计：三个写端点在成功后 `c.Set(contextAuditRecorded, true)`，避免中间件再写一条 HTTP 回退行（该问题是本任务的 API 测试跑出来的：`httpRows` 断言 3 条）。
- 变异验证 1（白名单）：把 `if !allowlist[k]` 改成 `if false` → `TestNormalizeOptions_RejectsSystemKeys` 与 `..._RejectsCaseAndWhitespaceVariants` 转红；恢复后全绿。
- 变异验证 2（版本）：把 `updates["version"] = row.Version + 1` 改成 `row.Version` → `TestUpdate_OptionsChangeBumpsVersion` 断言失败（expected 2, actual 1）；恢复后全绿。

**流程偏差（如实记录）**：T2 的测试先于实现写好，但实现写完才第一次运行，因此没有观察到「断言失败」形态的 RED（首次运行会是编译失败）。补救：两处关键不变量各做一次变异验证，证明用例确实能抓住回归。

**R3 `modified_at` 只在随 `strategy` 下发时出现。**
- 理由：客户端把 `modified_at` 存进 `strategy_timestamp`（`LocalConfig`，跨重启保留），而且**与 `strategy` 字段独立处理**（`src/hbbs_http/sync.rs` 先取 `modified_at` 存盘，再看 `strategy`）。只发版本不发选项 = 告诉客户端「你已是最新」而它仍跑着旧配置，且此后再也不会请求。
- 代价：没有策略时响应体为空对象，运维在抓包里看不到「当前生效版本」——需要时查 `strategies.version` 或审计。

**R4 停用策略终止解析，不向下一层回落。**
- 理由：`enabled=false` 是管理员「这台设备/这组设备不要这套下发」的明确决定；回落到更宽的层（组/成员）会把刚关掉的选项又装回去。只有「分配指向的行不存在」（数据完整性意外）才跳过该层继续。
- 代价：停用设备级策略后，组级策略不会自动接管；要接管必须显式清空设备级分配。

### T3 证据

```
go test ./internal/strategy/ -count=1                → ok（32 个顶层测试）
go test ./internal/compatapi/ -run TestHeartbeat_    → ok（6 个 HTTP 用例）
go test ./internal/compatapi/ ./internal/api/ ./internal/strategy/ ./internal/model/ -count=1 → 全绿
```

- 解析顺序：`device.strategy_id ?? device_group.strategy_id ?? owner membership.strategy_id`；无归属人的设备跳过成员层（不会借用别人的策略）；跨组织设备 id 解析为 nil。
- 下发：`DeliveryFor` 在版本相等时不投递；投递前**再次**用白名单校验库里的 `config_options_json`（防止手工 UPDATE / 旧版本写入 / 未来 bug 把网络键送到客户端）。校验失败 → 记日志、响应为空（fail closed）。
- 心跳：`touchDevice` 改为返回设备行，`writeHeartbeatResponse` 只在 `Deliver` 为真时同时写 `strategy` 与 `modified_at`；会话过期/设备停用/绑定变化一律空响应。
- 变异验证 1（版本比对）：`if version == clientVersion` 改成 `if false && ...` → `TestDelivery_DeliversOptionsWithVersion` 转红。
- 变异验证 2（版本必须伴随策略）：`!Deliver` 分支改成回 `{"modified_at": v}` → `TestHeartbeat_NoStrategySendsNothing` 与 `..._DeliversStrategyAndVersion` 同时转红。

**T3 跑出的真 bug（`afb5c64`）**：`Strategies.Enabled` 原来带 `gorm:"default:true"`，GORM 对「有默认值的零值字段」会从 INSERT 中省略，于是**创建 `enabled=false` 的策略会静默存成 true**，停用开关失效。`TestHeartbeat_DisabledStrategySendsNothing` 直接把它抓出来。改法：去掉 `default:true`，所有写入方显式赋值。

**R5 `device_heartbeats.conn_ids` 只做「最新一行」尽力更新，不作为断连依据。**
- 理由：心跳行按 30 秒窗口合并（`apiHeartbeatMinInterval`），不是每次心跳都有新行；若把断连依据放在这里，会出现「心跳到了但没有行」而无法断连。真正的依据是**本次请求的 `conns`**，落库证据是 `device_disconnects.conn_count`。
- 代价：`conn_ids` 可能滞后一个窗口，文档写明它只是排障线索。

**R6 过期是系统动作，审计 `ActorUserID=0`。**
- 理由：没有人执行过期，是时间到了；把它记成某个用户会污染追责链。
- 代价：按 actor 过滤审计时这些行不出现，需要按 action 查。

**R7 被拒绝的重复请求（409）落 HTTP 回退审计行。**
- 理由：领域审计只在状态真的变化时写；一次被拒的重复请求是「有人试了两次」这一事实，用中间件的 `POST .../disconnect` + status 409 记录最贴切，也不会伪造第二条 `device.disconnect.request`。
- 代价：同一路径在审计里可能同时出现领域行与 HTTP 行（成功一次 + 被拒一次），要靠 action 区分。

### T4 证据

```
go test ./internal/strategy/ -run TestDisconnect_   → ok（7 个用例）
go test ./internal/compatapi/ -run TestHeartbeat_   → ok（10 个用例）
go test ./internal/api/ -run TestDisconnect_        → ok（3 个用例）
go test ./internal/strategy/ ./internal/compatapi/ ./internal/api/ ./cmd/server/ ./internal/model/ ./internal/store/scopetest/ -count=1 → 全绿
go generate ./... 后 git status --porcelain -- gen openapi.yaml → 空
```

- 契约：`POST /orgs/{orgId}/devices/{deviceId}/disconnect`（201 + `DeviceDisconnect`），`reason` 必填 1–255；同设备已有 pending → 409；跨组织/不存在 → 404。
- 消费：`TakePendingTx` 用条件 UPDATE（`status=pending`）标记 fulfilled，`RowsAffected != 1` 时不再断连——两个并发心跳只有一个能拿到连接列表。
- 连接号清洗：只接受能装进客户端 `Vec<i32>` 的正整数；`-1`、`0`、`"x"`、`3.5` 全部丢弃，避免把未认证请求里的垃圾值原样回显。
- worker：`disconnect-expiry` 每 5 分钟扫描 `expires_at <= now` 的 pending 行，标记 expired 并写系统审计。
- 变异验证 1（空连接不消耗）：删掉 `len(conns)==0` 早退 → `TestDisconnect_NoConnsKeepsPending` 转红。
- 变异验证 2（连接号校验）：`float64` 分支改成无校验直接转换 → `TestHeartbeat_IgnoresInvalidConnIDs` 转红。
