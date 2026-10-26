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
| T5 分配 + CLI strategy_name | ✅ 完成 | `b42e35a` |
| T6 文档 + 评审 | ✅ 完成 | 文档见 `12c9a07`，评审整改见下方提交 |

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

**R8 分配端点与设备更新共用「未给出字段」的严格语义。**
- 理由：`PUT .../strategy` 的 `strategy_id` 是必填项（可显式为 `null`）；空体 `{}` 返回 400 而不是「清除」。控制角色分配在波次 3 已经踩过这个坑（空体静默清空）。生成的结构体分不出「缺失」与「null」，因此按原始 map 判键存在。
- 代价：调用方必须显式传 `{"strategy_id": null}` 才能清除。

**R9 CLI 的 `strategy_name` 在设备更新之前解析，分配在更新之后执行。**
- 理由：名字解析失败（404）必须让整个 `--assign` 失败，不能留下「备注改了、策略没分配」的半状态。分配本身是第二步事务，失败返回 500 并记日志——设备更新已提交这一点在响应里无法回滚，但分配失败的概率极低（单行 UPDATE），且失败原因会进日志。
- 代价：极端情况下可能出现「设备信息已更新、策略未分配」，需要运维重跑一次 `--assign`。

### T5 证据

```
go test ./internal/api/ -run TestStrategyAssign_       → ok（3 个用例）
go test ./internal/compatapi/ -run TestCLIAssign_     → ok（5 个用例，含 2 个既有回归）
go test ./internal/api/ ./internal/compatapi/ ./internal/strategy/ -count=1 → 全绿
go generate ./... 后 git status --porcelain -- gen openapi.yaml → 空
```

- 契约：3 条 `PUT .../strategy` 路径（device / device-group / member）+ `StrategyAssignmentRequest`；`Device` / `DeviceGroup` / `Member` 三个 schema 增加可空 `strategy_id` 并回读（设备列表、设备组列表、成员列表都已断言）。
- CLI：`cliAssignFields` 增加 `strategy_name`（反转波次 2 的 D5），解析大小写不敏感、未知 404、空串 400；成功写 `strategy.assign` 审计。
- 变异验证（跨租户）：把 `assign` 里的「策略必须属于本组织」查询短路掉 → `TestAssign_RejectsForeignTargets` 转红。
- 备注：`openapi.yaml` 的 Python 写入若不显式 `newline='\n'`，在 Windows 上会整文件转成 CRLF，导致锚点匹配与索引状态混乱；本任务已把工作副本统一为 LF 并复核 `git status` 干净。

## 子代理独立评审与整改（PR 前，2026-10-26）

评审范围 `1ef1e4d..12c9a07`（46 files，+4551/−51），输出「Critical / Important / Minor」分级与 Declined-to-judge 清单（20+ 条，全部对应既有裁定或设计非目标，已逐条核对）。

### 已修复

| 级别 | 问题 | 修复 |
|---|---|---|
| **C1** | 版本号按行计数，两个策略可同号：客户端只存一个数字，改派到另一策略会被判「已最新」而**一次都不下发**（评审用探针实证：`Deliver=false`） | **`version` 改为组织内单调序列**（`organizations.strategy_version_seq`，事务内 `UPDATE ... +1` 后回读，行锁串行分配）；回归用例 `TestDelivery_SwitchingStrategiesDelivers`。设计文档已补「评审修订」章节 |
| **I1** | `TakePendingTx` 不查 `expires_at`，过期但未被清扫的请求仍能断连（清扫 5 分钟一轮） | 消费点加 `expires_at > now`；用例 `TestDisconnect_ExpiredRequestNotConsumed` |
| **I2** | CLI `strategy_name` 只查 `device.write`（可委派），绕过不可委派的 `strategy.manage` | 抽出 `tokenPermissions`/`tokenHasPerm`，`strategy_name` 出现时额外要求 `strategy.manage`，403；用例 `TestCLIAssign_StrategyNeedsManagePermission` |
| **I3** | 「先 COUNT pending 再 INSERT」在 PG/MySQL 并发下两个请求都能成功，留下第二条 pending（几分钟后误断新连接） | 读设备行时加 `FOR UPDATE`（sqlite 跳过，写锁天然串行）；并发用例 `TestDisconnect_ConcurrentRequestsLeaveOnePending` 断言「至多一条 pending」 |
| **I4** | 大小写唯一只有应用层检查（DB 索引字节级），且 SQLite `LOWER()` 只折叠 ASCII，与 Go `EqualFold` 不一致 | 新列 `strategies.name_key`（`strings.ToLower`）+ 唯一索引 `(organization_id, name_key)`；查重改按 `name_key`；用例 `TestCreate_CaseFoldingCoversNonASCII`（Ölwechsel/ölwechsel） |
| **I5** | 从 `config_options` 删键：客户端只写收到的键，旧值（且被标记 fixed）永久保留，而 API 返回 200 并 bump 版本 | 新列 `cleared_keys_json`：Update 时合并「被移除的键」，DeliveryFor 把它们以 `""` 随下发回传；重新加回自动移出。用例 `TestDelivery_RemovedKeyIsCleared` |
| M1 | 设计列了 `GET /strategies/{strategyId}`，契约漏了 | 补 `getStrategy` 路径 + handler + 用例 |
| M2 | 请求体未知字段（含客户端 `extra`）被静默丢弃 → 201 | 策略 Create/Update 改 `DisallowUnknownFields` 严格解码，400；用例 `TestStrategy_RejectsUnknownFields` |
| M3 | 计划要求的并发用例、R4（停用终止解析）无用例 | 补 `TestDisconnect_ConcurrentRequestsLeaveOnePending` 与 `TestEffective_DisabledDeviceStrategyDoesNotFallThrough` |
| M4 | `parseConnIDs` 的 `case int` 分支缺 i32 上界 | 补 `> math.MaxInt32` 检查 |
| M5 | `strategyByName` 用 `context.Background()` 丢请求上下文 | 改收 `c.Request.Context()` |
| M7 | assign 与 delete 并发可留悬空 `strategy_id`（解析层会静默回落到更宽层，与 R4 意图相反） | 两边都对策略行加 `FOR UPDATE`（sqlite 跳过） |
| M9 | 测试死代码 `_ = foreign` | 删除 |
| M11 | 生产装配构造两个 `strategy.Service` 实例（NewAdminAPI 的副本不回写 Deps） | `NewRouter` 里取 `admin.deps.Strategies` 传给 compat 层 |
| M8 | 部署指南没提 `device_heartbeats.conn_ids` 这一最高写入量表的新列 | 已补（MySQL instant / PG 元数据变更的说明） |

### 记录但未改代码（评审同意的低风险项）

- **M6**：并发 PATCH 各自分配版本号（组织序列下已天然不同号），后写覆盖前者选项——最终状态一致、审计各记一条，可接受；若要严格可上乐观并发（`WHERE version=?`），记后续。
- **M10**：断连请求没有读端点（`GET .../disconnects`）；运维目前靠审计或查库。设计未要求，记后续。
- **伪造心跳消费断连**：无凭据心跳（设计 C16）下，知道 `(id, uuid)` 的人可把 pending 请求消费成假 `fulfilled`（响应对攻击者无用，但管理员的请求被作废）。已在运维指南 §2.7 排障表加一行；协议层修复（心跳引入凭据或客户端回执）超出本波次，记入设计文档「评审修订」。
- **版本空间的文档**：api-spec §3.14、operations §2.7 已同步「组织内单调序列 / 删键=清除 / 停用不清除已固定选项」。

### 整改后验证

```
npx @redocly/cli lint openapi.yaml → valid（3 条既有告警）
go generate ./... 后 git status --porcelain -- gen openapi.yaml → 空（提交后复核）
go vet ./...            → 无输出
gofmt -l internal cmd   → 无输出
go test -count=1 ./...  → 23 包全绿（api 49.1s、compatapi 12.8s、strategy 0.6s）
顶层测试计数             → 899（波次 3 基线 810，+89）
```

**整改中踩到的坑**（已写进测试注释）：SQLite 把时间按字符串比较，compat 心跳测试原来用 `time.Now().UTC()` 播种 `expires_at`，在 UTC+8 主机上读回就是「已过期」（`15:26 < 23:26`），I1 的消费点校验把它抓了出来。播种必须与服务同一时钟基准。
