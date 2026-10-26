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
| T2 白名单 + CRUD | ⏳ 未开始 | — |
| T3 生效解析 + 心跳下发 | ⏳ 未开始 | — |
| T4 断连 | ⏳ 未开始 | — |
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
