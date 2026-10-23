# Step 5 · M3 会话治理 云端 Docker 执行手册（v0.4.0+）

> **给谁用**：在**有 Docker 的 Linux 云主机**上新开的会话/新接手者。本手册 + 一个脚本 + 两个 Go 夹具即可独立执行，无需产生它的那次会话的上下文。
> **为什么需要云端**：M3 交付里唯一无法在 Windows AI 会话验证的是**容器路径**——`provision` 起容器、以及 `logcollect` 通过 `docker logs -f -t` 读真实容器日志来驱动 native 会话。Windows 本机没有可用容器运行时（Docker Desktop 依赖的 `wsl.exe` 被安全策略拦截）。
> **版本**：仓库 `GogoYang0/Rustdesk-Control-Panel-API`，分支 `develop`（含 PR #61/#62 的测试加固）；契约 v0.4.0。

---

## 0. 文件清单（都在仓库里，clone 即可）

| 路径 | 用途 |
|---|---|
| `docs/reference/step5-m3-run.sh` | **一键脚本**：环境检查 → 构建 panel → 起 panel → 播种 → 面板侧 12 项断言 → provision 端到端 → 采集/native 断言 →（可选）碰撞率专项 |
| `tools/regression/m3harness/` | Go 夹具：播种前置数据 + 驱动 M3 全部 HTTP 端点（12 项检查，逐项落证据 JSON） |
| `tools/regression/m3native/` | Go 夹具：**只替换 docker 传输层**，用真实 hbbs 日志驱动「解析 → LogEvent → native 会话归并 → 告警」 |
| `docs/reference/step5-collision-probe.sh` | #36 纳秒碰撞率专项（本手册 §6 可选） |
| 本手册 | 步骤、判定表、报告要求 |

---

## 1. 执行顺序

```bash
git clone --depth 1 -b develop https://github.com/GogoYang0/Rustdesk-Control-Panel-API.git
cd Rustdesk-Control-Panel-API
chmod +x docs/reference/step5-m3-run.sh docs/reference/step5-collision-probe.sh
./docs/reference/step5-m3-run.sh /root/step5m3-work          # 自动跑到 §6 之前
# 按 §5 手工接入真实客户端，然后继续 §6 的断言（脚本内已给提示）
./docs/reference/step5-m3-run.sh /root/step5m3-work --probe   # 或带碰撞率专项
```

脚本**可重跑**：panel 已在跑时会因端口占用失败——重跑前先 `kill $(cat panel-data/panel.pid)`，或换 `WORKDIR`。

---

## 2. 脚本自动完成的部分（阶段 0–5）

| 阶段 | 做什么 | 判定 |
|---|---|---|
| 0 | `docker ps` / `go version` / `curl` 检查 | 三项齐备 |
| 1 | 构建 panel（打印 commit） | 构建成功 |
| 2 | 写配置（**`logcollect.enabled=true`**、规则用示例集、`session.idleTimeout=10m`）并启动 panel | `/healthz` = 200 |
| 3 | 夹具 `seed`：直写库造 owner（`step5m3@example.com` / `step5m3-pass-123456`）、组织、设备（`123456789`）、一条 native 会话 | 退出码 0 |
| 4 | 夹具 `flows`：12 项 HTTP 断言 | 全部 PASS（明细在 `evidence/*.json`） |
| 5 | 用 API 建**第二个组织**触发 provision，等容器出现，检查 `docker ps` 与 `docker logs -t` | hbbs/hbbr 就绪、启动日志含 `Listening on tcp/udp :21116` |

### 2.1 面板侧 12 项断言（`m3harness -phase flows`）

| # | 检查 | 期望 |
|---|---|---|
| 1 | 登录 | 200 + `access_token`/`refresh_token` |
| 2 | 组织与设备 | `GET /orgs` 含该组织；`POST /devices` 幂等返回同一 id |
| 3 | 票据成功路径 | issue 201 → 记账 `used_at=null` → redeem 201 → 出现 `origin=panel,status=open` 会话 |
| 4 | 一次性 | 同一票据二次 redeem = **409 `conflict`**（不区分原因） |
| 5 | 并发闸门在**兑换** | 限额=当前 open+1：第一张兑换 201，第二张 **409** |
| 6 | 时段外 | 签发 **409**，并留下 `end_reason=policy_denied` 的 denied 会话 |
| 7 | 时段恢复 | 改回全天 → issue/redeem 均 201 |
| 8 | 事前审批 | 签发 409 `approval_required` → approve → 签发 201 且 `approval_id` 回填 → 再签发又 409（**签发即消费**）；deny 路径仍 409 |
| 9 | 事后追认 | `kind=ratification` + `session_id`（native）→ approve 生效，`ticket_id` 恒为 null |
| 10 | 告警 | `GET /alerts` 至少 1 条（本次实测出现 `info/outside_window` 与 `warning/concurrency_exceeded`） |
| 11 | 审计 | `audit_logs` 中 `session.ticket.issue/redeem/denied`、`session.approval.request/decide` 均 > 0 |
| 12 | 会话详情 | `GET /sessions/{id}` 含 `events` 与 `truncated` |

> 关键易错点（测试失败时先看这几条）：**并发闸门在兑换不在签发**；**策略 PUT 是全量替换且 `enabled`/`require_approval` 必填**；时段是 **UTC 当日分钟**、`start==end` 返回 400（全天用 null）；事前审批阻断**不产生告警**（正常受控流程）。

---

## 3. 前置数据为什么直写库

系统没有公开注册端点：首个账号由**邀请接受**创建。夹具的 `seed` 用项目自己的 `internal/auth.HashPassword`（Argon2id）+ `internal/store` 直接写库，避免手工拼 SQL 与密码算法。它**幂等**：重复运行返回同一批 id。

---

## 4. 真实客户端接入（脚本 §6 前必须做）

无法在无 GUI 容器里自动完成「客户端注册」这一步，需一台能连到云主机的 RustDesk 客户端（你的本机即可）：

1. 取**新组织** hbbs 的公钥：
   ```bash
   docker logs panel-org-<orgId>-hbbs 2>&1 | grep "Key:" | tail -1
   # 或：cat server-data/org-<orgId>/id_ed25519.pub
   ```
2. 客户端设置 → ID/中继服务器：`<云主机IP>:21116`，Key 填上一步的公钥；中继服务器 `<云主机IP>:21117`。
3. 启动客户端（会向 hbbs 注册）。hbbs 容器日志应出现：
   ```
   [...] INFO [src/peer.rs:102] update_pk <设备ID> [::ffff:<客户端IP>]:<端口> ...
   ```
4. 回到脚本按回车，脚本会断言：`log-events` 里出现 `kind=conn` 的事件、`sessions?origin=native` 出现 native 会话。

> 采集器是 `--tail 0` 起步（不回填历史）：**先启动 panel 再连客户端**才能采到。若客户端先连了，重连一次即可。

---

## 5. 手工判定表（脚本断言的展开，便于排障）

前缀：`AT=<access_token>`（脚本已算出 `$TOKEN`），`O=<orgId>`。

| # | 操作 | 期望 |
|---|---|---|
| D1 | `docker ps --filter name=panel-org-$O-` | 两个容器 Running，端口在 `21116–22115` 池内且成对 |
| D2 | `docker logs -t panel-org-$O-hbbs \| head` | 时间戳前缀为 RFC3339Nano（采集游标消费的就是它） |
| D3 | `curl $API/api/v1/orgs/$O/log-events -H "Authorization: Bearer $AT"` | 出现 `source=hbbs` 的 `conn` 事件，`device_id` 对应真实客户端 |
| D4 | `curl "$API/api/v1/orgs/$O/sessions?origin=native"` | 至少 1 条 `origin=native,status=open`，`started_at` = hbbs 行的 **docker 捕获时间** |
| D5 | 客户端断开后再连 | 契约：已吸收连接的会话不重开 → 新建第二条 native 会话（**多记不漏记**） |
| D6 | 把 `session.idleTimeout` 调小（如 `1m`）重启 panel | 超过窗口无事件的 open 会话被置 `closed/end_reason=idle_timeout` |

---

## 6. #36 纳秒碰撞率专项（可选）

```bash
bash docs/reference/step5-collision-probe.sh "100 1000 5000 20000"
```
口径：`docker logs -t` 的**捕获时间戳**（与 hbbs 消息内时间戳是两个时钟）。判定：各档同纳秒率 ≈ 0 → `+1ns` 游标可行、#36 维持低优先级；高吞吐出现显著同纳秒碰撞 → #36 升级为去重键方案。

---

## 7. 报告要求（交回分析）

产出 `step5-m3-result.md`，至少包含：

1. **环境**：发行版、内核、Docker/Go 版本、仓库 commit、是否容器内运行。
2. **结果表**：§2.1 的 12 项 + §5 的 D1–D6，逐项 `✅/❌` + 实测值（状态码、code、id、时间戳）。
3. **故障排查记录**：失败项的现象、`panel-data/panel.log` 相关片段、`docker logs -t` 片段。
4. **碰撞率数据表**（若跑 `--probe`）。
5. **与 Windows 侧结果的差异**：已知 Windows 侧 12/12 PASS、native 归并 7/7 PASS（仅替换 docker 传输层），容器侧应补上「真实 `docker logs -t` 路径」与「容器 stdout/stderr 合并」。
6. **遗留项**：明确哪些没验证、为什么。

---

## 8. 已知基线（来自 Windows 真机会话，2026-10-23）

- 面板侧 12 项：**12/12 PASS**（真实 panel + SQLite + 真实 worker）。
- native 归并：**7/7 PASS**，证据覆盖——真实 hbbs 1.1.16 日志 14 行中 1 行命中 `conn`、`device=426649028`；连接事件被会话吸收且 `started_at` = 日志时间；「已吸收→新建」与「唯一未吸收→并入」两条分支均验证；时段外产生 `outside_window/warning` 且会话不被阻断（D10）。
- 未验证（本手册要补的）：真实 `docker logs -f -t` 传输层、容器 stdout+stderr 合并、`--since` 纳秒精度与 #36 碰撞率、provision 端到端、空闲/时长清扫在真实时间流逝下的行为。

---

## 9. 常见问题

| 现象 | 原因/处置 |
|---|---|
| `flows` 里并发闸门用例失败 | 库里有上轮遗留的 open panel 会话；夹具按「当前 open 数 + 1」限额，若仍有残留，清库重跑或手工关会话（当前无关闭端点，删行即可） |
| `log-events` 为空 | 采集器 `--tail 0`；先起 panel 再连客户端。或 `logcollect.enabled` 仍为 false |
| native 会话 `started_at` 是「现在」而非日志时间 | 说明走的是事件到达时间；检查是否绕过 docker 传输层（本脚本不绕过） |
| `provision` 容器一直不出现 | 端口池冲突（本机 21116 被占）或镜像拉取失败；`docker ps -a`、`panel-data/panel.log` 里的 provision 审计 |
| panel 启动即退出 | 多半是 `auth.secret` 为空；脚本已生成随机 secret，手工部署时要设 `PANEL_AUTH_SECRET` |
