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
| `tools/regression/m3native/` | Go 夹具（**脚本不调用**）：只替换 docker 传输层，用**离线** hbbs 日志文件驱动「解析 → LogEvent → native 归并 → 告警」；用于无容器环境自测，需一次性数据库（见 §10） |
| `docs/reference/step5-collision-probe.sh` | #36 纳秒碰撞率专项（本手册 §6 可选） |
| 本手册 | 步骤、判定表、报告要求 |

> 前置要求精确版：docker（`docker ps` 可用）、**go 1.27+**（`go.mod` 指定 `go 1.27` + `toolchain go1.27.2`，`GOTOOLCHAIN=local` 的机器会失败）、curl、python3、bash。

---

## 1. 执行顺序

```bash
git clone --depth 1 -b develop https://github.com/GogoYang0/Rustdesk-Control-Panel-API.git
cd Rustdesk-Control-Panel-API
chmod +x docs/reference/step5-m3-run.sh docs/reference/step5-collision-probe.sh
PUBLIC_HOST=<云主机公网IP或域名> ./docs/reference/step5-m3-run.sh /root/step5m3-work
# 脚本跑到 §6 会打印客户端接入参数（ID/中继/Key）并等待回车；接完客户端回车继续
# 可选：带碰撞率专项重跑（会复用已起的 panel 与组织）
PUBLIC_HOST=<同上> ./docs/reference/step5-m3-run.sh /root/step5m3-work --probe
```

- `PUBLIC_HOST` 必填：`provision.relayHost` 会写进配置并下发给客户端，填 `127.0.0.1` 远程客户端将不可达。不传时脚本尝试用 `api.ipify.org` 探测。
- **可重跑**：panel 已在跑（`panel-data/panel.pid` 存活）则跳过启动；组织按名字 `step5m3-provision-org` 复用，不会每次烧掉一个 5 端口块。
- 若 `BRANCH` 不含 `tools/regression/`，脚本会在 §1 直接失败并提示——**先把本工具合入目标分支**再跑。

---

## 2. 脚本自动完成的部分（阶段 0–5）

| 阶段 | 做什么 | 判定 |
|---|---|---|
| 0 | `docker ps` / `go version` / `curl` / `python3` 四项检查 | 四项齐备 |
| 1 | 构建 panel（打印 commit） | 构建成功 |
| 2 | 写配置（**`logcollect.enabled=true`**、示例规则、`session.idleTimeout=10m`、`relayHost=$PUBLIC_HOST`）并启动 panel | `/healthz` = 200 |
| 3 | 夹具 `seed`（需 `-confirm-seed`）：直写库造 owner（`step5m3@example.com` / `step5m3-pass-123456`）、组织、设备（`123456789`）、一条 native 会话 | 退出码 0 |
| 4 | 夹具 `flows`：12 项 HTTP 断言 | 全部 PASS（明细在 `evidence/*.json`） |
| 5 | 用 API 建**第二个组织**（或复用）触发 provision，等容器出现，读 `server_groups` 得到**真实端口**，检查 `docker logs -t` 与 hbbs 公钥 | 容器就绪、日志含监听行、拿到 Key |

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

> 因为 `seed` 会向目标库写入一个**已知口令、已验证**的 owner，带 `-confirm-seed` 才允许执行；**永远不要把它指向生产库**。

---

## 4. 真实客户端接入（脚本 §6 前必须做）

无法在无 GUI 容器里自动完成「客户端注册」这一步，需一台能连到云主机的 RustDesk 客户端（你的本机即可）。脚本会打印三个参数，照填：

| 客户端字段 | 取值（脚本 §5 输出） |
|---|---|
| ID 服务器 | `$PUBLIC_HOST:<hbbs_port + 1>`（首块即 `21117`） |
| 中继服务器 | `$PUBLIC_HOST:<hbbr_port + 1>`（首块即 `21119`） |
| Key | `docker logs panel-org-<orgId>-hbbs \| grep "Key:"` 的最后一段 |

> 端口映射规则：panel 给每个组织分配**连续 5 端口**（如 `21116..21120`），容器把 hbbs 映射到 `hbbs_port+1`、hbbr 映射到 `hbbr_port+1`。**不要照抄 `21116/21117`**——那是宿主/容器内部端口，不是客户端入口。

启动客户端后，hbbs 容器日志应出现（1.1.16 实测为 `src/peer.rs:102`，某些版本/文档写作 `rendezvous_mediator.rs`）：

```
[...] INFO [src/peer.rs:102] update_pk <设备ID> [::ffff:<客户端IP>]:<端口> ...
```

脚本随后会分两步完成采集断言（顺序不能颠倒）：

1. 你启动客户端完成**第一次注册** → 脚本从 hbbs 容器日志读出该设备 ID（读不到会提示你手输客户端显示的 ID）；
2. 脚本把该 `rustdesk_id` **登记到组织** `$ORG2`（面板只关联同组织内已登记的设备，登记前处理的行不会 retro-link）；
3. 脚本提示你在客户端**断开并重连**一次，让新的注册行在设备登记之后到达；
4. 脚本轮询最多 90 秒，断言 `log-events` 出现 `kind=conn`、`sessions?origin=native` 出现 native 会话。

> 采集器是 `--tail 0` 起步（不回填历史）：**先启动 panel 再连客户端**才能采到。

---

## 5. 手工判定表（脚本断言的展开，便于排障）

前缀：`AT=<access_token>`（脚本已算出 `$TOKEN`），`O=<orgId>`。

| # | 操作 | 期望 |
|---|---|---|
| D1 | `docker ps --filter name=panel-org-$O-` | 两个容器 Running，端口在 `21116–22115` 池内且成对 |
| D2 | `docker logs -t panel-org-$O-hbbs \| head` | 时间戳前缀为 RFC3339Nano（采集游标消费的就是它） |
| D3 | `curl $API/api/v1/orgs/$O/log-events -H "Authorization: Bearer $AT"` | 出现 `source=hbbs` 的 `conn` 事件，`device_id` 对应真实客户端（该 `rustdesk_id` 必须已登记在同组织） |
| D4 | `curl "$API/api/v1/orgs/$O/sessions?origin=native&pageSize=50"` | 至少 1 条 `origin=native,status=open`，`started_at` = hbbs 行的 **docker 捕获时间** |
| D5 | 客户端断开后再连 | 契约：已吸收连接的会话不重开 → 新建第二条 native 会话（**多记不漏记**）。**注意触发条件**：RustDesk 重连时若密钥未变，hbbs **不会**再打印 `update_pk`（源码 `rendezvous_server.rs` 仅在 pk/uuid 变化时调用 `update_pk`），因此**普通重连不产生新日志行、也就不会开新会话**；要构造该分支需让客户端更换密钥对（重装/重置密钥确认）或让 hbbs 侧丢失 peer 记录（重启 hbbs 容器） |
| D6 | 把 `session.idleTimeout` 调小（如 `1m`）重启 panel | 超过窗口无事件的 open 会话被置 `closed/end_reason=idle_timeout` |

> 注意：`sessions` 的分页参数是 `page`/`pageSize`，**不是 `limit`**（`limit` 只属于 `log-events`）。

> **客户端 `api-server` 端口（云端实测踩过）**：RustDesk 客户端把 `custom-rendezvous-server` 的端口 **减 2** 当作 API 端口（本例 21117−2 = 21115），而该端口在宿主上没有映射到任何 HTTP 服务 → 客户端日志出现 `POST .../api/sysinfo → Connection refused`，随后 TCP proxy fallback 超时，**启动被拖慢约 40 s**。注册（`register_pk`）在此之前已发出，因此不影响本手册的断言；若要消除延迟，在客户端里显式把 `api-server` 指向面板的 compat 入口（`http://<panel>:8080`，或留空）。

---

## 6. #36 纳秒碰撞率专项（可选）

```bash
bash docs/reference/step5-collision-probe.sh "100 1000 5000 20000"
```
口径：`docker logs -t` 的**捕获时间戳**（与 hbbs 消息内时间戳是两个时钟）。

实现要点（这两个坑第一次云端实测时踩过，现已内置修正）：**docker 只捕获 PID 1 的 stdout/stderr**，用 `docker exec ... echo` 造行 `docker logs` 永远读不到；因此每档把「输出循环」作为容器 entrypoint，并让**每档一个独立容器**、退出后一次性取样（无需 `--since`，也不会有上一档的行混入）。实测吞吐会远低于名义值（每行一次 fork + `sleep` 精度），脚本按时间戳跨度打印 `actual`，解读以 `actual` 为准。

**2026-10-23 云端实测（Ubuntu 24.04 / Docker 27.5.1，SAMPLES=5000）**：

| 名义(行/s) | 实测(行/s) | 同纳秒 | 同毫秒 | 同秒 |
|---|---|---|---|---|
| 100 | 95 | 0 (0.0000%) | 0 | 4947 |
| 1000 | 686 | 0 (0.0000%) | 2 | 4992 |
| 5000 | 1540 | 0 (0.0000%) | 1880 (37.6%) | 4996 |
| 20000 | 2134 | 0 (0.0000%) | 2693 (53.9%) | 4996 |

结论：各档同纳秒碰撞率 **0** → `+1ns` 游标方案（重连 `--since <last+1ns>`）可行，**#36 维持低优先级**。附带约束：高吞吐档同毫秒碰撞达 37–54%，**游标不得降级到毫秒精度**（会漏行）。


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

## 8. 已知基线

**Windows（2026-10-23）**：面板侧 12 项 **12/12 PASS**；native 归并 **7/7 PASS**（仅替换 docker 传输层，回放离线日志）。

**云端 Linux + Docker（2026-10-23，Ubuntu 24.04 / Docker 27.5.1 / Go 1.27.2 / rustdesk-server 1.1.16 / 客户端 1.5.0，commit `443b949`）**：

- 面板侧 **12/12 PASS**；容器与 native 链路 **D1–D6 6/6 PASS**。
- 一键脚本首轮 `PASS=16 / FAIL=3`——3 个 FAIL 全在 §6，因该环境无真人操作 GUI 客户端；补装客户端后三项转 PASS。
- 容器侧新增证据：真实 `docker logs -f -t` 路径打通（`started_at` 取捕获时间，与行内时间差 0.11 ms）；**hbbs 写 stderr**，stdout/stderr 合并必需；provision 真实端口块与公钥；真实时间流逝下 `idle_timeout` 清扫（1m 窗口 90s 内 2 条转 closed）；panel 重启后采集器自动恢复（`organizations=2`）。
- 首次云端实测暴露的**工具/文档缺陷**（已修，见本仓库 `fix/step5-probe-and-runbook`）：①碰撞率探针因 `docker exec` 造行而全部 `lines=0`；②D5 未写明「同密钥重连不产生 `update_pk`」；③客户端 `api-server` 端口推导（id 端口 −2）导致 40s 启动延迟，需显式指向面板。
- 仍未验证：时长清扫（`max_session_minutes`）、数据面 P2P/relay 实际连接、采集器在容器重启/日志轮转下的 `--since` 游标、端口池耗尽路径、GUI 密钥确认交互。

---

## 9. 常见问题

| 现象 | 原因/处置 |
|---|---|
| `flows` 里并发闸门用例失败 | 库里有上轮遗留的 open panel 会话；夹具按「当前 open 数 + 1」限额，若仍有残留，清库重跑或手工关会话（当前无关闭端点，删行即可） |
| `log-events` 为空 | 采集器 `--tail 0`；先起 panel 再连客户端。或 `logcollect.enabled` 仍为 false |
| native 会话 `started_at` 是「现在」而非日志时间 | 说明走的是事件到达时间；检查是否绕过 docker 传输层（本脚本不绕过） |
| 有 `conn` 事件但没有 native 会话 | 该 `rustdesk_id` 未登记在本组织（面板只关联已登记设备）；检查脚本 §6 的 device 登记输出 |
| `provision` 容器一直不出现 | 端口池冲突（本机 21116 被占）或镜像拉取失败；`docker ps -a`、`panel-data/panel.log` 里的 provision 审计 |
| panel 启动即退出 | 多半是 `auth.secret` 为空；脚本已生成随机 secret，手工部署时要设 `PANEL_AUTH_SECRET` |
| 重跑报端口占用 | 说明 `panel.pid` 记录的不是 panel 本体（旧脚本缺陷，已改为 `exec nohup`）；手工 `pkill -f "$WORKDIR/panel"` 后重跑 |

---

## 10. `m3native`：无容器环境下的替代验证（不是本脚本的一部分）

当云端暂时不可用时，可以用 `tools/regression/m3native` 在**任意有 Go 的机器**上验证「解析 → LogEvent → native 归并 → 告警」这段逻辑：它把 docker 传输层换成一个回放**离线 hbbs 日志文件**的 `LineStreamer`，其余全是生产代码。

```bash
# 需要一份真实 hbbs 日志（含 update_pk 行），例如从容器导出：
docker logs -t panel-org-1-hbbs > hbbs.log
go run ./tools/regression/m3native -db "file:/tmp/m3native.db" -logfile ./hbbs.log -out /tmp/m3native-evidence -phase all
```

- **必须用一次性数据库**：它会在 `server_groups` 里写入/翻转该组织为 `deployed`（为了触发真实 `Service.Start` 的 tail 条件）。**运行前先停掉使用同一数据库的 panel**；指向在用的面板库会让该组织后续 provision 报「已供应」，端口块被占。若组织行已存在且非 `deployed`，工具会拒绝执行并提示；确需翻转时加 `-force-state`。
- 它**不能**替代容器验证：docker CLI 本身、容器 stdout/stderr 合并、`--since` 纳秒精度与 #36 碰撞率都必须在云端真跑（工具的 SKIP 项会如实列出）。
