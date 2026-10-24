# 运维指南（Operations Guide）

> 适用版本：v0.7.0（按组织 provisioning 开关 + 宿主端口探测；已发布基线 v0.4.0）。本文档随版本演进持续更新——每次发布前必须复核一遍。
> 配套文档：[部署指南](deployment.md) · [后端 API 规范](api-spec.md)

---

## 1. 日常管理操作（管理 API）

所有管理操作通过面板 API 完成（Bearer 管理令牌，15 分钟有效，`/api/v1/auth/refresh` 轮换）：

| 操作 | 端点 | 权限 |
|---|---|---|
| 创建组织 | `POST /api/v1/orgs` | 任意已验证用户（受 `maxOrgsPerUser` 限制） |
| 邀请成员 | `POST /api/v1/orgs/{orgId}/invitations` | admin |
| 接受邀请 | `POST /api/v1/invitations/accept` | 被邀请人 |
| 移除成员（离场） | `DELETE /api/v1/orgs/{orgId}/members/{userId}`（v0.6.0；同事务撤销该用户 compat 会话） | owner/admin |
| 变更成员角色 | `PATCH /api/v1/orgs/{orgId}/members/{userId}`（v0.6.0；仅 admin↔member，仅 owner 可调） | owner |
| 查看设备 | `GET /api/v1/orgs/{orgId}/devices`（v0.5.0；分页、`q` 搜索、`bound` 过滤） | member |
| 重置设备绑定（换机/重装） | `POST /api/v1/orgs/{orgId}/devices/{deviceId}/rebind`（v0.5.0；`reason` 必填） | owner/admin |
| 查看/切换供应开关 | `GET/PUT /api/v1/orgs/{orgId}/provisioning`（v0.7.0；关闭同步下线、开启异步入队；`cleanup_pending` 表示清理未完成） | owner |
| 查询日志事件 | `GET /api/v1/orgs/{orgId}/log-events` | member |

**设备解绑**是 compat 层最高频的管理操作：客户端重装/换机后 uuid 变化，登录报 403「设备已绑定」→ 管理员在设备列表找到该设备（同名多组织时先确认组织）→ 调 `rebind` 填理由 → 客户端重新登录即重新认领。`rebind` 会清绑定并让代数 +1，旧客户端随后的心跳/系统信息被丢弃；重复调用安全。
**先让旧机离线再让新机登录**：`rebind` 不吊销旧机的 compat token，也无法阻止一台仍在线、持同账号凭据的旧机**先于**新机重新认领（绑定是先到先得）。若新机仍报 403，说明旧机抢先认领了，先让旧机退出登录/离线，再重置一次即可。
**不要手改数据库**：只改 `bound_uuid` 而不动 `binding_generation` 会让旧会话继续驱动设备（最长到 token 过期），且没有审计可追。

---

## 2. 设备在线判定与心跳

设备 `online` 的判定：`last_seen_at + OnlineWindow > now`，且 `last_seen_at` 不得比 `now` 超前超过 5 秒（`ClockSkew`）——超前的设备判定为 offline（时钟偏差的节点不能借未来时间戳保持在线）。时间只前进，慢到的旧心跳不会回退时间戳。

心跳有两个来源，在 `DeviceHeartbeat.source` 中区分：

| 源 | 触发 | 去重 |
|---|---|---|
| `api` | 原生客户端 `POST /api/heartbeat`（无凭据，凭 uuid+设备 id 定位会话） | 与 `log` 源**共享**设备 `last_seen_at` 的 30s 合并窗口，事务内 `RowsAffected` 守卫保证并发下每窗口一行 |
| `log` | 日志采集器从 hbbs 日志中识别出连接行为（C11） | 与 `api` 源共享同一窗口（`logHeartbeatMinInterval`），`RecordLogActivity` 前置检查 + 事务内守卫 |

运维要点：

- 心跳历史每天每设备最多 2,880 行（**两源共享同一 30s 窗口**，非各自 2,880）；有行不能证明两个源分别产生了活动
- 客户端心跳是**幂等**的：窗口内的重复上报返回成功但不追加行；返回的设备状态是刷新后的
- 管理端点返回的设备状态在心跳合并竞态下也保证是最新值（不会把刚上线的设备报成 offline）

### 2.1 边界与已知局限（v0.3.0 设计现状）

- **免凭据心跳 = 不可信的活跃提示**。`/api/heartbeat`、`/api/sysinfo` 无凭据，任何知道 `(rustdesk id, uuid)` 组合的调用者都可提交活动。设备活跃数据**不得作为安全决策依据**：授权判断一律基于管理令牌或 compat 会话（签名令牌 + 活跃 JTI）。写放大已由 30s 窗口收敛；全局请求限流为后续硬化项；日志保留期的周期化清扫见 [#41](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/41)。
- **offboarding 即时撤销（v0.6.0 已接线）**。移除成员（`DELETE .../members/{userId}`）与 admin→member 降级在**同一事务**内调用 `compatapi.RevokeOrgSessions` 撤销该用户在本组织的全部活跃 compat 会话；撤销失败整体回滚并返回 500，不会出现「已删除」半状态。被撤销的 compat 令牌立即失效（管理请求 401、免凭据心跳不再生效），无需等待 720h 过期。
- **设备认领的竞态已关闭（v0.4.0）**。认领与会话落库在同一事务，落败方不留会话行；设备带**绑定代数**（每次绑定变更 +1，v0.5.0 起由 `rebind` 端点承担重置），会话快照登录时的代数，旧代数会话的心跳/系统信息被丢弃——绑定的所有权语义不依赖 uuid 保密性。免凭据心跳仍是**不可信活跃提示**（无凭据的本质不变），但落败/过期会话不再能驱动设备活动。
- **审批中心轮询是静默读**：`GET .../approvals`、`GET .../alerts` 不写审计（请求级审计回退被抑制），详情读（单个 approval）会记录——与票据/会话详情同规则。

### 2.2 会话治理运维（v0.4.0）

后台任务（共享调度器，每 1 分钟一轮，启动即跑首轮）：

| 任务 | 语义 | 运维关注 |
|---|---|---|
| `approval-expiry` | 超期 pending 审批置 `expired`（仅标记，不发通知） | 审批中心不再显示死请求；无告警 |
| `session-idle` | `last_activity_at`（缺省回退 `started_at`）超过 `session.idleTimeout`（默认 10 分钟）的 open 会话置 `closed`（`end_reason=idle_timeout`） | 日志断流（容器停止/采集中断）的会话由它兜底关闭；非违规、无告警。`session.idleTimeout` **必须为正**——配置 `0` 或负值不是"禁用清扫"，而是记 warning 并回退默认 10 分钟 |
| `session-duration` | 超过策略 `max_session_minutes` 的 open 会话置 `closed`（`end_reason=policy_exceeded`）并写 **critical** 告警 | 真实连接不被掐断（面板不在信令链路）——告警是唯一信号，**必须处置** |

**告警处置**（`GET .../alerts`，severity 语义）：

- `critical`（`duration_exceeded`）：native 会话超出策略时长仍在运行（D10：面板不阻断 native）。处置 = 联系设备管理员 / 网络侧断开，或收紧策略。D10 语义下若连接持续，之后每过一个 `max_session_minutes` 会再产生一条——这是"宁可多记"的设计取向，不是重复告警缺陷。
- `warning`（`outside_window`，native）：原生直连发生在策略时段外且连接已在运行；同上只能事后处置。
- `warning`（`concurrency_exceeded`）：panel 兑换被并发上限拒绝——已被阻断，无连接发生，留痕供审查配额是否合理。
- `info`（`outside_window`，panel）：签发被时段拒绝——已被阻断，无连接发生。

**审批流程**（`GET/POST .../approvals`）：成员提交 → owner/admin 在审批中心决策（approve/deny）。`pre_approval` 批准后**放行一次签发**（签发即消费审批）；`ratification` 批准即"已追认"，不出票。超期请求由 `approval-expiry` 自动过期，无需手工清理。

---

## 3. 审计日志

- 写入路径：管理 API 由中间件回退记录（一次可审计请求恰好一条）；地址簿等领域写由 `TxRecorder` 在**实体事务内**原子记录（#26）；compat 写路径的归因由中间件回退读取 `compat.*` 上下文（#37，v0.3.0 恢复）
- **完整性**：每条审计行带 per-org 连续序列号，序列断裂即表示行被删除或篡改——巡检时应检查序列连续性
- 无租户请求（login、healthz）不产生持久审计行（`GormAuditor` 对 org 0 直接丢弃，有意 fail-closed）
- 遗留：compat 写路径的**事务级**审计（与业务写同事务）尚未实现，当前为请求级归因
- **M3 新增的领域审计动作**（`TxRecorder` 在实体事务内记录）：`session.ticket.issue`（票据签发）、`session.ticket.redeem`（票据兑换）、`session.ticket.denied`（策略拒绝）、`session.approval.request`（新建审批请求；复用不重复记）、`session.approval.decide`（approve/deny 决策）、**`device.binding.reset`（v0.5.0 重置设备绑定；含 actor、`rustdesk_id`、reason、had_binding）**、`organization.member.remove` / `organization.member.role`（v0.6.0 成员离场；含目标用户、角色变化与撤销会话数）。会话治理与设备列表的**轮询读不产生审计**（读静默），单个详情读会记录；provision 供应与保留期清扫等基础设施动作的审计见 provision 相关节（#46）

---

## 4. 日志采集运维

### 4.1 生命周期

| 事件 | 采集器行为 |
|---|---|
| 组织部署成功 | `Watch`：确认 server group 仍 deployed 后启动 hbbs/hbbr 两个 tailer |
| 首次连接 | `--tail 0` 只跟随新行（历史不回灌） |
| 重连 | `--since <最后确认时间戳+1ns>`（闭区间 `--since` 从该时间戳起读）。⚠️ **同时间戳多行不会被完整重放**（与最后确认行共享同一 Docker `--timestamps` 捕获时间戳的后续行会被跳过）——见 [#36](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/36)；修复断点算法前的回归标准在 #36 验收节。时间戳指 Docker 捕获时间，不是 hbbs 消息内时间 |
| 行写入失败 | 停止当前流。**已有确认断点**时，断点保持不变并从最后确认位置重连；**断点为零**（首条带时间戳行即失败）时，断点锚定为该行时间戳前 `1ns`，从该时间戳重连——会重放失败行以及退避期间产生的行。注意：①若失败行与最后确认行同时间戳，该行可能无法重放（[#36](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/36) 已记录该限制与回归标准）；②若当前流此前已交付过至少一行，重连前退避会**重置**为初始值——DB 长时间不可用时可能按初始间隔重试（已知行为） |
| 组织下线 | `OnDeprovisioned → Unwatch` 取消 tailer（仅删除成功后触发） |
| 关闭 | `Wait` 置 `closed` 标志后 `WaitGroup.Wait`；关闭后的迟到部署回调不注册新 tailer |

### 4.2 规则与事件

- 规则按序匹配、首条命中即停；命名捕获组写入 `DetailJSON`，`device` 捕获组把事件关联到设备并产生辅助心跳
- 匹配不上的行**按设计丢弃**（C7），每分钟至多记一条 `unparseable` 速率限制告警——大量 unparseable 说明规则与镜像实际格式不符
- 事件保留 30 天（`DefaultLogEventRetentionDays`）：由后台调度器按 `logcollect.retentionSweepInterval`（默认 6h）执行，启动即清扫一次——**与采集启停解耦**，停用采集也会执行（#41）；设为 `0` 则完全停用保留期清理。清扫是**分批删除**（每批 `pruneBatchSize` 行，默认 1000），避免大表长事务
- 事件 kind 与会话治理的映射：`conn`=连接事件、`file`/`error`=活动事件、`disconnected`=连接结束（**默认规则集不含**——rustdesk-server 默认日志级别不打印断开行，见部署指南 §6 第 6 条；自定义规则必须放在宽泛 connection 规则之前）。kind→会话语义的完整规则见运维指南 §2.2 与 API 规范 §3.6

### 4.3 常见问题

| 症状 | 原因 | 处置 |
|---|---|---|
| 启用采集后零事件 | 规则与镜像日志格式不符（如换用了非 1.1.11 镜像） | `docker logs -t <容器>` 抽样核对，调整规则后重启 |
| 大量 `unparseable` 告警 | 同上 | 同上 |
| 事件里设备关联为空 | 该行的 device 捕获组为空，或设备不在本组织 | 检查规则捕获组与设备注册状态 |
| 采集器频繁重连 | 容器被重建（正常）或 docker socket 异常 | 看 panel 日志的 tailer warn |

---

## 5. 邮件运维

| 症状 | 原因 | 处置 |
|---|---|---|
| 用户未收到验证邮件 | devMode=true（邮件在 panel stdout 里） | 生产必须 `mail.devMode=false` |
| SMTP 报 STARTTLS 相关错误 | 服务器不支持 STARTTLS | panel **拒绝明文发送**——改用支持 TLS 的 relay |
| 验证邮件 5xx 后用户收不到 | 永久错误不重试（设计） | 让用户点重发（`/api/v1/auth/resend-verification`） |
| 邀请邮件 5xx 后用户收不到 | 永久错误不重试（设计） | **没有邀请重发端点**——等待邀请记录过期后重新创建邀请 |
| 验证令牌结果不明 | 连接中断，投递状态未知 | 验证令牌保留，用户可重试 |
| 邀请令牌结果不明 | 连接中断，投递状态未知 | 邀请令牌保留；同样没有重发端点，过期后重建 |

---

## 6. Provisioning 运维

- **单实例前提**：供应队列、reconciler 与组织级切换锁都是**进程内**组件，同一数据库只应由一个 panel 实例执行 provisioning；多实例会重复对账并绕过切换锁（数据库侧的开关复核与 `RowsAffected` 守卫仍会清理越权持久化的行，但容器操作无法跨进程互斥）
- 每组织一对容器：`panel-org-<orgId>-hbbs` / `-hbbr`，端口从 `provision.portStart..portEnd` 池分配并持久化在 `ServerGroup` 行
- **开关 API（v0.7.0，仅 owner）**：`GET/PUT /api/v1/orgs/{orgId}/provisioning`。关闭（`enabled=false`）会同步删除容器、删除 `ServerGroup` 行、置 `provisioning_disabled`，并在同一事务写 `organization.provisioning.update` 审计（`Detail` 含 `removed_deployment` 与端口）；容器删除失败则请求 500、行标 `failed`、开关不变。开启只清除标记并把组织交给队列（队列满由 reconciler 兜底）；**下次部署会重新生成服务端密钥对**（`dataDir/org-<orgId>/` 中的数据保留，但密钥文件被覆盖，客户端需重新配对）。重复关闭会清理并发失序遗留的部署行（自愈）
- **在途部署的关闭（deferred cleanup）**：若关闭时行状态为 `provisioning` 且未超过 10 分钟宽限，接口**不删除该行**（审计 `Detail.deferred_cleanup=true`、`state=provisioning`），保留为容器清理锚点；在途部署在持久化时发现开关已关会自行回滚。若回滚删除失败，行会保留为 `failed`，重复关闭会**立即**重试清理；若进程在部署中途中断，行保持 `provisioning`，重复关闭需在该行超过 10 分钟宽限后才会清理。这样不会出现“容器仍在运行但数据库无行可追踪”的状态
- **回滚归属校验**：失败部署在删除容器前会核对当前 `ServerGroup` 行的 id；若组织已被关闭并重新开启、已存在更新的部署行，旧尝试**不会**删除同名容器（容器名按组织复用，无法凭名字区分代际）
- 供应队列：`provision.workers` 并发。部署失败后会执行清理：**清理成功 → 删除 `ServerGroup` 行并释放端口；清理失败 → 行保留为 `failed` 状态**。保留的行会被 `PendingOrgIDs` 排除，对账 reconciler（2 分钟周期）**不会**重新入队——清理失败的部署必须人工处理（残留容器、行、端口）
- **启动端口探测**：启动日志 `provision port range is free` 表示范围内（已预留块除外）没有外部占用；`provision port range has externally occupied ports` 会列出 `端口/协议`，表示面板外进程占用了可分配端口——调整 `provision.portStart/portEnd` 或停止占用进程。探测绑定本机 IPv4 通配地址、只告警不阻断启动；**IPv6-only 监听不在探测范围**；`DOCKER_HOST` 指向远端时本机探测不适用
- **部署前预检**：每次 provision 在 `docker run` 前检查本块 5 个 TCP 端口 + 主端口 UDP；冲突时返回 `host port already in use: <port>/<协议>` 并**释放本次分配**（不产生失败行）。reconciler 会周期性重试；**若外占长期存在，每次重试仍可能按端口池顺序选中同一块**——启动告警给出根因，处置方式是调整端口范围或停止占用进程
- ⚠️ **端口规划前提**：`PortPool` 只按 DB `server_groups` 判重，不感知面板外占用；预检只是提前诊断，探测与 `docker run` 之间仍有竞态。规划端口池时确保范围独占；相关可观测/控制缺口跟踪于 [#46](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/46)
- 下线：`Deprovision` 删除容器 → 删行 → `Unwatch` 采集器；失败时行保留（failed 状态），端口继续被占用，且不会由 reconciler 自动重试
- `provision.dataDir/org-<orgId>/` 含容器运行时数据（`dataDir` 可配置，默认根目录为 `./data/servergroups`）：**备份范围必须包含它**。服务端密钥对由 panel 每次部署时生成并覆盖，恢复后客户端需按 `ServerGroup.pub_key` 重新配对

---

## 7. 备份与恢复

| 数据 | 位置 | 频率建议 |
|---|---|---|
| 关系数据（用户/组织/设备/审计/日志事件/供应状态） | `panel.db` 或外部 DB | 每日；审计行是安全证据，保留期越长越好 |
| 各组织 hbbs/hbbr 密钥与数据 | `provision.dataDir`（默认 `./data/servergroups`，组织子目录为 `org-<orgId>/`） | 每日（与 DB 同步点） |

恢复：恢复 DB + 数据目录 → **恢复对应的 Docker 容器状态**（reconciler 会跳过已有 `ServerGroup` 行的组织，不会重建缺失的容器）——容器状态不可恢复时，须对每个已恢复的组织执行并验证容器重建 → 启动 panel → AutoMigrate 幂等。

**审计完整性巡检**：按组织检查 audit 序列号连续性（断号 = 行被删/篡改）。

---

## 8. 监控建议（当前无内建指标端点）

可从 panel 自身的 JSON 日志（`log.format=json`）采集以下信号：

| 信号 | 日志关键字 | 含义 |
|---|---|---|
| 供应失败 | `provision` + error / `mark server group failed` / `provision rollback: remove failed` | 需要人工检查 docker/端口 |
| 审计写失败 | `audit record failed` | 审计链路异常（Drop 即损失证据） |
| 日志事件持久化失败 | `store log event failed` | DB 压力/故障；tailer 会自动重连重放 |
| 规则失配 | `unparseable`（限速告警） | 规则需要校准 |
| 采集器启停 | `log collector started`（organizations 数） | 巡检被 tail 的组织数 |

Prometheus 指标端点属后续硬化项（见 #31 描述遗留清单）。

---

## 9. 故障排查速查

| 症状 | 首查 |
|---|---|
| 客户端登录报 403「设备已绑定」 | §1 设备解绑流程 |
| 设备显示离线但客户端在跑 | 心跳源与窗口（§2）；确认 uuid/设备 id 与会话一致 |
| 地址簿同步报 400 | 契约上限（2000/256/64、字段长度）与 `ErrInvalidContent` 映射（见 API 规范 §4.2） |
| 地址簿整本推送 409 | `ab_conflict`：content hash 与服务器不一致，先 `GET /api/ab` 取最新 |
| 500 `ab` 相关 | 历史 compat 写入缺校验导致唯一索引冲突——v0.3.0 已修；仍出现请带请求样本反馈 |
| panel 启动即退出 | 启动序列某步 Fatal：看日志第一行（配置/DB/邮件校验，见部署指南 §4.1） |
| 审计序列断号 | 立即排查（§3），确认 DB 访问面 |
