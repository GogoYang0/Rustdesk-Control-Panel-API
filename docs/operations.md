# 运维指南（Operations Guide）

> 适用版本：v0.3.0（M2）。本文档随版本演进持续更新——每次发布前必须复核一遍。
> 配套文档：[部署指南](deployment.md) · [后端 API 规范](api-spec.md)

---

## 1. 日常管理操作（管理 API）

所有管理操作通过面板 API 完成（Bearer 管理令牌，15 分钟有效，`/api/v1/auth/refresh` 轮换）：

| 操作 | 端点 | 权限 |
|---|---|---|
| 创建组织 | `POST /api/v1/orgs` | 任意已验证用户（受 `maxOrgsPerUser` 限制） |
| 邀请成员 | `POST /api/v1/orgs/{orgId}/invitations` | admin |
| 接受邀请 | `POST /api/v1/invitations/accept` | 被邀请人 |
| 查看设备 | `GET /api/v1/orgs/{orgId}/devices` | member（owner/admin 见契约） |
| 删除设备（解绑 compat 客户端） | `DELETE /api/v1/orgs/{orgId}/devices/{deviceId}` | admin |
| 查询日志事件 | `GET /api/v1/orgs/{orgId}/log-events` | member |

**设备解绑**是 compat 层最高频的管理操作：客户端重装/换机后 uuid 变化，登录报 403「设备已绑定」→ 管理员删除设备行 → 客户端重新登录即重新认领。删除设备不影响历史心跳与日志事件（按组织保留）。

---

## 2. 设备在线判定与心跳

设备 `online` 的判定：`last_seen_at + OnlineWindow > now`（时间只前进，慢到的旧心跳不会回退时间戳）。

心跳有两个来源，在 `DeviceHeartbeat.source` 中区分：

| 源 | 触发 | 去重 |
|---|---|---|
| `api` | 原生客户端 `POST /api/heartbeat`（无凭据，凭 uuid+设备 id 定位会话） | 30s 窗口合并（`apiHeartbeatMinInterval`），**事务内 `RowsAffected` 守卫**保证并发下每窗口一行 |
| `log` | 日志采集器从 hbbs 日志中识别出连接行为（C11） | 30s 窗口（`logHeartbeatMinInterval`），`RecordLogActivity` 前置检查 + 事务内守卫 |

运维要点：

- 心跳历史每天每设备最多 2,880 行（两源各一），可作为设备活跃度审计数据
- 客户端心跳是**幂等**的：窗口内的重复上报返回成功但不追加行；返回的设备状态是刷新后的
- 管理端点返回的设备状态在心跳合并竞态下也保证是最新值（不会把刚上线的设备报成 offline）

---

## 3. 审计日志

- 写入路径：管理 API 由中间件回退记录（一次可审计请求恰好一条）；地址簿等领域写由 `TxRecorder` 在**实体事务内**原子记录（#26）；compat 写路径的归因由中间件回退读取 `compat.*` 上下文（#37，v0.3.0 恢复）
- **完整性**：每条审计行带 per-org 连续序列号，序列断裂即表示行被删除或篡改——巡检时应检查序列连续性
- 无租户请求（login、healthz）不产生持久审计行（`GormAuditor` 对 org 0 直接丢弃，有意 fail-closed）
- 遗留：compat 写路径的**事务级**审计（与业务写同事务）尚未实现，当前为请求级归因

---

## 4. 日志采集运维

### 4.1 生命周期

| 事件 | 采集器行为 |
|---|---|
| 组织部署成功 | `Watch`：确认 server group 仍 deployed 后启动 hbbs/hbbr 两个 tailer |
| 首次连接 | `--tail 0` 只跟随新行（历史不回灌） |
| 重连 | `--since <最后确认时间戳+1ns>`（闭区间 `--since` 从该时间戳起读） |
| 行写入失败 | 停止当前流，断点**不推进**，重连重放该行；退避继续增长（DB 不可用时不猛打） |
| 组织下线 | `OnDeprovisioned → Unwatch` 取消 tailer（仅删除成功后触发） |
| 关闭 | `Wait` 置 `closed` 标志后 `WaitGroup.Wait`；关闭后的迟到部署回调不注册新 tailer |

### 4.2 规则与事件

- 规则按序匹配、首条命中即停；命名捕获组写入 `DetailJSON`，`device` 捕获组把事件关联到设备并产生辅助心跳
- 匹配不上的行**按设计丢弃**（C7），每分钟至多记一条 `unparseable` 速率限制告警——大量 unparseable 说明规则与镜像实际格式不符
- 事件保留 30 天（`DefaultLogEventRetentionDays`），启动时清扫

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
| 5xx 后用户收不到 | 永久错误不重试（设计） | 让用户点重发（`/api/v1/auth/resend-verification`） |
| 令牌结果不明 | 连接中断，投递状态未知 | 验证码/邀请令牌保留，用户可重试 |

---

## 6. Provisioning 运维

- 每组织一对容器：`panel-org-<orgId>-hbbs` / `-hbbr`，端口从 `provision.portStart..portEnd` 池分配并持久化在 `ServerGroup` 行
- 供应队列：`provision.workers` 并发；失败的部署保留行与端口（不回收），由对账 reconciler（2 分钟周期）重新入队——**不要手工删除 `ServerGroup` 行**，会造成端口重复分配
- 下线：`Deprovision` 删除容器 → 删行 → `Unwatch` 采集器；失败时行保留（failed 状态），端口继续被占用
- `provision.dataDir/org-<orgId>/` 含各组织密钥与数据（`dataDir` 可配置，默认根目录为 `./data/servergroups`）：**备份范围必须包含它**，否则重建容器后客户端 ID 不变但密钥丢失

---

## 7. 备份与恢复

| 数据 | 位置 | 频率建议 |
|---|---|---|
| 关系数据（用户/组织/设备/审计/日志事件/供应状态） | `panel.db` 或外部 DB | 每日；审计行是安全证据，保留期越长越好 |
| 各组织 hbbs/hbbr 密钥与数据 | `provision.dataDir`（默认 `./data/servergroups`，组织子目录为 `org-<orgId>/`） | 每日（与 DB 同步点） |

恢复：恢复 DB + 数据目录 → 启动 panel → AutoMigrate 幂等 → 供应状态从 `ServerGroup` 行恢复（reconciler 会对账）。

**审计完整性巡检**：按组织检查 audit 序列号连续性（断号 = 行被删/篡改）。

---

## 8. 监控建议（当前无内建指标端点）

可从 panel 自身的 JSON 日志（`log.format=json`）采集以下信号：

| 信号 | 日志关键字 | 含义 |
|---|---|---|
| 供应失败 | `provision` + error / `markFailed` | 需要人工检查 docker/端口 |
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
