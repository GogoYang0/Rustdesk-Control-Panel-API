# 运维指南（Operations Guide）

> 适用版本：v0.11.0（M6 波次 5b-1 Passkey、5b-2 OIDC、5b-3 LDAP；上一基线 v0.10.0）。本文档随版本演进持续更新——每次发布前必须复核一遍。
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
| 变更成员角色 | `PATCH /api/v1/orgs/{orgId}/members/{userId}`（仅 owner 可调；支持 admin、member 和自定义角色） | owner |
| 停用/恢复成员 | `PATCH /api/v1/orgs/{orgId}/members/{userId}`（字段 `disabled`；停用在同一事务撤销该成员在本组织的 compat 会话；重复设置当前状态不产生审计） | `member.manage` |
| 查看设备 | `GET /api/v1/orgs/{orgId}/devices`（v0.5.0；分页、`q` 搜索、`bound` 过滤） | `device.read` |
| 停用/恢复设备 | `PATCH /api/v1/orgs/{orgId}/devices/{deviceId}`（字段 `disabled`；停用在同一事务撤销该设备的 compat 会话；重复设置当前状态不产生审计） | `device.write` |
| 重置设备绑定（换机/重装） | `POST /api/v1/orgs/{orgId}/devices/{deviceId}/rebind`（v0.5.0；`reason` 必填） | owner/admin |
| 查看/切换供应开关 | `GET/PUT /api/v1/orgs/{orgId}/provisioning`（v0.7.0；关闭同步下线；开启仅在无部署行即 `pending` 时异步入队，`deployed`/`failed` 不入队、`failed` 需人工恢复；`cleanup_pending` 表示清理未完成） | owner |
| 查询日志事件 | `GET /api/v1/orgs/{orgId}/log-events` | member |
| 管理访问控制 | `GET/POST/PATCH/DELETE /api/v1/orgs/{orgId}/user-groups`、`/device-groups`、`/access-rules`（v0.9.0；含成员/设备全量替换，语义见 §2.3） | `access.manage`（内置 owner/admin；不可委派） |

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
- **并发登录竞态（v0.8.0 起关闭）**。登录在事务外解析会籍、随后才落会话；若与成员移除重叠，旧实现可能留下“撤销后才创建”的活跃会话。现在所有 compat 消费者（Bearer 中间件与免凭据 heartbeat/sysinfo 的会话解析）都会复核当前 membership，缺少会籍即 401/忽略；membership 查询失败按非成员处理（fail closed）。v0.8.0 起该复核同时要求会籍未停用（`disabled=false`）。
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

### 2.3 访问控制运维（v0.9.0）

**默认状态**：组织创建与存量组织启动收敛会生成内置 `everyone` 用户组与 `everyone → 全部设备` 规则，因此升级后**未停用设备**的访问范围不变；停用设备从 v0.9.0 起不再出现在客户端设备列表（管理面仍可见）。

**收紧步骤**（按顺序，避免中途出现空窗）：

1. 建用户组并加入成员（`PUT .../user-groups/{groupId}/members` 全量替换）。
2. 建设备组并放入设备（`PUT .../device-groups/{deviceGroupId}/devices` 全量替换；设备从原组移入，一设备一组）。
3. 建精确规则 `用户组 → 设备组`（或 `用户组 → 全部设备`）。
4. 验证目标成员的客户端设备列表（`GET /api/peers`）符合预期。
5. 删除 `everyone → 全部设备` 默认规则完成收紧（删除后重启不会复活）。

**生效与不生效**：规则变更只影响**新查询、新签发、新兑换**；已建立的远控连接不中断（面板不在信令链路，D10）。停用的设备与停用会籍立即不可达且优先于规则；停用设备不会出现在客户端设备列表（管理面设备列表仍可见）。owner/admin 不受规则限制（避免把自己锁在门外）。

**票据**：签发按签发人、兑换按兑换人各判一次；收紧后，若**兑换人当前无权访问目标设备**，未兑换的有效旧票据在兑换时返回 `404`（仍有权限的成员与 owner/admin 仍可兑换，停用设备仍为 `409`）。访问拒绝写 `session.ticket.denied`（`reason=access_control`）；停用设备的兑换审计 `reason=device_disabled`。错误 token 在任何设备状态下都是 `409`，不泄露设备状态。访问判定是**准入时**校验，不是原子撤销：规则删除与在途签发/兑换并发时，仍可能有在途请求按旧判定完成（窗口极小，且面板不在信令链路）。

**权限**：`access.manage` 不可委派，仅内置 owner/admin 默认拥有，**自定义角色无法获得**（权限目录禁止委派）。v0.9.0 之前签发的个人 API Token 需要重建后才能在令牌身份下管理访问控制（令牌权限是申请集 ∩ 角色权限集的硬上限）。

**排查**：普通成员客户端设备列表为空 → 检查该成员所在用户组是否被规则覆盖、`everyone → 全部设备` 是否已被删除、设备是否处于停用状态；管理员看不到某设备 → 先查管理面设备列表（全量），规则只影响客户端可见性与票据准入。

### 2.3.1 设备归属运维（v0.10.0）

**归属是什么**：`devices.owner_user_id`，一台设备最多归一名本组织成员。它决定两件事：**归属人本人始终能在客户端看到并连接自己的设备**（无需任何规则，停用设备/停用会籍除外），以及 `用户组 → 用户组` 规则按目标组成员的归属展开设备集合。

**三种归属来源**：
1. **登录自动归属**（默认路径）：设备尚未归属时，首个登录成功的用户成为归属人——前提是本次登录**提交了 `uuid` 且与设备绑定一致**；**空 `uuid` 登录成功但不产生归属**（uuid 是客户端唯一的身份信号，归属不能靠"知道一个 rustdesk id"取得）。**已归属他人的设备不会被登录改写**（管理员改派过的归属保持不动，除非管理员再次改派）。
2. **管理面改派**：`PATCH /api/v1/orgs/{orgId}/devices/{deviceId}`，`{"owner_user_id": <userId>}` 改派、`{"owner_user_id": null}` 清空；目标必须是本组织的有效成员（会籍未停用且角色可解析），否则 404。改派与清空各写一条 `device.assign` 审计（`Detail` 含 `from`/`to`）。
3. **客户端 `--assign`**：`rustdesk --assign --user-name user@example.com --device-name ... --note ...` 按客户端配置的 API 服务器调用 `POST /api/devices/cli`，需要**个人令牌**（`device.write`）。字段白名单外的参数（`--strategy`、`--address-book-*`、`--device-username`）会被 `400` 明确拒绝——这是有意行为，不是兼容性缺陷。

**常见运维与排查**：

| 场景 | 处理 |
|---|---|
| 成员看不到自己的设备 | ① 管理面确认该设备的 `owner_user_id` 是不是本人（登录自动归属只在**设备无归属**且登录**带匹配 `uuid`** 时生效，设备可能已被改派给他人，或该成员登录时客户端没带 uuid）；② 设备是否被停用；③ 该成员的会籍是否被停用；④ 改派：`PATCH` 该设备 `owner_user_id` 为本人 |
| 成员换机后仍看到旧设备 | 归属不变更：清空 `{"owner_user_id": null}` 或改派给新使用者；`rebind` 只换绑定不换归属 |
| 一台共用机反复被不同人登录 | 归属保持第一次登录的用户（不会被后来者抢走）；需要改派时由管理员显式 `PATCH`，或先清空再由登录自动归属 |
| 成员离职后设备归属仍在 | 归属**故意保留**（历史可追溯，管理面 `owner_email` 继续显示）：离职成员会籍停用后本人不可见，且其设备也不会通过 `用户组 → 用户组` 规则对他人可见；要交给接任者请显式改派 |
| `--assign` 返回 404 | 设备/用户/组不在该令牌绑定的组织内，或名称/邮箱不匹配（组名大小写不敏感，邮箱精确匹配）；跨组织操作在契约上不存在 |
| 改派后旧归属人仍在会话中 | 归属变更**不撤销已建立的连接**（与规则变更一致）；需要立即收权请停用设备（`disabled`，会撤销活跃 compat 会话） |

**删除用户组时**：以该组为源/目标的规则与以该组为主体的地址簿授权同事务级联删除（响应报 `removed_rules` / `removed_grants`）；**设备归属不受影响**（归属是用户维度，删组不清归属）。

### 2.4 验证码运维（v0.10.0）

**启用前置**：选定 `captcha.provider`（默认 `altcha`），注入对应秘密（`PANEL_CAPTCHA_ALTCHA_KEY` / `PANEL_CAPTCHA_GEETEST_KEY` / `PANEL_CAPTCHA_CAP_SECRET`），并把 `captcha.enabled=true`。启用后 `POST /api/v1/auth/login`、`POST /api/v1/auth/2fa/verify`、`POST /api/v1/invitations/accept` 全部要求 `GET /api/v1/auth/captcha` 发放的挑战；compat `POST /api/login`（原生客户端，**不带 `/api/v1` 前缀**）不受影响。

**提供商与运维归属**：
- `altcha`：自带 proof-of-work，无外部依赖；`maxNumber` 越高越难爆破、客户端越费 CPU（默认 10 万次哈希，通常毫秒级）。
- `geetest`：需要极验账号与 `captchaId`；依赖境外服务，部署前确认可达。
- `cap`：需要单独部署并升级 Cap Standalone，面板只调用其 `/siteverify`；Cap 不可用时按 `failMode` 处理。

**失败语义**：缺 `captcha` → `400 captcha_required`；挑战过期/已用/答案错/**提供商判定失败** → `400 captcha_invalid`（不区分账号是否存在）；提供商网络错误/超时/5xx/响应无可判定内容，且 `failMode=closed` → `503 captcha_unavailable`。**判定与故障按响应内容区分而不是状态码**：例如 Cap 对不存在或已消耗的 token 返回 `404 {"success":false}`，这是判定（400），不是故障。`failMode=open` 只放行“提供商不可达”，提供商判定失败永远不放行，且每次放行都打 error 日志——仅用于临时运维窗口，用完立即改回 `closed`。

**状态与多副本**：挑战本身无状态，但「已消耗凭据」与登录限流都在进程内存（Altcha 5 分钟、GeeTest/Cap 10 分钟去重窗口）。两者约束不同：**消费键与 IP 无关**，按 IP 粘性路由**不能**保证跨实例单次消费（换源 IP 的同一凭据可能命中未记录它的实例），需要该保证时必须单副本或共享消费存储；登录限流按 IP 计费，粘性路由有效。进程重启同样会清空消费表。一个凭据只有一次尝试机会；错误答案也会消耗它。已通过校验的凭据在 TTL 内不会被容量淘汰——内存表满时优先淘汰未通过校验的占位，全是已通过条目时拒绝新挑战，而不是把已用凭据放回可用；校验进行中若占位被淘汰，成功结果仍会补记为**已通过**状态，且过期句柄不会覆盖或删除同 key 的新占位。

**failMode 的边界**：`open` 只在**校验阶段**遇到提供商网络故障时放行；如果提供商连**挑战都发不出来**（`GET /api/v1/auth/captcha` 503），三个入口仍会被挡住——此时应临时停用验证码（`captcha.enabled=false`）或切换提供商，而不是长期依赖 `open`。

**停用**：把 `captcha.enabled=false` 重启即可恢复原登录流程（无需数据库变更）；停用后 `GET /api/v1/auth/captcha` 返回 `enabled=false`，客户端可跳过验证码。

**排查**：全员卡在登录 → 先看 `GET /api/v1/auth/captcha` 是否 5xx（提供商不可达或配置错误），再看 `captcha` 配置与秘密是否注入；个别用户反复 `captcha_invalid` → 检查客户端时钟与挑战 TTL；日志出现 `captcha provider unavailable; fail-mode open` → 说明正在放行，立即确认提供商状态并改回 `closed`。

### 2.5 控制角色运维（v0.10.0）

**它管什么、不管什么**：控制角色只描述「连上之后能做什么」（键盘鼠标、剪贴板、文件、音频、摄像头、终端、隧道、重启、录屏、阻断输入、远程改配置、隐私模式、USB、远程打印，共 14 项，每项三态）。它**不决定能否连接**（那是访问控制 §2.3），也**不改被控端设置**（那是 Strategy，波次 4）。

**最重要的运维事实：原生客户端会话目前不受它约束。** 权限位图由 hbbs 在信令消息里注入，面板不在信令链路、provision 起的是 stock rustdesk-server（设计 D10）。当前版本你能得到的是：管理面可配、票据与服务端快照可查（`tickets.control_permissions` / `sessions.control_permissions`）、审计可追。**不要把它当作已生效的强制限制向业务方承诺。**

- 每个成员最多一个角色；未分配即回到组织内置 `default`（每组织一行，不可删、不可改名、权限可改）。
- `control_role.manage` 授予 owner 与 admin（不可委派给自定义角色）。删除自定义角色会把持有者的分配清空（回到 default），同事务写审计。
- 排障：票据上的 `control_permissions` 与预期不符 → 先看签发时刻该成员的分配（角色后来被改不会回溯旧票据），再看 `control_role.assign` 审计；`control_permissions=0` 表示「没有任何显式 enable」，不是「未计算」。

### 2.6 compat 登录 2FA 运维（v0.10.0）

- 开启方式与面板一致：成员在面板里完成 TOTP 启用（`/auth/2fa/enable`）；开启后**原生客户端登录也必须过第二步**。
- 现象：客户端先弹「2FA code」输入框（服务端返回 `tfa_type=totp`），输入 6 位码后才进入；密码错误/验证码错误都计入同一账号锁定计数（与面板共用）。
- **同码两次登录会失败**：面板与客户端共用 `user_totps.last_step`，同一 30 秒窗口内先用面板登录、再用同一个码登录客户端会被判重放。等下一窗口即可，不是故障。
- 用户丢失设备：管理员走 `POST /orgs/{orgId}/members/{userId}/2fa/reset`（与面板 2FA 同一入口，见 §3.1 的跨组织边界）。
- 挑战记录存 `compat_login_challenges`（TTL 5 分钟、单次消费、失败 5 次作废）；表无需手工清理，过期行不影响登录，可按需在维护窗口删除。
- 注意：**未配置 `auth.secret` 时 2FA 相关操作 fail closed**；轮换 `auth.secret` 会让既有 TOTP 秘密无法解密，必须先重置用户的 2FA。


### 2.7 客户端策略与心跳断连运维（v0.10.0）

**它管什么、不管什么**：策略改的是**被控端客户端的本地选项**（音频、剪贴板、文件传输、摄像头、终端、隧道、录屏、隐私模式等 20 项），由客户端每 30 秒拉取一次心跳时下发。它**不决定谁能连接**（访问控制 §2.3），也**不决定连上后能做什么**（控制角色 §2.5）。三者的排障入口不同，别混。

- 生效链路：管理面改 `config_options` → `version` +1 → 客户端下次心跳（≤30 秒）带着旧 `modified_at` 来 → 响应回 `strategy` + `modified_at` → 客户端写入本地配置并把该键标记为「固定」（用户在本机改不回来）。**没有推送**，客户端离线就一直不生效。
- 三层优先级固定：设备 > 设备组 > 成员（设备归属人的会籍）。排障顺序：先看 `GET devices` 的 `strategy_id`，再看 `GET device-groups`，最后看 `GET members`。停用的策略**不会**回落——这是有意设计，否则「临时关掉」会变成「换成另一套」。
- 常见误解：客户端心跳里回传了版本号但没收到 `strategy` 是正常的（说明它已是最新）；反过来，服务端**绝不会**只发版本号不发选项——那会让客户端永久停在旧配置。
- `config_options` 只接受 20 个白名单键。收到 `400 option key is not allowed: xxx` 说明键名拼错、大小写不对、或带空格；网络类键（`api-server`、`relay-server`、`key` 等）**永远**拒绝：客户端会照单全收，放行等于设备接管。
- 空值（`""`）表示「清除该键、回到客户端内置默认」，不是「关闭」。要关闭请用 `N`。
- **从 `config_options` 里删掉一个键等于「清除」**：服务端会把它以空值继续随下发回传（记在策略的 `cleared_keys` 里），确保客户端撤掉旧值；重新加回该键则自动移出。不要指望「删掉就没人管了」——那样客户端会一直保留旧值。
- **改派策略看版本号**：`version` 是组织内单调序列，两个策略永远不会同号。若在抓包里看到客户端回传的 `modified_at` 与当前策略 `version` 相同，说明它已经是最新；不同就一定会下发一次。

- **跨组织身份歧义（v0.10.0 安全边界）**：若同一 `(rustdesk id, uuid)` 被注册进多个组织（影子注册），该设备的心跳**收不到策略也不会消费断连**（服务端日志记 `heartbeat identity is ambiguous`）。这是有意的 fail closed：防止把 A 组织的策略推给 B 组织控制的客户端。**恢复需要两步，只删设备行不够**：心跳会话按全平台「最新」解析，若最新会话属于影子设备所在的组织，`touchDevice` 在该组织找不到设备行后直接结束心跳——此时必须 ① 撤销影子组织的 compat 会话（需要相应管理权限），**或** ② 让合法客户端重新登录（产生更新的会话重新赢得解析），然后确认心跳恢复。合法迁移设备（换组织）时，先删旧组织的设备行即可避免窗口。

**断连（`POST .../devices/{deviceId}/disconnect`）**

- 面板不在信令链路，**不能**直接掐断连接。它只记录请求，由客户端下次心跳按它自己上报的连接编号执行。
- 现象：请求成功（201）后连接最多再存活 30 秒左右；客户端当时没有活跃连接时请求保持 `pending`，等它下次带连接上报才生效，15 分钟后作废（`expired`）。
- 同一设备已有 pending 请求时返回 409——先看是不是上一次还没被消费（客户端离线），而不是重复点击。
- 审计：`device.disconnect.request`（谁、为什么）、`device.disconnect.fulfilled`（断了几个）、`device.disconnect.expired`（系统动作，`ActorUserID=0`）。被拒绝的 409 只会留下一条 HTTP 回退审计（`POST .../disconnect` + status 409），这是预期。
- `strategy_name` 可用：客户端 `rustdesk --assign strategy_name=<名字>` 现在会按本组织策略名分配（大小写不敏感，未知名字 404 且整单失败）。


---

## 3. 审计日志

- 写入路径：管理 API 由中间件回退记录（一次可审计请求恰好一条）；地址簿等领域写由 `TxRecorder` 在**实体事务内**原子记录（#26）；compat 写路径的归因由中间件回退读取 `compat.*` 上下文（#37，v0.3.0 恢复）
- **完整性**：每条审计行带 per-org 连续序列号，序列断裂通常表示行被删除或篡改。**保留期清理是唯一的预期缺口**：`audit.retention.purge` 只删除已成功归档且早于保留阈值的行，因此巡检应只把**保留窗口内（未归档范围）**的非预期缺口当作篡改信号，并用归档文件（JSONL + `.sha256`）与 `audit.retention.archive` / `audit.retention.purge` 审计交叉核对被清理的区间。
- 无租户请求（login、healthz）不产生持久审计行（`GormAuditor` 对 org 0 直接丢弃，有意 fail-closed）
- 遗留：compat 写路径的**事务级**审计（与业务写同事务）尚未实现，当前为请求级归因
- **领域审计动作**（`TxRecorder` 在实体事务内记录）：`session.ticket.issue`（票据签发）、`session.ticket.redeem`（票据兑换）、`session.ticket.denied`（策略拒绝）、`session.approval.request`（新建审批请求；复用不重复记）、`session.approval.decide`（approve/deny 决策）、**`device.binding.reset`（v0.5.0 重置设备绑定；含 actor、`rustdesk_id`、reason、had_binding）**、`organization.member.remove` / `organization.member.role`（v0.6.0 成员离场；含目标用户、角色变化与撤销会话数）、**v0.8.0 新增：`organization.member.disable` / `organization.member.enable`（成员停用/恢复，含撤销会话数）、`device.disable` / `device.enable`（设备停用/恢复，含撤销会话数）、`role.create` / `role.update` / `role.delete`、`token.create` / `token.revoke`（个人令牌，明文不入审计）、`user.2fa.reset`（管理员重置成员 2FA）、`organization.audit_retention.set`、`audit.retention.archive` / `audit.retention.purge`（系统动作，actor 0）**。地址簿授权与回收站动作仍由请求级中间件回退归因（与 compat 写路径同一机制）。会话治理与设备列表的**轮询读不产生审计**（读静默），单个详情读会记录；provision 供应与保留期清扫等基础设施动作的审计见 provision 相关节（#46）

### 3.1 审计保留期与本地归档（v0.8.0）

- **按组织配置**：`GET/PUT /api/v1/orgs/{orgId}/audit-retention`（仅 owner）。`audit_retention_days=0` 永久保留；`1..3650` 为正的保留窗口；`days` 字段必填（缺失返回 400，避免误把空请求当成"永久保留"）。设置动作写 `organization.audit_retention.set` 审计。
- **先归档、校验、后删除**：每小时后台任务对每个保留期 > 0 的组织，把 `created_at` 早于阈值的行写成 JSONL（每行一条），附同名 `.sha256`；**重新读取校验行数与摘要一致后**才按 id 精确删除。归档或校验失败时**该批不删除任何行**（fail closed），此前已成功的批次保持已删除、不会被回滚，下个周期从剩余行继续。**按批处理**：每批最多 1000 行，逐批归档/校验/删除，直到该组织剩余不足一批——首次开启或长期停摆造成的积压不会一次性载入内存，也不会撞上数据库的占位符上限。归档数据文件与校验文件均在删除前 `fsync`；重命名在 Windows 使用 `MOVEFILE_WRITE_THROUGH`、在其他平台 rename 后 `fsync`；每次运行都会无条件重同步归档目录的整条父链（不依赖本次是否新建，覆盖上次同步失败后的重试），任一同步失败即保留该批数据库行。同步链**跳过文件系统根目录**：以写权限打开卷根通常被服务账号的 ACL 拒绝，强行同步会让保留期任务整轮卡死；归档根直接位于卷根时，该目录条目的持久化交给操作系统。
- **归档位置**：`<audit.archiveDir>/org-<orgId>/audit-<minId>.jsonl`（先写 `.tmp` 再原子改名；文件名只由批次最小 id 决定，事务失败后的重试会覆盖同一路径，即使期间有新行过期也不堆积孤立归档）。归档文件不经 API 暴露；**运维备份必须覆盖该目录**，否则删除后的历史只存在于备份之外。
- **系统动作也审计**：归档写 `audit.retention.archive`（`Detail` 含 rows/path/sha256/threshold）、清理写 `audit.retention.purge`；actor 为 0（系统）。两条审计与删除在同一事务提交；无事务审计器时整轮拒绝删除。
- **回收站（地址簿 v0.8.0）**：删除的 peer 软删除保留 30 天，每小时清扫永久删除过期行；恢复会 bump revision，永久删除不动 revision 与 live 内容。
- **个人令牌（v0.8.0）**：只在组织路径生效；有效权限 = 申请集 ∩ 当前角色权限集，每请求实时重算。列表只显示 `token_prefix`，明文只在创建响应出现一次；遗失令牌请直接撤销后重建。**令牌权限是硬上限**：地址簿写入即使由所有权或 full 授权放行，仍要求令牌含 `addressbook.write`，否则 403。
- **管理面 2FA（v0.8.0）**：启用后用户登录需要第二步（`/auth/2fa/verify`，与登录共用两轨限流）。用户丢失设备与恢复码时，由 owner/admin 用 `POST /orgs/{orgId}/members/{userId}/2fa/reset` 重置（写 `user.2fa.reset` 审计）。**边界**：2FA 是账号级而非组织级——管理员不能重置自己（409，自服务走 `/auth/2fa/disable`）；目标在本组织是 owner 时只有 owner（`org.admin`）能重置；目标只要**在本组织之外还存在任何会籍**（无论角色、含已停用）就一律拒绝（403）——账号级因素同时保护其在其他组织的登录，清除它会让任一组织的管理员越权削弱别租户；这类跨组织用户的账号恢复只能走平台级运维（系统外）。TOTP 密钥以 `auth.secret` 派生的密钥加密存储，**未配置 `auth.secret` 时 2FA 操作 fail closed**（500）；**轮换 `auth.secret` 会让既有 2FA 配置无法解密**，须先重置相关用户 2FA 再轮换。**启用流程原子化**：已启用的配置不会被再次 setup 覆盖（行锁 + `enabled_at IS NULL` 条件写），Enable 只激活它校验过的那个待启用秘密——并发的 setup 不能把已激活账号"降级"回待启用状态。

### 3.2 客户端连接 / 文件传输日志（v0.10.0）

- 来源：原生客户端上报 `POST /api/audit/{conn,file,alarm}`（无 Authorization，靠 `(id, uuid)` 与设备绑定比对；见 API 规范 §4.5）。**与 `sessions` 是两套记录**：`sessions` 是面板记账，这里是客户端侧证据。
- 查询：`connection-logs` / `file-logs`（`audit.read` + `audit_scope`）。`individual` 只能看自己拥有设备（`owner_user_id`）的记录；想看全组织需要 `global` 审计范围。
- 导出上限 1000 行，超出报 400 要求收窄；导出动作本身写 `connection_log.export` / `file_log.export` 审计。
- 去重：客户端重试按 `nonce` 幂等 5 分钟；`audit_nonces` 由每 10 分钟的 worker 清理，正常运维无需干预。
- 保留期：跟随组织 `audit_retention_days`（0 = 永久），`client-log-retention` 每小时删除过期行。**没有归档**：与审计日志不同，删了就没了；需要长期留存的证据请自行导出 CSV 到外部存储。
- 可信度：知道 `(id, uuid)` 的人可以伪造上报，与免凭据心跳同一信任级。**不要把这两张表当作不可抵赖证据**；需要强证据时以 `sessions` + hbbs 日志采集交叉验证。
- 常见现象：`close` 先于 `new` 到达会留下一条 `status=closed`、`started_at=ended_at` 的孤儿行（设计如此，用于保留证据）；备注只写进该会话最近一条 open 行，同一设备并发会话时可能落到相邻行。


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
- **开关 API（v0.7.0，仅 owner）**：`GET/PUT /api/v1/orgs/{orgId}/provisioning`。关闭（`enabled=false`）会同步删除容器、删除 `ServerGroup` 行、置 `provisioning_disabled`，并在同一事务写 `organization.provisioning.update` 审计（`Detail` 含 `removed_deployment` 与端口）；容器删除失败则请求 500、行标 `failed`、开关不变。开启只清除标记；**仅在无部署行（`pending`）时异步入队**，已有 `deployed` 不入队、`failed` 需人工恢复；队列满由 reconciler 兜底。**下次部署会重新生成服务端密钥对**（`dataDir/org-<orgId>/` 中的数据保留，但密钥文件被覆盖，客户端需重新配对）。重复关闭会清理并发失序遗留的部署行（自愈）
- **在途部署的关闭（deferred cleanup）**：若关闭时行状态为 `provisioning` 且未超过 10 分钟宽限，接口**不删除该行**（审计 `Detail.deferred_cleanup=true`、`state=provisioning`），保留为容器清理锚点；在途部署在持久化时发现开关已关会自行回滚。若回滚删除失败，行会保留为 `failed`，重复关闭会**立即**重试清理；若进程在部署中途中断，行保持 `provisioning`，重复关闭需在该行超过 10 分钟宽限后才会清理。这样不会出现“容器仍在运行但数据库无行可追踪”的状态
- **回滚归属校验**：失败部署在删除容器前会核对当前 `ServerGroup` 行的 id；若组织已被关闭并重新开启、已存在更新的部署行，旧尝试**不会**删除同名容器（容器名按组织复用，无法凭名字区分代际）
- 供应队列：`provision.workers` 并发。部署失败后会执行清理：**清理成功 → 删除 `ServerGroup` 行并释放端口；清理失败 → 行保留为 `failed` 状态**。保留的行会被 `PendingOrgIDs` 排除，对账 reconciler（2 分钟周期）**不会**重新入队——清理失败的部署必须人工处理（残留容器、行、端口）
- **启动端口探测**：启动日志 `provision port range is free` 表示范围内（已预留块除外）没有外部占用；`provision port range has externally occupied ports` 会列出 `端口/协议`，表示面板外进程占用了可分配端口——调整 `provision.portStart/portEnd` 或停止占用进程。探测绑定本机 IPv4 通配地址、只告警不阻断启动；**IPv6-only 监听不在探测范围**；`DOCKER_HOST` 指向远端时本机探测不适用
- **部署前预检**：每次 provision 在 `docker run` 前检查本块 5 个 TCP 端口 + 主端口 UDP；冲突时**释放该块并在本次尝试中跳过**，继续尝试后续可用块（默认端口池有 200 块）。**只有当范围内每一块都因宿主端口冲突被跳过**时才返回 `host port already in use: <port>/<协议>`（不产生失败行）；若耗尽同时包含数据库已分配的块，则保留 `no free hbbs/hbbr port pair in the configured range`，避免把「端口池用完」误报成宿主占用。启动告警给出根因。若**释放**冲突块本身失败（数据库故障），该行会保留为 `failed` 并同样返回错误——这是人工恢复状态，需按上条清理后再重试
- ⚠️ **端口规划前提**：`PortPool` 只按 DB `server_groups` 判重，不感知面板外占用；预检只是提前诊断，探测与 `docker run` 之间仍有竞态。规划端口池时确保范围独占；相关可观测/控制缺口跟踪于 [#46](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/46)
- 下线：`Deprovision` 删除容器 → 删行 → `Unwatch` 采集器；失败时行保留（failed 状态），端口继续被占用，且不会由 reconciler 自动重试
- `provision.dataDir/org-<orgId>/` 含容器运行时数据（`dataDir` 可配置，默认根目录为 `./data/servergroups`）：**备份范围必须包含它**。服务端密钥对由 panel 每次部署时生成并覆盖，恢复后客户端需按 `ServerGroup.pub_key` 重新配对

---

## 7. 备份与恢复

| 数据 | 位置 | 频率建议 |
|---|---|---|
| 关系数据（用户/组织/设备/审计/日志事件/供应状态） | `panel.db` 或外部 DB | 每日；审计行是安全证据，保留期越长越好 |
| 各组织 hbbs/hbbr 密钥与数据 | `provision.dataDir`（默认 `./data/servergroups`，组织子目录为 `org-<orgId>/`） | 每日（与 DB 同步点） |
| 审计归档文件（已清理行的唯一副本） | `audit.archiveDir`（默认 `./data/audit-archive`，组织子目录为 `org-<orgId>/`） | 每日（与 DB 同步点；保留期清理会删除 DB 行） |

恢复：恢复 DB + 数据目录 → **恢复对应的 Docker 容器状态**（reconciler 会跳过已有 `ServerGroup` 行的组织，不会重建缺失的容器）——容器状态不可恢复时，须对每个已恢复的组织执行并验证容器重建 → 启动 panel → AutoMigrate 幂等。

**审计完整性巡检**：按组织检查 audit 序列号连续性。**保留期清理会产生预期断号**——先排除已成功归档并由 `audit.retention.purge` 清理的区间（用归档文件 JSONL + `.sha256` 与 `audit.retention.archive` / `audit.retention.purge` 审计交叉核对），只对**保留窗口内（未归档范围）**的非预期断号按"行被删/篡改"告警（见 §3）。

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
| 审计序列断号 | 先确认是否落在已归档清理区间（`audit.retention.archive`/`audit.retention.purge` + 归档 JSONL/`.sha256` 交叉核对，§3）；保留窗口内的非预期断号立即排查，确认 DB 访问权限是否受控（应用账号以外的写入途径、是否有直连改表） |
| 普通成员客户端设备列表为空 | 访问控制（§2.3）：成员所在用户组是否有规则覆盖、`everyone → 全部设备` 是否已删除、设备是否停用；票据签发/兑换被拒 `404` 同因 |
| 成员看不到**自己的**设备 | 设备归属（§2.3.1）：`owner_user_id` 是否指向本人（登录自动归属只在设备无归属时生效，可能已被改派）、设备是否停用、该成员会籍是否停用；改派用管理面 `PATCH` |
| 管理面 `POST /api/v1/auth/login` / `POST /api/v1/auth/2fa/verify` / `POST /api/v1/invitations/accept` 报 400 `captcha_required`/`captcha_invalid` | 验证码（§2.4）：客户端需先 `GET /api/v1/auth/captcha`；挑战过期/已用/答案错都归为 invalid，重新取挑战再试。compat `POST /api/login` 不接验证码，无需取挑战 |
| 上述三个管理面入口报 503 `captcha_unavailable` | 提供商不可达且 `failMode=closed`（§2.4）：检查网络/提供商状态/秘密配置；确认后可临时 `open` 或停用验证码 |
| 策略改了但客户端没变 | 策略靠心跳拉取（§2.7）：确认客户端在线（`last_seen_at`）、分配落在正确层级（设备 > 组 > 成员）、策略 `enabled=true`。离线设备要等它上线后第一个心跳 |
| 客户端心跳回传版本号但没收到 `strategy` | 正常：说明 `modified_at` 与 `strategies.version` 相同，服务端不重复下发（§2.7） |
| 创建策略报 `option key is not allowed` | 键名不在 20 个白名单内（拼写/大小写/空格错，或用了 `api-server` 一类网络键）——见 API 规范 §3.14 的键表 |
| 断连请求返回 409 | 该设备已有 pending 请求（§2.7）：多半是客户端离线没消费，等它上线或等 15 分钟过期 |
| 断连后连接还在 | 面板不直接断连，最长等一个心跳周期（30 秒）+ 客户端处理；若 15 分钟后仍无 `fulfilled` 记录，说明客户端期间没有上报活跃连接 |
| 策略/断连突然对某设备失效，日志有 `identity is ambiguous` | 同一 `(rustdesk id, uuid)` 被注册进多个组织（§2.7 安全边界）。只删设备行**不够**——心跳会话按全平台最新解析，影子会话会让 `touchDevice` 直接结束心跳。恢复两步：① 撤销影子组织的 compat 会话（需相应权限），**或** ② 合法客户端重新登录产生更新会话；之后确认心跳恢复（§2.7） |
| 断连显示 `fulfilled` 但连接仍在 | 心跳端点无凭据（设计 C16）：知道 `(id, uuid)` 的人可以伪造一次带 `conns` 的心跳把请求消费掉。响应对攻击者无用（断的是他自己的连接），但管理员的请求会被作废。需要强断连时以 `sessions` 与 hbbs 日志交叉验证 |
| 客户端登录弹出「2FA code」且输入后仍 401 | compat 2FA（§2.6）：码已过期/同窗口被面板用过（防重放）/挑战过期超 5 分钟；重新登录取新挑战。确认账号确实启用了 TOTP |
| 票据/会话的 `control_permissions` 与预期不符 | 控制角色（§2.5）：快照取签发时刻、不回溯；`0` 表示无显式 enable。**原生客户端不受其约束** |
| 连接/文件日志为空但客户端确实在跑 | 客户端需已登录（上报依赖登录态）且设备 `bound_uuid` 与应用一致；`uuid` 不符会被 403 丢弃（§3.2） |
| 导出连接/文件日志报 400 | 结果超过 1000 行（§3.2）：加 `deviceId` / `from` / `to` 收窄 |
| 全员登录被限流 429 | 挑战端点与登录各有一个独立的 5/min/IP 桶：排查是否有客户端在循环刷 `/api/v1/auth/captcha`；正常用户刷新一两次不会触发 |

## 10. Passkey 运维（v0.11.0）

**管理员重置成员凭据**：`POST /api/v1/orgs/{orgId}/members/{userId}/passkeys/reset`
（`member.manage`）。守卫与 2FA 重置一致：不能重置自己；重置 owner 需要
`org.admin`；目标同属其他组织时拒绝。审计 `user.passkey.reset` 记录删除条数。
**目标没有密码时返回 409**：清空凭据会让账户彻底无法登录。

**transports 列类型变更（v0.11.0，text → varchar(255)）**：MySQL 8/9 拒绝
TEXT 列带默认值（error 1101），旧列定义在 MySQL 上无法完成启动迁移——本版本
把列改为 `varchar(255)`。注册入口同时按集合语义去重 transports 并限制编码后
长度 ≤255 字节。

**PG 升级必须在启动新版本之前清理超长行**：gorm 的 postgres 驱动对
`ALTER ... TYPE varchar(255)` 使用显式转换 `USING ...::varchar(255)`，该转换
对超长值是**静默截断**而非报错——截断后的 JSON 不合法，凭据将无法使用。
升级步骤：① 停旧版本；② 检查
`SELECT id FROM user_passkeys WHERE char_length(transports) > 255;`，
有行则先删除或手工修复；③ 再启动新版本执行 AutoMigrate。正常认证器的
transports 远小于 255 字节，此检查绝大多数部署为空。MySQL 上不存在此类
存量行（旧表建不出来）。

**无密码账户丢失全部 passkey（唯一需要改库的场景）**：

1. 先确认没有别的出路：该账户是否绑定了另一个 passkey；再看
   `GET /auth/identity` 是否有可用的外部身份绑定——有则先走 SSO/目录登录，
   重新绑定 passkey 即可，无需改库。都没有才继续。
2. 生成一个新密码的哈希（与面板存储格式一致）：

   ```bash
   read -rs PW && printf '%s\n' "$PW" | go run ./tools/pwhash && unset PW
   ```

   `read -rs` 不回显、也不进 shell history；口令只经 stdin 传给工具，不出现在
   进程列表里。

3. 写入数据库（**先备份**，并把该值只交给账户本人）：

   ```sql
   UPDATE users SET password_hash = '<上一步输出>' WHERE id = <userId>;
   ```

4. 用户用该密码登录后，应立即在设置里重新绑定 passkey，并走
   `POST /auth/password/remove` 恢复 passkey-only（或改密后保留密码）。
5. 若不想给临时密码，也可以只删除该用户的 `user_passkeys` 行并保留 `users`
   行——但那不会让账户变得可登录，仍需第 2–3 步。

**`clone_warning` 处置**：`GET /auth/passkeys` 里 `clone_warning=true` 表示该
凭据曾报告签名计数器回退（可能被复制）。处理：让用户删除该凭据并重新绑定；
不要直接改库清标志。计数器恒为 0 的平台认证器不会触发该标记。

**清扫任务**：`webauthn-ceremony-sweep` 每 10 分钟删除过期 ceremony。过期的
ceremony 本来就无法被消费，任务只回收空间；它失败会按 worker 约定写审计。

**自助事件在哪看**：passkey 注册/删除/登录、删除/恢复密码只写结构化日志
（`user_id`、`passkey_id`、`mode`），**不进 `audit_logs`**——它们没有租户
归属。管理员重置是唯一进入审计表的 passkey 事件。

## 11. 外部身份运维（v0.11.0，OIDC）

**绑定冲突处置**：`GET /auth/identity` 里 `conflict_at` 非空，或日志出现
`oidc callback rejected`（`error_code=identity_conflict`），表示某 subject 的
绑定与该账户邮箱不再对应（IdP 侧邮箱被回收/改名）。处置：管理员调用
`POST /orgs/{orgId}/members/{userId}/identity/reset` 清空绑定；用户重新走一次
SSO 即按当前邮箱重绑。reset 写审计 `user.identity.reset`。

**换 IdP（issuer 变化）**：旧行不命中也不删除；启动日志出现
`identities are bound to a different oidc issuer`（含条数）。批量步骤：

1. 通知用户 SSO 需要重新绑定一次；
2. 对每个受影响账户调用管理员 reset（脚本按 `SELECT user_id FROM
   user_identities WHERE provider='oidc' AND issuer <> '<新 issuer>'` 圈出名单）；
3. 保留旧行直到新绑定完成——它们是回滚路径，**不要手工 DELETE**。

**discovery/JWKS 故障排查**：SSO 报 503 时按序检查——issuer 拼写（必须与
IdP discovery 返回的完全一致）、`{web.baseURL}` 是否可达、IdP 证书是否过期、
出站网络是否放行。discovery 失败不缓存，修复后无需重启。

**`email_verified` 缺失**：部分自建 IdP 不返回该 claim，绑定会得到
`email_unverified`。在 IdP 侧补 claim；面板侧无开关，这是有意的 fail-closed。

**日志字段**：自服务绑定/登录/解绑只写结构化日志（`user_id`、`provider`、
`identity_id`、`error_code`），不进 `audit_logs`；secret/code/id_token/ticket
原文不出现在任何日志。管理员 reset 是唯一进审计表的外部身份事件。

## 12. LDAP 目录运维（v0.11.0）

**401 与 503 的分流**：401 有两种成因，先看涉及面——个别用户 401 = 无效凭据
（或该用户的 `userFilter` 命中了多条目录条目，面板按 fail-closed 拒绝，日志
`error_code=invalid_credentials` 不可区分是刻意设计）；**所有人** 401 且带
`ErrAmbiguousResult` 症状（`userFilter` 写宽了）= 检查 filter 是否会匹配多个
条目。503「目录服务不可用」= 面板到目录的链路或配置问题——按 `transport`
分情况验证连通性：

```bash
# ldaps（默认端口 636）
ldapsearch -H ldaps://HOST:PORT -x -s base -b ''
# starttls
ldapsearch -H ldap://HOST:PORT -ZZ -x -s base -b ''
# none（仅隔离网络）
ldapsearch -H ldap://HOST:PORT -x -s base -b ''
# 验证服务账号本身可用（替换 bindDN；-W 交互输密码；在上方对应
# transport 的命令中加上 -D/-W，starttls 用 ldap://HOST:PORT -ZZ）
ldapsearch -H ldaps://HOST:PORT -x -D 'BINDDN' -W -s base -b ''
```

再查证书链（LDAPS）、`transport`/`allowInsecure` 组合、服务账号是否被锁。
**绝不能**因为 503 被误报成密码错而让用户反复重试。

**目录改名后重新绑定**：`subject` 是 `usernameAttribute` 的值（L7），目录侧
改了它 = 旧绑定不命中。启动日志出现 `identities are bound to a different
ldap host`（换主机）或用户报 401（改用户名）时：管理员调用
`POST /orgs/{orgId}/members/{userId}/identity/reset` 清空绑定，用户重新登录
一次即按新值绑定。reset 写审计 `user.identity.reset`。

**目录账号复用（用户名重分配）**：LDAP 的 subject 是用户名——目录侧把
`alice` 重新分配给另一个人时，新持有人能通过自己的口令 bind。面板的防线是
**绑定邮箱漂移即冻结**：返回登录发现该 subject 的目录邮箱与绑定时记录的
不一致 → 绑定标记 `conflict_at`，登录返回 409，直到管理员
`identity/reset` 清掉旧绑定后新人重新绑定。注意残余风险：若目录管理员把
用户名**和邮箱一起**让给新人（邮箱不变），面板无法区分——这属于目录侧
账号管理责任，处置同「目录改名后重新绑定」。

**`mail` 属性缺失**：登录返回 403「directory account has no mail attribute」。
处置：在目录侧给该账号补 `mail`（必须与面板账户邮箱一致），无需面板侧操作。

**bind 账号密码轮换**：服务账号密码只在 `PANEL_LDAP_BIND_PASSWORD`。轮换
四步：目录侧设置新密码 → 更新环境变量 → 重启面板 → 删除旧密码。轮换窗口内
登录返回 503（不是 401），不要在窗口内尝试排查用户凭据。

**日志边界**：登录日志只含 `username`、结果与 `error_code`；503 分支额外带
`zap.Error` 的链路原因（go-ldap 的结果码与错误消息，用于区分断连/证书/协议
故障），其中不含任何口令。目录密码、bind 密码不落任何日志或审计。多次 401 会进入与密码登录同一失败窗口
（同 IP + 同用户名），达到阈值后 429。

