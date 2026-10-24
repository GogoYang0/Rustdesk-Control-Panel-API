# 后端 API 规范（Backend API Specification）

> 适用版本：v0.8.0（M4 角色模型与 Server Pro 对齐；已发布基线 v0.4.0）。本文档是对 `openapi.yaml`（契约 v0.8.0）与 compat 层协议的人类可读摘要与语义说明；**字段与请求/响应形状以 `openapi.yaml` 为契约权威**，本文负责解释语义、边界与易错点。
> 本文档随版本演进持续更新——契约变更的 PR 必须同步更新 §3/§4。
> 配套文档：[部署指南](deployment.md) · [运维指南](operations.md)

---

## 1. 两族认证

| | 管理 API（WEB/APP） | compat 层（RustDesk 原生客户端） |
|---|---|---|
| 令牌 | JWT（`/api/v1/auth/login` 签发）+ 刷新令牌（**轮换 + 重放撤销**）；时长默认 `15m`/`168h`，实际值以 `auth.accessTTL`/`auth.refreshTTL` 配置为准 | compat access token（`/api/login` 签发，TTL 默认见 `compat.accessTTL`，以配置为准） |
| 中间件 | 管理 JWT 中间件，写入 `api.*` 上下文 | compat 会话中间件，写入 `compat.*` 上下文（`compat.userID` / `compat.orgID` / `compat.jti`） |
| 审计 | 中间件回退记录（领域写用 `TxRecorder` 同事务） | 同一审计中间件回退读取 compat 键归因（v0.3.0 起） |
| 多组织 | 登录响应仅含 `access_token`、`refresh_token`、`expires_in`，**不含组织列表**；管理请求携带 `orgId` 路径参数 | 账号属多组织时用户名用 `email#orgID` 选择组织，会话固定组织 |
| 传输 | `Authorization: Bearer <token>` | 同左（`authed` 组）；`heartbeat`/`sysinfo` 无凭据 |

两族**互不可换用**：管理令牌打不开 compat 端点，反之亦然（中间件按族校验）。

---

## 2. 通用约定

### 2.1 响应包络

管理 API 统一包络：

```json
{ "code": "ok", "message": "", "data": { ... } }
```

错误：

```json
{ "code": "invalid_request", "message": "human readable", "data": null }
```

`code` 取值（契约枚举）：`ok` `invalid_request` `unauthorized` `not_found` `conflict` `forbidden` `email_not_verified` `rate_limited` `internal` `approval_required`。`unauthorized` 映射 **401**（登录/刷新的凭据拒绝路径）；`internal` 映射 **500**（未预期的服务端错误，不向客户端泄露细节）。

`approval_required` 是唯一**必须携带 `data` 对象**的错误码（`data.approval_id` 指向待审批请求），其余错误码的 `data` 为 `null`。

### 2.2 租户隔离（管理 API）

管理 API 的一切组织内资源都带 `{orgId}` 路径参数；服务端通过 `ScopedByOrg` 强制租户过滤，**组织内**跨租户资源访问返回 `404 not_found`（不泄露存在性）；**调用者不属于该组织**时返回 `403 forbidden`（"不是本组织成员"本身不构成信息泄露，且便于前端区分"没权限"与"资源没了"）。compat 层不带 `{orgId}`：**已认证请求**使用已验证 token 的 `org` claim 作为组织上下文；**无凭据的 heartbeat/sysinfo** 从持久化会话取得 `OrganizationID` 后执行组织范围查询（见 §4）。

fail-closed 的适用范围必须分清（以 `internal/store` 的租户插件注册为准）：

- **ORM 作用域查询**（经 `ScopedByOrg` 包装的 Query/Row/Update/Delete）由租户插件注入条件；`orgID=0` 时注入的条件匹配不到任何行，即 fail-closed。
- **`Create` 不经过租户插件回调**：创建必须显式设置 `organization_id` 并校验 `orgID`；`orgID=0` 没有插件提供的 fail-closed 保证。
- **`Raw()` / `Exec()` 不经过租户插件**，不会被自动注入租户条件——未显式写入租户过滤的原始 SQL **不具备** fail-closed 保证，也不得用于访问租户数据（store 层硬性约定）。

### 2.3 错误码 → HTTP 映射

| code | HTTP | 典型场景 |
|---|---|---|
| `invalid_request` | 400 | 载荷校验失败、契约上限越界 |
| `email_not_verified` | 403 | 未验证邮箱登录 |
| `forbidden` | 403 | 角色不足、设备已绑定（compat） |
| `not_found` | 404 | 跨组织访问 / 不存在的资源 |
| `conflict` | 409 | 管理 API 资源冲突；compat 地址簿的 hash 冲突使用 compat 专用错误 `ab_conflict`（见 §4.3），不走此包络 |
| `approval_required` | 409 | 票据签发被策略的事前审批要求阻断（`data.approval_id` 指向待审批请求，见 §3.6） |
| `unauthorized` | 401 | 登录/刷新的凭据拒绝 |
| `rate_limited` | 429 | 登录锁定（LoginGuard） |
| `internal` | 500 | 未预期的服务端错误（不向客户端泄露细节） |

### 2.4 分页

分页参数**按端点各自定义**，不要混用：

- **日志事件**（`GET .../log-events`）：`since` + `limit`（`limit` 取值 1–200，默认 50），筛选参数为 `since`、`deviceId`、`level`（`source` 是返回字段，不是筛选参数）
- **compat 地址簿 peers**（`POST /api/ab/peers`，仅个人簿）：query 参数 `ab`（地址簿 guid，必填）、`current`（页码，默认 1，最小 1）、`pageSize`（默认 100，最小 1，超过 500 截断为 500）
- **会话 / 审批 / 告警**（§3.6）：`page`（默认 1，最小 1）+ `pageSize`（默认 50，1–200）；响应形状为 `data.items/page/page_size/total`（这三张表无限增长，需要总数支撑翻页）
- 设备（§3.3）：`page`（默认 1，最小 1）+ `pageSize`（默认 50，1–200），响应形状 `data.items/page/page_size/total`（与会话/审批/告警一致）

---

## 3. 管理 API（WEB/APP）

### 3.1 认证

| 端点 | 说明 |
|---|---|
| `POST /api/v1/auth/login` | 邮箱+密码；未验证邮箱返回 `email_not_verified`；连续失败触发 LoginGuard 锁定（429，键含用户名规范化） |
| `POST /api/v1/auth/refresh` | 刷新令牌轮换：旧 refresh 即刻撤销，重放旧令牌会**整族撤销**（重放检测） |
| `POST /api/v1/auth/verify-email` | 邮箱验证（一次性令牌，邮件下发） |
| `POST /api/v1/auth/resend-verification` | 重发验证邮件（结果不明时令牌保留，可重试） |
| `GET /api/v1/auth/tokens` | 列出本人在某组织的个人令牌（v0.8.0，`organizationId` 查询参数必填；不返回明文） |
| `POST /api/v1/auth/tokens` | 创建个人令牌（v0.8.0，绑定单个组织；明文只出现一次；权限不得超过当前角色） |
| `DELETE /api/v1/auth/tokens/{tokenId}` | 撤销本人的令牌（v0.8.0，幂等；他人令牌 404） |
| `POST /api/v1/auth/2fa/setup` | 初始化 TOTP（v0.8.0）：返回待启用的 `secret` 与 `otpauth://` URI；已启用时 409 |
| `POST /api/v1/auth/2fa/enable` | 校验首个 TOTP 码后启用（v0.8.0） |
| `POST /api/v1/auth/2fa/disable` | 关闭 2FA（v0.8.0，需当前密码 + TOTP/恢复码） |
| `POST /api/v1/auth/2fa/recovery-codes` | 重新生成 10 个一次性恢复码（v0.8.0，需当前密码 + TOTP/恢复码） |
| `POST /api/v1/auth/2fa/verify` | 登录第二步（v0.8.0，公开）：`{challenge_token, code}` → 令牌对 |
| `POST /api/v1/orgs/{orgId}/members/{userId}/2fa/reset` | 管理员重置成员 2FA（v0.8.0，`member.manage`，写 `user.2fa.reset` 审计） |

> **v0.8.0 个人访问令牌**：明文格式 `rdt_<32B base64url>`，服务端只存 SHA-256，列表只回 `token_prefix`（前 8 字符）。
> 令牌只在**组织路径**上生效（路径 `orgId` 必须等于签发组织）；`/auth/tokens` 自身、`/orgs`、`/permissions` 等非组织端点仍只接受 JWT。
> **有效权限 = 令牌申请集 ∩ 用户当前角色权限集**，每个请求实时重算：角色降级或会籍停用会立即收窄/失效，令牌不会绕过这些变更。
> 每人每组织最多 20 个活跃令牌，有效期 1..365 天（默认 90）。令牌与 refresh/JWT 是不同凭证族，互不替代。

> **v0.8.0 管理面 2FA（TOTP）**：启用后 `/auth/login` 密码正确也**不直接发令牌**，而是返回 `401 + code=two_factor_required`，`data.challenge_token` 为 5 分钟有效的挑战令牌；客户端用它调用公开的 `/auth/2fa/verify`（TOTP 码或一次性恢复码）换取令牌对。挑战令牌本身可重复提交（不是一次性凭据），一次性体现在凭据层面——每个 TOTP 码仅在其时间步内可用且不可重放，每个恢复码只能成功使用一次；该端点与登录共用两轨限流（IP 桶 + 账户/IP 失败计数，超限 429）。
> TOTP 秘密以 AES-256-GCM 加密存储（密钥由 `auth.secret` 经 HKDF-SHA256 派生）；验证窗口 ±1 步，`last_step` 保证同一码不可重放；恢复码 10 个、Argon2id 存储、成功后即作废。
> 管理员 `member.manage` 可重置成员 2FA（丢失设备场景），重置动作写审计 `user.2fa.reset`；该审计失败则整体失败（fail closed）。管理员**不能重置自己**（409）——自服务移除走 `/auth/2fa/disable`（需当前密码 + TOTP/恢复码），否则该端点就成了第二因素的旁路。

### 3.2 组织与成员

| 端点 | 说明 |
|---|---|
| `POST /api/v1/orgs` | 创建组织（受 `maxOrgsPerUser` 限制，超出 409/400） |
| `GET /api/v1/orgs/{orgId}/members` | 成员列表及其组织内角色（**组织成员即可访问**，不限 admin） |
| `DELETE /api/v1/orgs/{orgId}/members/{userId}` | 移除成员（v0.6.0，`member.manage`）：同一事务内撤销该用户在本组织的活跃 compat 会话；admin 不能移除 owner、不能移除自己、不能移除最后一个 owner |
| `PATCH /api/v1/orgs/{orgId}/members/{userId}` | 按字段更新会籍（v0.8.0，`MemberUpdateRequest`）：`role_id` 授予内置 admin/member 或自定义角色（**仅 owner**，`org.admin`），不能授予 owner；任何丢失既有权限的变更（降级或收窄）在同一事务撤销该用户在本组织的 compat 会话，提升不撤销；不能改自己或 owner。`disabled`（`member.manage`）停用或恢复会籍：停用在同一事务撤销该用户在本组织的活跃 compat 会话并写 `organization.member.disable` 审计，恢复写 `organization.member.enable`；不能停用自己或末位 owner，admin 不能停用 owner。重复设置同一状态为 200 no-op，不产生重复审计。两个字段可同时出现，各自校验权限 |
| `POST /api/v1/orgs/{orgId}/invitations` | 邀请（admin 生成邀请令牌，邮件下发） |
| `POST /api/v1/invitations/accept` | 接受邀请并加入组织 |
| `GET /api/v1/permissions` | 权限目录（v0.8.0，任何已认证用户）：`code`、`description`、`delegable` |
| `GET/POST /api/v1/orgs/{orgId}/roles` | 角色列表（成员可读，内置在前）/ 创建自定义角色（v0.8.0，`role.manage` 仅 owner） |
| `GET/PUT/DELETE /api/v1/orgs/{orgId}/roles/{roleId}` | 角色详情（成员可读）/ 全量更新 / 删除（v0.8.0，`role.manage` 仅 owner） |
| `GET /api/v1/orgs/{orgId}/provisioning` | 查询供应开关与部署状态（v0.7.0，**仅 owner**）：`enabled` + `state`（`disabled`/`pending`/`provisioning`/`deployed`/`failed`） |
| `PUT /api/v1/orgs/{orgId}/provisioning` | 启用/禁用供应（v0.7.0，**仅 owner**，幂等）：`enabled=false` 同步下线容器、删 `ServerGroup` 行、置标记并在同一事务写 `organization.provisioning.update` 审计；`enabled=true` 只清标记，由供应队列异步部署 |

角色矩阵：`owner` > `admin` > `member`。共享地址簿写操作需要 `addressbook` 权限（owner/admin）；**列表地址簿只需组织成员身份**。

> **v0.8.0 角色模型（模型 A）**：授权唯一来源是 `memberships.role_id → roles.permissions`，旧 `memberships.role` 字符串仅保留给迁移、不再读写。owner/admin/member 是每个组织自动种子的**内置角色行**（`kind` 分别为三者），权限集固定、不可编辑或删除，owner 行不可授予他人（所有权转移不在本版范围）。自定义角色 `kind=custom`，权限只能是权限目录中 `delegable=true` 的码；`org.admin`、`role.manage` 不可委派。角色名在同一组织内唯一，内置名保留；被会籍引用的自定义角色删除返回 409（先改派）。`Member.role` 为兼容字段，与 `role_name` 相同，自定义角色名会出现在这里。

> **v0.7.0 provisioning 开关语义**：关闭是"下线"而不是"暂停"——已有容器会被同步删除、端口释放；再次开启不会复活旧容器，而是重新排队部署（`provision.dataDir/org-<orgId>/` 中的数据保留，但**每次部署都会重新生成服务端密钥对**，客户端需重新配对）。
> 容器删除失败时请求 500、`ServerGroup` 行标 `failed`、开关不变（fail closed）；`failed` 行不会因开启而自动重试（既有语义：清理失败的部署需人工处理）。
> 重复关闭不是纯 no-op：若并发部署在开关置位后才落库，重复关闭会下线该遗留部署并写一条审计（自愈）。
> 若关闭时部署仍在进行（行状态 `provisioning` 且未超过 10 分钟宽限），`ServerGroup` 行会保留为容器清理锚点，审计 `Detail` 含 `deferred_cleanup=true` 与 `state=provisioning`；在途部署在持久化时自行收尾。回滚删除失败时行标 `failed`，重复关闭会立即重试清理；进程在部署中途中断时行保持 `provisioning`，重复关闭需等待宽限期后再清理。响应仍为 `disabled`。
> 响应字段 `cleanup_pending` 区分“关闭意图已记录”与“容器清理已完成”：`disabled` 且 `cleanup_pending=true` 表示仍有待清理的部署行（在途部署回滚或重复关闭重试），`false` 表示清理已完成。
> 供给队列满时开启仍返回 200，reconciler（2 分钟）会补入队。宿主端口探测与预检属于服务内部行为，不在契约内，语义见 [运维指南](operations.md) §6。

### 3.3 设备

| 端点 | 说明 |
|---|---|
| `GET /api/v1/orgs/{orgId}/devices` | 分页列表（`device.read`，成员可读；`q`/`bound`/`page`/`pageSize`） |
| `POST /api/v1/orgs/{orgId}/devices` | 注册设备（`device.write` 权限） |
| `POST .../devices/{deviceId}/heartbeat` | 管理端手动心跳（`source=api`，30s 窗口合并） |
| `POST .../devices/{deviceId}/rebind` | 重置绑定（`device.write`；`reason` 必填 1..500） |
| `PATCH .../devices/{deviceId}` | 停用/恢复设备（v0.8.0，`device.write`）：`{disabled}`，停用在同一事务撤销该设备的活跃 compat 会话并写 `device.disable` 审计（恢复写 `device.enable`）；重复设置同一状态为 200 no-op。停用期间该设备拒绝客户端认领、compat 登录、心跳与系统信息（后者静默丢弃），票据兑换返回 409 |

> **v0.5.0 起设备换机/重装的恢复流程有管理面入口**：管理员列出设备 → 调 `rebind` 填理由 →
> 客户端重新登录自动重新认领。**仍不提供 `DELETE` 设备**（硬删除会留下心跳/会话/审计悬空引用；
> 恢复用 rebind 即可，见增量设计文档）。`Device.bound` 表示当前是否绑定某个客户端实例。
> compat 侧的认领与绑定语义见 §4。
>
> **v0.8.0 设备停用（`disabled`）与 `rebind` 正交**：停用只阻断访问、不解除绑定，恢复后同一客户端
> （同 uuid）可直接重新登录；要换机仍走 `rebind`。停用不清理历史心跳/会话/审计，这些记录保持
> 可追溯。停用与恢复是幂等的，重复设置同值不产生审计。

### 3.4 地址簿

| 端点 | 说明 |
|---|---|
| `GET/POST .../address-books` | 列表（个人 + 共享）/ 创建（`personal` 或 `shared`） |
| `GET/PUT/DELETE .../address-books/{bookId}` | 详情 / 更新 / 删除 |
| `PUT .../address-books/{bookId}/peers` | **全量替换** peers（上限 2000；单 peer ≤64 tags；TagsJSON ≤2048 runes） |
| `PUT .../address-books/{bookId}/tags` | 全量替换 tags（上限 256；color 0..4294967295） |
| `GET/POST .../address-books/{bookId}/grants` | 共享簿授权列表 / 新增或更新授权（v0.8.0，需 `full`：`addressbook.write` 或该簿 `full` 授权） |
| `DELETE .../address-books/{bookId}/grants/{grantId}` | 撤销授权（v0.8.0，需 `full`） |
| `DELETE .../address-books/{bookId}/peers/{peerId}` | 删除条目（v0.8.0，`write`+）：**软删除进回收站**，不硬删除 |
| `GET .../address-books/{bookId}/recycle-bin` | 回收站列表（v0.8.0，`write`+），按删除时间倒序 |
| `POST .../address-books/{bookId}/recycle-bin/{peerId}/restore` | 恢复条目（v0.8.0，`write`+），bump revision |
| `DELETE .../address-books/{bookId}/recycle-bin/{peerId}` | 永久删除（v0.8.0，`full`），不可恢复 |

语义要点：

- 替换是**最后写入者生效**；`revision` 随每次替换递增，仅供客户端同步对比，服务端不校验客户端提交的版本
- `peer_id` ≤64 runes 且请求内唯一；`alias/username/hostname` ≤128；`platform` ≤64
- color 越界（<0 或 >uint32）返回 400，不会被截断
- 审计：替换/创建/删除会产生审计条目（含 actor 与组织）

> **v0.8.0 共享簿授权**：授权主体为 `user`（`subject_user_id` 必填且须为本组织成员）或 `everyone`（无 subject id），访问级别 `read`/`write`/`full`。
> 共享簿默认**所有成员可读**（保持 M2 行为），授权只升不降：`everyone` 授权可把全体成员升到 write/full；**显式 user 授权优先于 everyone**，因此可用 user=`read` 把某成员重新收紧。
> `addressbook.write` 权限（owner/admin 与持有该码的自定义角色）始终是 full。`write` 可替换 peers/tags；`full` 还可改名、删除簿、管理授权。个人簿没有授权概念（400）。
> 同一主体重复 POST 为更新（200），首次创建为 201。

> **v0.8.0 回收站（D9）**：**所有删除入口都是软删除**——管理面 `DELETE .../peers/{peerId}`，以及客户端整本同步（`PUT .../peers`、legacy `/api/ab` 推送）中缺失的条目。软删除行保留 `(book_id, peer_id)` 身份与 opaque `hash`/`note`，因此再次添加同 id 会**原地恢复**并覆盖字段，而不是新建行。
> 回收站保留 30 天，由后台清扫每小时永久删除过期行（系统动作，`deleted_by=0`）；`full` 访问可手动永久删除。恢复会 bump `revision`（内容变化），永久删除不改变 live 内容、不动 `revision`。
> 管理面与 compat 共用同一回收站；客户端看不到回收站条目（快照只含未删除行）。

### 3.5 日志事件

| 端点 | 说明 |
|---|---|
| `GET .../log-events` | 采集到的事件（level/kind/source/device/时间过滤 + 分页） |

事件由采集器写入（见运维指南 §4），API 只读。

---

### 3.6 会话治理（会话记录 / 策略 / 审批 / 票据 / 告警）

> 契约 v0.4.0 定稿，**本节全部端点已实现**（票据、策略、会话记录、审批、告警）。契约之外的行为约定：**会话列表**的 `origin`/`status` 过滤参数是契约**枚举**，未知取值返回 `400 invalid_request` 而不是空列表（客户端不应把参数错误误读为"该状态下没有数据"）；**审批列表**仅支持下表列出的 `status`/`deviceId` 过滤参数（无 `origin`）。

| 端点 | 权限 | 说明 |
|---|---|---|
| `GET .../sessions` | 成员 | 会话记录（按 `started_at` 倒序）：`origin`、`status`、`deviceId`、`since`/`until` 过滤 + 分页 |
| `GET .../sessions/{sessionId}` | 成员 | 会话详情 + 事件序列（最早 200 条，超出置 `truncated=true`） |
| `GET .../policies` | 成员 | 策略列表（单次返回全部，不分页） |
| `POST .../policies` | owner/admin | 创建策略（同组织 `name` 唯一，重复 409） |
| `PUT .../policies/{policyId}` | owner/admin | **全量替换**：`enabled`/`require_approval` 必填，限额字段 null = 不限 |
| `DELETE .../policies/{policyId}` | owner/admin | 删除策略（已签票据保留签发时的快照） |
| `GET .../approvals` | 成员 | 审批列表（`status`/`deviceId` 过滤 + 分页；`status=pending` 即待办） |
| `GET .../approvals/{approvalId}` | 成员 | 审批详情（深链） |
| `POST .../approvals` | 成员 | 提交审批（`kind` 决定 `device_id` 还是 `session_id`；按 kind 复用：事前审批看 actor+设备 pending，追认看会话 pending/approved，复用返回 200） |
| `POST .../approvals/{approvalId}/decision` | owner/admin | approve/deny；只有 `pending` 可决策，否则 409 |
| `POST .../tickets` | 成员 | 签发一次性票据（`ttl_seconds` 30–900，默认 300）；评估**时段 + 审批要求**（并发不在这里判） |
| `GET .../tickets/{ticketId}` | 成员 | 票据记账状态（不返回明文 token） |
| `POST .../tickets/{ticketId}/redeem` | 成员 | 兑换票据 → **复查并发/时段** → 创建 open panel 会话（同一事务） |
| `GET .../alerts` | 成员 | 违规告警（`severity`/`kind`/`since` 过滤 + 分页） |

会话生命周期（契约语义，v0.4.0 实现语义）：

- **panel 会话在兑换时创建**：`POST .../tickets/{ticketId}/redeem` 在同一事务里复查并发/时段 → 原子占用 `used_at` → 写入 `open` 会话，`started_at` = 兑换时刻。票据签发本身不建会话、不算并发（否则 TTL 30–900 秒的票据会变成"幽灵并发"）。
- **并发闸门在兑换，不在签发**：签发时看不到任何新会话，在那里判并发等于恒不超限——"先连签 N 张票再并行兑换"会绕过上限。兑换必须做「count(open,panel) < 上限 → 插入」，且**显式串行化同一组织的兑换**：READ COMMITTED 下仅把两步放进同一事务不够（两个事务都能读到旧计数），实现需先锁组织行/策略行（`SELECT ... FOR UPDATE`）再计数与插入。**不要用按设备的唯一约束代替**——上限是按组织统计的，设备级约束既拦不住不同设备同时占满名额，又会错误拒绝同一设备的第二个合法会话。锁粒度到组织即可，跨组织互不影响。
- **native 会话由日志推断，归并规则按事件类型分开**：日志里没有连接级标识（连接号/对端地址）时，"同设备 30 秒窗口"证明不了两条**连接**事件来自同一条连接。
  - **活动事件**（文件传输、错误、心跳类）：**一个**候选时并入它（panel 只刷 `last_activity_at`，不重复记 native、不触发 native 告警；native 则并入并记录事件）；**多个**候选（面板远控与原生直连并发）时**刷新所有候选的活动时间**、事件只记在 native 会话上——不能 panel 优先，否则 native 会被判空闲关闭，之后它的时长超限告警就永远不会产生；没有候选则新建 native。
  - **连接事件** → **一个会话最多吸收一条**（记 `SessionEvent.kind=connected`）：恰好存在**一个**尚未吸收连接事件的候选（panel 或 native 一视同仁）时归属该会话；**候选都已吸收过、或存在多个未吸收候选无法判定时，新建 native 会话**。
  - 取舍单向：宁可多记一条 native 会话，也不漏记一条连接（CWE-778）。面板远控与原生直连并发时，第二条连接会被独立记下来。
  - 采集规则能提取连接级标识时按标识精确匹配，取代上述保守规则。关联不到组织设备的事件不建会话（`device_id` 必填）。
- **活动时钟**：`status=open` 的会话 `last_activity_at` 非空，为 null 时以 `started_at` 作为空闲基线；日志事件命中会话即刷新。
- **关闭**：可识别的连接结束事件（采集规则映射为 `SessionEvent.kind=disconnected`；rustdesk-server 默认日志级别不打印断开行，默认规则集不含该规则——见部署指南 §6，规则随部署配置提供），或空闲超时（默认 10 分钟无关联事件，可由部署配置覆盖）→ `closed`，`end_reason` 取 `disconnected` / `idle_timeout`。**已关闭的会话不会被重新打开**：窗口内再来的事件新建会话（重连 = 新会话）。没有客户端主动关闭端点——面板不在信令链路上。
- **时长上限是后置的**：超过 `max_session_minutes` 由后台任务把会话置 `closed`（`end_reason=policy_exceeded`）并告警，**不断开真实连接**。panel 会话的强制手段是"兑换时拦截"，不是"中途掐断"。
- **并发口径**：`max_concurrent_sessions` 只统计 `status=open` **且** `origin=panel` 的会话。native 只告警不阻断（D10），把 native 计入会让策略不可执行。
- **`denied` 会话**：仅 panel 来源，由**签发**路径在策略拒绝时写入（`ticket_id=null`、`started_at=ended_at=拒绝时刻`、`end_reason=policy_denied`），不占并发额度；它不经兑换创建。

策略与审批语义：

- **`PUT` 是全量替换，两个布尔字段必须显式给出**：`enabled`/`require_approval` 缺失或 null → 400。服务端要从原始 JSON 判存在性（强类型默认值分不清"没给"与"给了 false"，静默按 false 会把策略关掉或取消审批要求）。
- **多策略同时生效**：所有 `enabled` 策略参与评估，各维度取最严——并发/时长取最小值、时段取交集（按模 1440 求交，跨零点窗口先展开成区间，**交集为空 = 该时段完全禁止**）、任一条要求审批即需审批；组织没有策略等于不限。`Session.policy_id` 记 id 最小的生效策略（多策略各管不同维度时无法唯一归因，具体约束以交集为准）。
- **审批分两类**：`pre_approval` 放行**一次**签发（审批本身不出票，客户端重试 `POST .../tickets` 才拿到 token，**签发即消费审批**并回填 `ticket_id`；票据过期不退还审批，需重新申请）；`ratification` 是对**已发生**的原生直连违规会话补追认——请求必须给 `session_id`（会话须属本组织且 `origin=native`，`device_id` 由服务端派生），决策通过即"已追认"，只改状态 + 落审计，不产生票据、不消费额度、`ticket_id` 恒为 null。
- **`approval_required` 是 409 + 业务码**（不是新 HTTP 状态）：`data.approval_id` 指向新建或复用的待审批请求。
- **票据不外泄、只用一次**：明文 `token` 只在签发响应出现一次，服务端只存摘要；`used_at` 非 null 即不可再用；重复/过期/撤销兑换一律 `409`（不区分原因，避免探测）。

其它易错点：

- **时段语义**：`allowed_start_minute`/`allowed_end_minute` 是 **UTC 当日分钟数**（0–1439），起点 > 终点表示跨零点窗口（如 `1320`→`360` 即 22:00–06:00）；两者必须同时提供或同时为 `null`；**`start == end` 返回 400**（全天请用 null）。
- **事前审批阻断不产生告警**：那是正常的受控流程，每次受控远控都告警会把告警列表变成噪音；它体现在 409 与审计里。原生直连无法事前审批（审批是签发的前提），所以 native 会话的告警只用 `duration_exceeded` / `outside_window` 表达实际违规。
- **`PUT` 是全量替换**：`enabled` 与 `require_approval` 必填，避免"改时段时省略 `enabled` 导致已停用策略被静默重新启用"。

---

### 3.7 审计（v0.8.0）

| 端点 | 权限 | 说明 |
|---|---|---|
| `GET .../audit-logs` | `audit.read` | 审计查询：`action`、`actorUserId`、`targetType`、`targetId`、`from`（含）/`to`（不含，UTC）过滤 + `page`/`pageSize`（默认 50，上限 200）；按 `created_at desc, id desc` |

- **可见范围由角色 `audit_scope` 决定**：`global` 可查全组织；`individual` 只返回**自己是操作者**（`actor_user_id`）或**用户类目标是本人**（`target_type="user"` 且 `target_id` 为本人 id 的十进制字符串）的条目。这个过滤在 SQL 层完成，不是先查全量再裁剪；缺失/未知 scope 按 `individual` 处理（fail closed）。
- **列表轮询不写审计**：查询审计这个动作本身不产生新审计行，否则每次刷新都会污染数据；导出等有副作用的一次性动作才写审计（见 §3.8）。
- `detail` 为解析后的 JSON 对象；历史行若不是合法 JSON 则原样返回字符串，不丢数据。
- 审计记录只读：查询不修改任何审计内容，也不提供删除端点。

### 3.8 审计导出（v0.8.0）

| 端点 | 权限 | 说明 |
|---|---|---|
| `GET .../audit-logs/export` | `audit.read` | 与查询相同的过滤条件，返回 `text/csv`（`created_at, actor_user_id, actor_email, action, target_type, target_id, detail`） |

- **单次上限 1000 行**：超出返回 `400`，要求收窄过滤；不做静默截断（截断的导出会让人误以为"就这些"）。
- **公式注入防护**：单元格以 `= + - @` 开头时加 `'` 前缀，避免在电子表格中被当作公式执行。这包括 `action`、`target_id` 与 `detail` 原始文本。
- **可见范围与查询一致**：`individual` 角色只能导出自己的条目；导出内容不会越过角色 scope。
- **导出动作写审计 `audit.export`**：`Detail` 含行数与生效的过滤条件；审计写入失败则拒绝返回文件（fail closed）。响应带 `Content-Disposition: attachment` 与 `Cache-Control: no-store`。

### 3.9 审计保留期与本地归档（v0.8.0）

| 端点 | 权限 | 说明 |
|---|---|---|
| `GET .../audit-retention` | `org.admin`（owner） | 返回 `audit_retention_days` 与最近一次成功归档摘要（`at`/`rows`/`path`） |
| `PUT .../audit-retention` | `org.admin`（owner） | 设置保留天数：0 = 永久，1..3650；写 `organization.audit_retention.set` 审计 |

- **先归档、后删除（fail closed）**：每小时后台任务对每个保留期 > 0 的组织，把早于阈值的审计行写成 JSONL，附同名 `.sha256`，**重新读取校验行数与摘要一致后才删除**；归档或校验失败则该组织本轮不删除任何行。
- **归档路径**：`<audit.archiveDir>/org-<orgId>/audit-<UTC时间戳>.jsonl`；临时文件原子改名落盘。归档文件不经 API 暴露，运维备份见运维指南。
- **系统动作也审计**：归档与清理分别写 `audit.retention.archive`（含行数、路径、摘要、阈值）与 `audit.retention.purge`；actor 为 0（系统）。
- **删除与归档同事务**：两条系统审计与按 id 精确删除在同一事务提交；无事务审计器时整轮拒绝删除。

---

## 4. compat 层（RustDesk 原生客户端）

挂载于 `/api`，**协议形状冻结自官方客户端源码**（rustdesk flutter/sciter）——字段名不遵循管理 API 包络，迁移契约前不得擅改。

### 4.1 认证与会话

| 端点 | 说明 |
|---|---|
| `POST /api/login` | `{username, password, id, uuid, org?}`。`id`=rustdesk 设备 id，`uuid`=客户端实例 uuid。登录成功 = 签发 compat token + **认领设备** |
| `GET /api/login-options` | 登录能力协商（当前返回空列表） |
| `POST /api/logout` | 撤销当前 compat 会话 |
| `POST /api/currentUser` | 当前用户信息（需 Bearer） |

**设备认领语义**（重要，v0.4.0 事务化 + 绑定代数，v0.5.0 增加重置入口）：

- 设备 `rustdesk_id` 首次登录时绑定提交的 `uuid`（`BoundUUID`）；之后不同 uuid 登录同一 id → 403 `device is already bound`
- **解绑只能走管理面 `POST .../devices/{deviceId}/rebind`**（owner/admin，`reason` 必填随审计留存）：清 `BoundUUID` + `binding_generation` **无条件 +1** + 同一事务写 `device.binding.reset` 审计。重复调用每次成功且代数继续 +1；审计写失败则绑定不变（fail closed）。**禁止直接改 `bound_uuid` 而不动代数**——那会让旧会话仍能驱动设备。重置不吊销旧机 token，重新认领是**先到先得**：要让新机赢得认领，先让旧机退出登录/离线
- **认领与会话在同一事务**（#40）：认领成功但会话落库失败会整体回滚——不存在「已绑定但无会话」或「有会话无绑定」的中间态；被拒绝的认领（403）不会留下任何会话行
- **绑定代数**：每次绑定变更（首次认领、管理员改绑）使 `binding_generation` +1；登录会话快照当时的代数，`heartbeat`/`sysinfo` 校验会话代数与设备当前代数一致——**旧代数会话的活动被丢弃**（不落库、不推进 `last_seen_at`）。绑定的所有权语义因此不依赖 uuid 的保密性
- uuid 非秘密且登录时不校验归属——这正是心跳必须按 `(uuid, device_id)` 双条件解析会话的原因
- `id` ≤ 64 字符、`uuid` ≤ 128 字符，超长直接 400（防止「绑定成功但会话建不出来」的死锁状态）
- **设备停用（v0.8.0）**：`disabled=true` 的设备拒绝 compat 登录（403，提示联系管理员恢复；停用时的活跃会话已在同一事务撤销），心跳与系统信息静默丢弃（不刷新 `last_seen_at`），票据兑换返回 409。恢复后保持原绑定，同 uuid 客户端可直接登录。
- **成员失去组织访问时**（v0.6.0 已接线：`DELETE .../members/{userId}` 与 admin→member 降级；v0.8.0 起也包括会籍停用）在**同一事务**内调用 `compatapi.RevokeOrgSessions` 撤销该用户在该组织的全部活跃 compat 会话（#39）；撤销失败整体回滚、请求 500，绝不返回成功。撤销后该用户的 compat 请求 401、免凭据心跳不再生效。停用的会籍对 compat 登录不可见：该组织不参与 `email#orgID` 选择，单会籍用户登录返回 403（提示会籍已停用）。
- **会话有效 ≠ 会籍有效（v0.8.0 起）**：所有 compat 消费者在会话有效后**复核当前 membership**——`requireSession`（Bearer 端点）与免凭据 heartbeat/sysinfo 的 `activeSessionByUUID` 都要求 `(user_id, organization_id)` 仍存在且未停用（v0.8.0 增加 `disabled=false` 条件）。这样即使登录与成员移除/停用并发、会话在撤销之后才落库，后续请求也会 401，免凭据心跳也不会再刷新设备。membership 查询失败按“非成员”处理（fail closed）。

### 4.2 心跳与系统信息（无凭据）

| 端点 | 说明 |
|---|---|
| `POST /api/heartbeat` | `{id, uuid}`。按 `(uuid, device_id)` 解析活跃会话；命中则更新 `last_seen_at`（30s 窗口合并，幂等）。任何匹配失败都**静默 200**（协议兼容； forged id 不会被记录） |
| `POST /api/sysinfo` | 同心跳语义，携带系统信息 |

安全语义：无凭据写槽位按设备 30s 窗口收敛；伪造的 `(id, uuid)` 组合不会命中会话（#32 修复的 DoS：只按 uuid 解析会让攻击者压制他人设备）。

### 4.3 地址簿同步（个人簿）

compat 地址簿**只服务个人地址簿**（`EnsurePersonalBook`），共享簿无 compat 路径。

| 端点 | 说明 |
|---|---|
| `GET /api/ab`（别名 `GET /api/ab/get`） | 整本快照（BookSnapshot：book + peers + tags，含 hash/note 不透明字段） |
| `POST /api/ab` | 整本写入：`{data: <json 字符串>, hash}`。`hash` 非空时与服务器重算的 content hash 比对，不一致 → **409，响应体为 compat 专用形状 `{"error":"ab_conflict"}`**（不走管理 API 包络；乐观并发检查）；缺省 hash 时直接覆盖 |
| `POST /api/ab/personal` | 同整本写入（个人语义显式化） |
| `POST /api/ab/peers` | 分页读 peers |
| `POST /api/ab/tags/:guid` | 某标签组列表 |
| `POST /api/ab/peer/add/:guid` | 增加单个 peer（字段边界校验；重复 id 视为更新） |
| `PUT /api/ab/peer/update/:guid` | 更新 peer |
| `DELETE /api/ab/peer/:guid` | 删除 peer |
| `POST /api/ab/tag/add/:guid` `PUT /api/ab/tag/rename/:guid` `PUT /api/ab/tag/update/:guid` `DELETE /api/ab/tag/:guid` | 标签 CRUD（rename 到同名 = 无操作成功；rename 到已存在的其他名 = 400） |

**通用校验**（管理/compat 两条路径一致，上限常量同源）：

- peer `id` 非空 ≤64 runes；`alias/username/hostname` ≤128；`platform` ≤64；单 peer tags ≤64；`TagsJSON` ≤2048 runes；`hash` ≤128；`note` ≤512
- 整本上限：peers ≤2000、tags ≤256
- 违规 → `ErrInvalidContent` → HTTP 400；**重复 id/标签名在整本推送中去重（后出现的覆盖），不报错**
- 整本写入的 `hash`/`note` 语义：省略字段**继承**已存值（老客户端不回传 note），显式空字符串清除

### 4.4 冲突检测

- compat 整本写入（`/api/ab`）带 content hash → 冲突 409，**仅个人簿**
- 管理 API 的 `PUT .../peers` 无冲突检测（最后写入者生效，revision 仅对比用）——共享簿由客户端自行协调

---

## 5. 与官方客户端的兼容性注记

- 兼容层形状冻结自 rustdesk 客户端源码（flutter `ab_model.dart` / sciter / `hbbs.dart`），契约变更前必须核对客户端行为
- C7：客户端发送的、不匹配任何采集规则的日志按设计丢弃，不算处理失败
- 客户端把心跳当幂等操作：服务端 30s 合并对其不可见
- Step 5（真机回归）将用 RustDesk 1.5 客户端对以上协议逐条验证

---

## 6. 版本与变更管理

- 契约版本随 release 演进：v0.1.0（M0）→ v0.2.0（M1）→ v0.3.0（M2）→ v0.4.0（M3，会话治理域）→ v0.5.0（设备管理增量）→ v0.6.0（成员离场）→ v0.7.0（按组织 provisioning 开关）→ **v0.8.0（M4：角色模型、审计查询/导出、停用、地址簿授权与回收站、令牌、2FA）**
- v0.6.0 为**加性变更**：新增 `DELETE/PATCH /orgs/{orgId}/members/{userId}`（#39 撤销接线）。v0.5.0 的新增设备列表与 rebind 保持不变；仍不提供 `DELETE` 设备
- v0.7.0 为**加性变更**：新增 `GET/PUT /orgs/{orgId}/provisioning` 与 `ProvisioningStatus.cleanup_pending`；既有端点请求/响应形状与字段不变
- v0.4.0 的既有端点请求/响应形状与字段零变更，但 **`ErrorCode` 新增了 `approval_required`**（所有响应共用的 `code` 类型）——对穷尽式 `switch` 或严格枚举解码的客户端属于 **breaking**，重新生成类型后必须处理该分支（0.x 阶段按 C10 以 minor 承载，见 §3.6）
- **契约变更的 PR 必须同步更新本文档 §3/§4 与 `openapi.yaml`**，并保证 `go generate` 零漂移
- WEB/APP 从 `openapi.yaml` 生成类型：任何字段/形状变更视为 breaking，需在 PR 描述中标注
