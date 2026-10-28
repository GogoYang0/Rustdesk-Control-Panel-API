# 后端 API 规范（Backend API Specification）

> 适用版本：v0.11.0（M6 波次 5b-1 Passkey、5b-2 OIDC；上一基线 v0.10.0）。本文档是对 `openapi.yaml`（契约 v0.11.0）与 compat 层协议的人类可读摘要与语义说明；**字段与请求/响应形状以 `openapi.yaml` 为契约权威**，本文负责解释语义、边界与易错点。
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

`code` 取值（契约枚举）：`ok` `invalid_request` `unauthorized` `not_found` `conflict` `forbidden` `email_not_verified` `rate_limited` `internal` `approval_required` `two_factor_required` `captcha_required` `captcha_invalid` `captcha_unavailable`。`unauthorized` 映射 **401**（登录/刷新的凭据拒绝路径）；`internal` 映射 **500**（未预期的服务端错误，不向客户端泄露细节）。

`approval_required` 必须携带 `data.approval_id`（指向待审批请求），`two_factor_required` 必须携带 `data.challenge_token`（登录第二步挑战令牌，5 分钟有效）；其余错误码的 `data` 为 `null`。

### 2.2 租户隔离（管理 API）

管理 API 的一切组织内资源都带 `{orgId}` 路径参数；**例外**是个人令牌端点 `/auth/tokens`（列表用必填 `organizationId` 查询参数，创建用请求体 `organization_id`）——令牌属于用户而非组织路径资源，但签发后只在对应组织的路径上生效。这组令牌管理端点（列表、创建、撤销）**只接受管理 JWT**：个人令牌仅能访问带 `{orgId}` 的组织路径，用它调用 `/auth/tokens` 一律返回 `401 unauthorized`。服务端通过 `ScopedByOrg` 强制租户过滤，**组织内**跨租户资源访问返回 `404 not_found`（不泄露存在性）；**调用者不属于该组织**时返回 `403 forbidden`（"不是本组织成员"本身不构成信息泄露，且便于前端区分"没权限"与"资源没了"）。compat 层不带 `{orgId}`：**已认证请求**使用已验证 token 的 `org` claim 作为组织上下文；**无凭据的 heartbeat/sysinfo** 从持久化会话取得 `OrganizationID` 后执行组织范围查询（见 §4）。

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
| `two_factor_required` | 401 | 已启用 2FA 的账号密码正确但需第二步（`data.challenge_token` 指向 `/auth/2fa/verify`） |
| `rate_limited` | 429 | 登录锁定（LoginGuard） |
| `captcha_required` | 400 | 已启用验证码但请求未携带 `captcha`（v0.10.0） |
| `captcha_invalid` | 400 | 挑战缺失、过期、已用或答案错误；提供商判定失败（响应不区分账号是否存在） |
| `captcha_unavailable` | 503 | 验证码提供商不可达且 `failMode=closed`（启用验证码时） |
| `internal` | 500（唯一例外：passkey 未启用时 12 个端点返回 503，响应体 code 仍为 `internal`） | 未预期的服务端错误（不向客户端泄露细节） |

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
| `POST /api/v1/auth/login` | 邮箱+密码；启用验证码时先校验 `captcha`（v0.10.0）；未验证邮箱返回 `email_not_verified`；连续失败触发 LoginGuard 锁定（429，键含用户名规范化） |
| `GET /api/v1/auth/captcha` | 公开：返回当前验证码提供商与挑战（v0.10.0）；未启用时 `enabled=false`（不耗限流桶）；**启用时**独立 IP 限流（429） |
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
| `POST /api/v1/auth/2fa/verify` | 登录第二步（v0.8.0，公开；v0.10.0 起启用验证码时同样要求 `captcha`）：`{challenge_token, code}` → 令牌对 |
| `POST /api/v1/orgs/{orgId}/members/{userId}/2fa/reset` | 管理员重置成员 2FA（v0.8.0，`member.manage`，写 `user.2fa.reset` 审计） |

> **v0.8.0 个人访问令牌**：明文格式 `rdt_<32B base64url>`，服务端只存 SHA-256，列表只回 `token_prefix`（前 8 字符）。
> 令牌只在**组织路径**上生效（路径 `orgId` 必须等于签发组织）；`/auth/tokens` 自身、`/orgs`、`/permissions` 等非组织端点仍只接受 JWT。
> **有效权限 = 令牌申请集 ∩ 用户当前角色权限集**，每个请求实时重算：角色降级或会籍停用会立即收窄/失效，令牌不会绕过这些变更。
> 每人每组织最多 20 个活跃令牌，有效期 1..365 天（默认 90）。令牌与 refresh/JWT 是不同凭证族，互不替代。创建与撤销都在**令牌写事务内**写审计（`token.create` / `token.revoke`，明文不入审计）；无事务审计器时拒绝写入。
> **令牌权限是硬上限**：地址簿的写入在解析出所有权或 `full` 授权后仍要求令牌具备 `addressbook.write`——缺少该码的令牌（即使调用者是个人簿所有者或持有共享簿 full 授权）对地址簿的创建/改名/删除/peer/标签/授权/回收站操作一律 403；JWT 调用不受影响。

> **v0.8.0 管理面 2FA（TOTP）**：启用后 `/auth/login` 密码正确也**不直接发令牌**，而是返回 `401 + code=two_factor_required`，`data.challenge_token` 为 5 分钟有效的挑战令牌；客户端用它调用公开的 `/auth/2fa/verify`（TOTP 码或一次性恢复码）换取令牌对。挑战令牌本身可重复提交（不是一次性凭据），一次性体现在凭据层面——每个 TOTP 码仅在其时间步内可用且不可重放，每个恢复码只能成功使用一次；该端点与登录共用两轨限流（IP 桶 + 账户/IP 失败计数，超限 429）。
> TOTP 秘密以 AES-256-GCM 加密存储（密钥由 `auth.secret` 经 HKDF-SHA256 派生）；验证窗口 ±1 步，`last_step` 保证同一码不可重放；恢复码 10 个、Argon2id 存储、成功后即作废。
> 管理员 `member.manage` 可重置成员 2FA（丢失设备场景），重置动作写审计 `user.2fa.reset`；该审计失败则整体失败（fail closed）。管理员**不能重置自己**（409）——自服务移除走 `/auth/2fa/disable`（需当前密码 + TOTP/恢复码），否则该端点就成了第二因素的旁路。2FA 是**账号级**状态：目标在本组织是 owner 时只有 owner（`org.admin`）能重置；目标只要**在本组织之外还存在任何会籍**（无论角色、含已停用）就一律 403——清除账号级因素会同时削弱其登录其他组织的保护，这类跨组织用户的账号恢复只能走平台级运维（系统外）。

> **v0.10.0 交互式验证码**：部署启用后，三个公开凭据入口（`/auth/login`、`/auth/2fa/verify`、`/invitations/accept`）都在密码/TOTP 校验**之前**要求 `captcha` 对象：`{response: {<provider 字段>}}`。客户端先调 `GET /auth/captcha` 取挑战。提供商：`altcha`（默认，自托管 proof-of-work，`response.payload` 为 widget 返回的 base64 payload）、`geetest`（v4，`response` 带 `lot_number`/`captcha_output`/`pass_token`/`gen_time`）、`cap`（自托管 Standalone，`response.response` 为 token）。
> 错误码：缺 `captcha` → `400 captcha_required`；挑战过期/已用/答案错/提供商判定失败 → `400 captcha_invalid`（响应不区分账号是否存在）；提供商不可达且 `failMode=closed` → `503 captcha_unavailable`。**判定与故障按响应内容区分，不按状态码**：Cap 对不存在或已消耗的 token 返回 `404 {"success":false}`、对过期 token 返回 `403 {"success":false}`，两者都是判定（判定失败永远 400，`failMode=open` 也不放行）；只有网络错误、超时、5xx 或响应里没有任何判定字段才算故障。**验证码失败不计入登录失败窗口**，只受 IP 桶约束；**面板对三家凭据统一做本地单次消费**（Altcha 已用签名 5 分钟窗口；GeeTest `lot_number` 与 Cap token 10 分钟去重窗口，与提供商自身的限制叠加），TTL 默认 5 分钟；提供商不可达属于「无判定」而非「已用」，此时释放本地占用，同一凭据可在服务恢复后重试；已通过校验的凭据在其窗口内不会被内存上限淘汰（表满优先淘汰未通过校验的占位）；校验进行中若占位已被淘汰，成功结论仍会补记为已通过，过期句柄也不会覆盖或删除同 key 的新占位。**单次消费状态是进程内的**：多副本部署下按 IP 粘性路由不足以提供全局单次消费（消费键与 IP 无关），需要该保证时须单副本或共享消费存储。compat `/api/login` 不接验证码（原生客户端无法解交互式验证码）。

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
| `PATCH .../devices/{deviceId}` | 更新设备（v0.8.0 起支持 `disabled`；v0.10.0 扩展为 `DeviceUpdateRequest`，`device.write`）：请求体至少一个字段，**同一请求要么全部生效、要么全部不生效**（单事务）。`disabled`：停用在同一事务撤销该设备的活跃 compat 会话并写 `device.disable` 审计（恢复写 `device.enable`）；停用期间该设备拒绝客户端认领、compat 登录、心跳与系统信息（后者静默丢弃），票据兑换返回 409；v0.9.0 起签发停用设备的票据返回 404，且 compat `GET /api/peers` 不返回停用设备（见 §3.10）。`owner_user_id`：设置/清空归属（`null` 清空、`0` 非法，目标必须是本组织有效成员否则 404）。`note`：运维备注，`null` 或空串清空，≤255 字符。每个实际变化的字段各写一条审计（`device.assign`/`device.note`），重复设置同值为 200 no-op 不写审计 |

> **v0.5.0 起设备换机/重装的恢复流程有管理面入口**：管理员列出设备 → 调 `rebind` 填理由 →
> 客户端重新登录自动重新认领。**仍不提供 `DELETE` 设备**（硬删除会留下心跳/会话/审计悬空引用；
> 恢复用 rebind 即可，见增量设计文档）。`Device.bound` 表示当前是否绑定某个客户端实例。
> compat 侧的认领与绑定语义见 §4。
>
> **v0.8.0 设备停用（`disabled`）与 `rebind` 正交**：停用只阻断访问、不解除绑定，恢复后同一客户端
> （同 uuid）可直接重新登录；要换机仍走 `rebind`。停用不清理历史心跳/会话/审计，这些记录保持
> 可追溯。停用与恢复是幂等的，重复设置同值不产生审计。
>
> **v0.9.0 `Device.device_group_id`**：设备所属设备组（nullable，未分组为 `null`）。由
> `PUT .../device-groups/{deviceGroupId}/devices` 全量替换维护；**删除设备组时系统会把关联设备的
> `device_group_id` 置为 `null`**（每台设备最多属于一个设备组，换组即从原组移出）；
> 管理面设备列表对该字段只读，语义见 §3.10。

> **v0.10.0 设备归属（`Device.owner_user_id` / `owner_email` / `note`）**：归属是**用户维度**的事实
> （`devices.owner_user_id` 可空列），它决定「谁在客户端能看到并连接这台设备」——归属人**始终可见并
> 可连接自己的设备**（设备停用或会籍停用时除外），无需任何规则；归属不会绕过绑定，也**不因心跳/系统
> 信息上报而变更**。写入口两条，语义与审计完全一致：管理面 `PATCH`（`owner_user_id` 可被 `null`
> 清空、`0` 非法，目标必须是本组织「有效成员」——会籍未停用且角色可解析，否则 404）与客户端
> `--assign`（§4.1）。`owner_email` 为只读展示字段：归属人用户行已不存在时为 `null`（归属本身保留为
> 历史）。**成员被移除或停用不会自动清空归属**（历史可追溯，管理面仍显示邮箱），其可见性按会籍
> fail closed（本人不可见、组→组规则也不可见）。改派只需再 `PATCH` 一次 `owner_user_id`，旧归属人
> 立即不再通过归属看到该设备。

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

> **v0.8.0 共享簿授权**：授权主体为 `user`（`subject_user_id` 必填且须为本组织成员）、`everyone`（无 subject id）或 v0.10.0 起的 `user_group`（`subject_group_id` 必填且须为本组织的用户组，否则 404），访问级别 `read`/`write`/`full`。
> 共享簿默认**所有成员可读**（保持 M2 行为），授权只升不降：`everyone` 授权可把全体成员升到 write/full；**显式 user 授权优先于 everyone**，因此可用 user=`read` 把某成员重新收紧。
> `user_group` 授权对该组的**显式成员**生效（`everyone` 组的隐式成员身份不参与授权）：有效级别取所有命中主体（`everyone`、命中的各 `user_group`）中的**最高档**；显式 user 授权仍然优先（可把某成员从组授权的高档重新收紧）。内置 `everyone` 组**不能**作为 `user_group` 主体（它没有显式成员行，授权永远不会命中任何人）——给全体成员授权请直接用 `subject_kind=everyone`，误用返回 400。
> `addressbook.write` 权限（owner/admin 与持有该码的自定义角色）始终是 full。`write` 可替换 peers/tags；`full` 还可改名、删除簿、管理授权。个人簿没有授权概念（400）。
> 同一主体重复 POST 为更新（200），首次创建为 201。**删除用户组时**，以该组为主体的授权在同一事务级联删除，删除响应 `removed_grants` 报告条数（§3.10）。

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
| `POST .../tickets` | 成员 | 签发一次性票据（`ttl_seconds` 30–900，默认 300）；先过**访问控制**（§3.10，不通过 → 404），再评估**时段 + 审批要求**（并发不在这里判） |
| `GET .../tickets/{ticketId}` | 成员 | 票据记账状态（不返回明文 token） |
| `POST .../tickets/{ticketId}/redeem` | 成员 | 兑换票据 → 先**无副作用**校验 token 与终态 → 按兑换人复判访问控制（不通过 → 404；停用设备 → 409）→ **复查并发/时段** → 创建 open panel 会话（同一事务） |
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
- **票据不外泄、只用一次**：明文 `token` 只在签发响应出现一次，服务端只存摘要；`used_at` 非 null 即不可再用。兑换先做**无副作用**的 token/终态校验：错误 token、重复、过期、撤销一律 `409`（不区分原因，避免探测，且不会因设备状态产生差异）。**通过校验后**才按兑换人做访问判定：没有规则覆盖 → `404`（§3.10）；停用设备 → `409`。拒绝路径不消耗票据、不建会话，并写 `session.ticket.denied` 审计（理由 `access_control` / `device_disabled`；`Detail` 含 `stage=issue|redeem`、`device_id`，兑换另含 `ticket_id`；签发阶段的停用设备也记 `access_control`）。

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
| `PUT .../audit-retention` | `org.admin`（owner） | 设置保留天数：`days` 必填（缺失 400），0 = 永久，1..3650；写 `organization.audit_retention.set` 审计 |

- **先归档、后删除（fail closed）**：每小时后台任务对每个保留期 > 0 的组织，把早于阈值的审计行写成 JSONL，附同名 `.sha256`，**重新读取校验行数与摘要一致后才删除**；某批归档或校验失败时**该批不删除任何行**，已成功的批次不回滚，下个周期从剩余行继续。按批处理（每批 ≤1000 行，逐批归档/校验/删除，直到剩余不足一批），积压不会一次性载入或撞占位符上限。
- **归档路径**：`<audit.archiveDir>/org-<orgId>/audit-<minId>.jsonl`；临时文件原子改名落盘，文件名只由批次**最小 id** 决定：事务失败后的重试重选同一批（行未删除，批次只增不减），最小 id 不变即覆盖同一路径；已提交批次的行已删除，其最小 id 不会被再次选中，因此不会覆盖已引用的归档。归档文件不经 API 暴露，运维备份见运维指南。
- **系统动作也审计**：归档与清理分别写 `audit.retention.archive`（含行数、路径、摘要、阈值）与 `audit.retention.purge`；actor 为 0（系统）。
- **删除与归档同事务**：两条系统审计与按 id 精确删除在同一事务提交；无事务审计器时整轮拒绝删除。

### 3.10 访问控制（v0.9.0）

> 契约 v0.9.0：用户组、设备组与「只有 allow」的组规则。语义与 RustDesk Server Pro 的 Access Control 对齐：**规则只决定能否连接**；连上后的动作权限（Control Role）与客户端策略下发（Strategy）不在本版本。v0.10.0 扩充：规则目标新增 `user_group`、设备可归属到用户（§3.3）。

| 端点 | 权限 | 说明 |
|---|---|---|
| `GET/POST .../user-groups` | `access.manage` | 列表（含内置 `everyone`，带 `kind` 与 `member_ids`）/ 创建自定义组 |
| `PATCH/DELETE .../user-groups/{groupId}` | `access.manage` | 改名 / 删除（`everyone` 409；删除级联成员、以该组为源的规则、以该组为 `user_group` 目标的规则，以及以该组为主体的地址簿授权，逐条审计，响应报 `removed_rules` 与 `removed_grants`；**不影响设备归属**） |
| `PUT .../user-groups/{groupId}/members` | `access.manage` | **全量替换**成员；任一 id 非本组织成员 → 400 整单拒绝 |
| `GET/POST .../device-groups` | `access.manage` | 列表（含 `device_ids`）/ 创建 |
| `PATCH/DELETE .../device-groups/{deviceGroupId}` | `access.manage` | 改名 / 删除（设备回到未分组，指向该组的规则同事务级联删除） |
| `PUT .../device-groups/{deviceGroupId}/devices` | `access.manage` | **全量替换**设备；目标设备从原组移入本组（每台设备最多属于一个设备组） |
| `GET/POST .../access-rules` | `access.manage` | 列表（源组名 + 目标类型/组名）/ 创建（`target_kind`=`device_group`/`all_devices`/`user_group`） |
| `DELETE .../access-rules/{ruleId}` | `access.manage` | 删除规则 |

判定语义：

- **只有 allow，多条并集**：成员通过显式所属的用户组 ∪ 内置 `everyone` 组获得规则；目标为设备组、用户组或全部设备，多条同时命中取**并集**（不是首个命中）。
- **设备只属于一个设备组**：`devices.device_group_id` 由设备组全量替换维护；未分组设备（`null`）只被 `all_devices` 规则覆盖。
- **`user_group` 目标（v0.10.0）**：目标组**显式成员**所拥有的设备（按 `devices.owner_user_id` 展开）。目标成员的会籍停用/缺失/无角色时其设备不通过该规则可见——该成员本人也一并不可达（会籍失效先于一切判定，见下方「停用优先」，其「本人设备始终可见」的兜底同样不生效）；`everyone` 作为**目标**时语义为「所有由**有效成员**归属的设备」——停用、无角色（含 `role_id` 指向已删除角色）或已移除会籍的归属人贡献空集。未归属设备不因此可见（与 `all_devices` 仍有区别）。
- **本人设备始终可见（v0.10.0）**：**会籍有效**（未停用且角色可解析，即 `role_id` 指向本组织现存角色行）的普通成员，其无规则兜底包含**自己拥有的未停用设备**（归属见 §3.3），因此「登录后只看到自己那台」无需任何规则。会籍停用 / 角色不可解析、或设备停用时，该兜底**不生效**（与下方「停用优先」一致）。
- **`everyone` 是保留名 + 隐式成员**：每个组织恰有一个，不可改名/删除，成员不可编辑；`all_devices` 规则存 `target_group_id=0` 哨兵，契约层映射为 `null`。
- **默认规则可删除**：组织创建（及存量组织启动收敛）时生成 `everyone → all_devices`；它是普通可删除行，删除后重启不会复活，再建精确规则即完成收紧。
- **管理员绕过**：会籍角色 `owner`/`admin`（按 `role_id` 解析）不受组规则限制，管理面设备列表与票据签发/兑换均为全量；绕过不看是否持有 `access.manage`。
- **停用优先**：停用的设备与停用/无角色的会籍一律不可达，先于规则判定。
- **两处执行点**：compat `GET /api/peers`（§4.1）只返回判定允许且未停用的设备；票据签发（按签发人）与兑换（按兑换人）各判一次——**一般访问拒绝返回 `404`**，但兑换一张有效票据且目标设备已停用时返回 `409 conflict` 并记 `device_disabled` 审计（见 §3.6）。已建立的连接不因规则变更中断；**归属变更也不撤销已建立的 compat 会话**（与「规则变更不中断连接」一致，需要立即收权时改用停用设备）。
- **审计**：组/规则写操作为 `access.user_group.*` / `access.device_group.*` / `access.rule.*`；票据访问拒绝为 `session.ticket.denied`，`Detail` 含 `reason`（`access_control`|`device_disabled`）、`stage`（`issue`|`redeem`）、`device_id`（兑换含 `ticket_id`）。签发阶段遇到停用设备也记 `access_control`（判定层先于管理员绕过拒绝）。

### 3.11 验证码（v0.10.0）

`GET /api/v1/auth/captcha`（公开，独立 5 次/分钟/IP 限流）：

```json
{"code":"ok","message":"ok","data":{"enabled":true,"provider":"altcha","challenge":{"params":{"algorithm":"SHA-256","challenge":"...","maxNumber":100000,"salt":"...?expires=...","signature":"..."}}}}
```

- `enabled=false` 时 `provider` 与 `challenge` 省略，客户端按原流程直接登录。
- `geetest`：`params={"captcha_id":"...","script_url":"https://static.geetest.com/v4/gt4.js"}`。
- `cap`：`params={"api_endpoint":"https://cap.example.com/<site_key>/","site_key":"..."}`（尾斜杠必需：widget 会拼接 `challenge`/`redeem`）。
- 挑战只对 `altcha` 携带 `maxNumber`（解题上限）；挑战 TTL 由部署配置（`1m–10m`），外部提供商校验超时固定 3 秒，见 [部署指南 §3.2](deployment.md)。

### 3.12 控制角色（v0.10.0）

控制角色（Control Role）定义「**连上之后能做什么**」，与访问控制（能否连接）、Strategy（改被控端设置）是三件不同的事。

- 端点：`GET|POST /orgs/{orgId}/control-roles`、`PATCH|DELETE /orgs/{orgId}/control-roles/{roleId}`、`PUT /orgs/{orgId}/members/{userId}/control-role`。读取要求组织成员；写入要求 `control_role.manage`（owner 全量、admin 由内置集合授予，**不可委派**）。
- 权限集合是 **14 个协议键的三态映射**：`use_client`（不覆盖被控端本地设置，缺省值）/ `enable` / `disable`；键与 RustDesk 客户端 `ControlPermissions.Permission` 枚举一一对应（`keyboard`=bit0 … `usb`=bit13）。未知键或非法状态整单 `400`。
- 内置 `default` 角色：每个组织一行，**不可删除、不可改名**，权限可改；未分配角色的成员回退到它。删除自定义角色会在同一事务里清空持有者的 `control_role_id`（回到 default）。成员列表/详情通过 `Member.control_role_id`（可空）回读当前分配，名称由 `GET /control-roles` 解析。
- 快照语义：票据签发时按操作人计算并写入 `tickets.control_role_id` / `control_permissions`（14 位 bitmask）与完整三态快照，兑换时复制到 `sessions.control_permissions`。**之后修改角色不会改写已签发的票据**（票据 TTL ≤ 15 分钟）。
- **执行边界（必读）**：`control_permissions` 由 hbbs 在信令消息（`PunchHole`/`RequestRelay`/`FetchLocalAddr`）里注入，本面板**不在信令链路**（设计 D10），provision 起的是 stock rustdesk-server——因此**原生客户端会话不受控制角色约束**。本版本交付的是管理面模型、票据快照与审计证据；执行面属于 M7 网页客户端（读票据快照）或未来的 Pro 兼容 hbbs。不要据此向用户承诺「已在客户端生效」。

### 3.13 客户端连接 / 文件传输日志（v0.10.0）

数据来自原生客户端主动上报（§4.5），与面板签发的 `sessions` 是两套记录：前者是**被控端视角的连接与传输证据**，后者是面板侧记账。

- `GET /orgs/{orgId}/connection-logs`、`GET .../connection-logs/export`、`GET /orgs/{orgId}/file-logs`、`GET .../file-logs/export`；权限 `audit.read`。
- 可见范围复用角色 `audit_scope`：`global` 看全组织；`individual` 只看自己拥有设备（`devices.owner_user_id`）的记录；`individual` 且用户 id 为 0 时返回空页（不退化成全量）。
- 过滤：`deviceId`、`rustdeskId`、`from`/`to`（连接日志比较 `started_at`，文件日志比较 `created_at`，均为含边界）。
- 导出口径：单次最多 **1000** 行，超出返回 `400` 要求收窄（不静默截断）；CSV 单元格对 `= + - @` 前缀加 `'` 防公式注入；导出写审计 `connection_log.export` / `file_log.export`（含过滤条件与行数），审计写不进去则不返回文件。
- 保留期：两张表跟随组织 `audit_retention_days`（0 = 永久），由 `client-log-retention` 每小时清扫；**不做归档**——这些行是证据而非审计卷宗，删除即不可恢复。

### 3.14 客户端策略（Strategy，v0.10.0）

策略是**下发到被控端的客户端配置**，与「能否连接」（访问控制 §3.10）和「连上后能做什么」（控制角色 §3.12）是三件不同的事。它通过客户端每 30 秒一次的 `POST /api/heartbeat` 响应下发（§4.2），不是主动推送。

- 端点：`GET|POST /orgs/{orgId}/strategies`、`GET|PATCH|DELETE /orgs/{orgId}/strategies/{strategyId}`；读取要求组织成员，写入要求 `strategy.manage`（owner 全量、admin 由内置集合授予，**不可委派**）。请求体拒绝未知字段（含客户端的 `extra`）：静默忽略会得到 201 而选项根本没存。
- `config_options` 是 **20 个白名单键**的三态字符串映射（键名逐字匹配，大小写与空格敏感）：`enable-audio`、`enable-clipboard`、`enable-file-transfer`、`enable-file-copy-paste`、`enable-camera`、`enable-terminal`、`enable-tunnel`、`enable-remote-restart`、`enable-record-session`、`enable-block-input`、`enable-privacy-mode`、`enable-remote-modify`、`enable-remote-printer`、`enable-check-update`、`disable-change-id`、`disable-settings`、`disable-installation`、`disable-unlock-pin`、`disable-tcp-listen`、`disable-ab`。
- **白名单就是安全边界**：客户端对收到的键**没有自己的白名单**（`handle_config_options` 直接写入本地配置），因此 `api-server`、`custom-rendezvous-server`、`relay-server`、`key`、`whitelist` 一类键一律 400——放行一个就等于把设备交给别人。值 ≤256 字符、不得含控制字符；空值的语义是「清除该键、回到客户端内置默认」。
- 客户端会把下发的键标记为**固定**（`is_option_fixed`），用户无法在本机改回——这是策略生效的表现，不是 bug。
- 三层分配（固定优先级，无叠加）：**设备 > 设备组 > 成员**（设备归属人的会籍）。`PUT .../devices/{deviceId}/strategy`、`PUT .../device-groups/{deviceGroupId}/strategy`、`PUT .../members/{userId}/strategy`，`strategy_id` 必填（显式 `null` 清除）。跨组织 id 一律 404。
- `enabled=false` 是停用开关：保留行与分配，但心跳不下发；**停用会终止解析**，不会回落到更宽的层（避免把刚关掉的选项装回去）。停用/清空分配**不会撤销**客户端已经固定的选项——协议只按「收到的键」写入，撤销必须显式下发空值。
- `version` 是**组织内单调递增**的下发代次（不是行内计数器），只在 `config_options` 实际变化或创建时分配，作为心跳响应的 `modified_at`；改名、停用、空转 PATCH 都不分配新版本。之所以不能按行计数：客户端只存一个数字（`strategy_timestamp`），两个策略的版本相同会让「改派到另一个策略」被误判为「已是最新」而**一次都不下发**。
- **删除某个键 = 显式清除**：`config_options` 整体替换，被去掉的键会以空值（`""`）随下发回传一次并持续保留在 `cleared_keys` 里（重新加回该键则移出），否则客户端会一直保留旧值。
- 删除策略在同一事务里清空设备/设备组/会籍上指向它的分配，并写审计 `strategy.delete`。

### 3.15 心跳断连（v0.10.0）

- `POST /orgs/{orgId}/devices/{deviceId}/disconnect {reason}`：权限 `device.disconnect`（不可委派），`reason` 必填 1–255 字符；同设备已有 pending 请求 → `409`。
- **面板不直接断连**：它不在信令链路（设计 D10）。请求落 `device_disconnects`，由客户端下一次心跳响应里的 `disconnect` 字段执行；客户端只会断开**它自己刚上报的**连接编号（`conns`），面板编不出编号。
- 生效延迟：最长一个心跳周期（30 秒）加客户端处理时间；客户端当时没有活跃连接时请求**保持 pending**，不消耗。
- pending 15 分钟未被消费 → `disconnect-expiry` worker 标记 `expired` 并写系统审计（`ActorUserID=0`）。
- 请求记录 `status`（`pending|fulfilled|expired`）、`conn_count`、`fulfilled_at`，审计动作 `device.disconnect.request/fulfilled/expired`。

---

### 3.16 Passkey / WebAuthn（v0.11.0）

管理面支持 passkey 登录，三条独立的用途：

| 用途 | 入口 | 前置 |
|---|---|---|
| 第二因子（替代 TOTP） | `/auth/passkey/login/begin` 带 `challenge_token` | 密码已通过且账户启用了 TOTP |
| 无密码登录 | `begin` 不带参数（可发现凭据）或带 `email` 提示 | 账户有 passkey |
| 敏感操作 step-up | `/auth/passkey/stepup/begin`、`/auth/passkey/stepup/finish` | 已登录 + 有 passkey |

**绑定不改变密码登录的因子要求**：只有启用 TOTP 时 `/auth/login` 才返回
`two_factor_required`；`data.methods` 列出可用因子（`totp`，以及该账户有
passkey 时的 `passkey`）；该字段是 0.11.0 对既有 401 响应体唯一的增补。想让 passkey 成为强制要求，要么删除密码
（见下），要么先启用 TOTP。

**`begin` 的 `email` 提示可区分"该邮箱是否已绑定 passkey"**：命中时
`allowCredentials` 收窄为该账户的凭据，未命中时退化为可发现凭据 ceremony
（不带该字段）。状态码与结构一致，差别只在内容。这是为让浏览器只列相关凭据
而显式接受的取舍（设计 D16），**不是**保密边界；探测成本由 per-IP 限流约束。
需要完全消除差异的部署**必须在服务端或入口网关拒绝 `email` 参数**——本版本的
客户端不发送它并不够，任何匿名调用者都能直接提交；本版本无内置开关，属已知限制。

**客户端要做编码转换，不能把 JSON 直接交给浏览器**：`options` 里的
`challenge`、`user.id`、`allowCredentials[].id`/`excludeCredentials[].id` 都是
base64url 字符串，而 `navigator.credentials.create()`/`get()` 要求 `ArrayBuffer`。
反向提交时，`rawId`、`clientDataJSON`、`attestationObject`、`authenticatorData`、
`signature`、`userHandle` 都要编码回 base64url（`userHandle` 可为 `null`，
`transports` 可缺失）。参考实现：`docs/reference/passkey-smoke.html` 的
`b64urlToBuf`，以及注册向的 `prepareCreationOptions` 与登录向的
`prepareRequestOptions`（约 40 行）。

**无密码账户**：`POST /auth/password/remove` 把 `password_hash` 置空，之后
`/auth/login` 对任何密码都返回通用 `401 unauthorized`（内部仍走一次
Argon2id，保持耗时恒定）。删除密码的四项前置条件：当前密码正确、step-up
有效、已绑 passkey ≥ 2、`user_totp` 行完全不存在（含未启用的 pending 行）。
代价是 **compat 登录不可用**（响应 `warnings` 明示），且没有邮箱自救通道。
`POST /auth/password/set` 可在无密码时恢复（同样需要 step-up）。

**step-up**：`finish` 返回 2 分钟、一次一用的 `stepup_token`；每次敏感操作
消耗一次，重放 401。

**错误语义**：断言失败（origin/rpId/challenge/签名/克隆计数器回退）一律
401 且不区分原因；凭据已绑定（含跨账户）409；最后一个凭据 + 无密码 409；
服务未启用 503。签名计数器回退只标记 `clone_warning=true`，**不自动删除**
凭据。

**compat 层不受影响**：原生客户端不走 WebAuthn，`/api/login` 协议不变；
无密码账户在 compat 侧必然失败（空 hash 也走 dummy 校验，保持耗时一致）。

### 3.17 OIDC 单点登录（v0.11.0）

部署级**单一**外部身份源（与 LDAP 互斥，两者同时启用会启动失败）。
流程：Authorization Code + PKCE(S256) + nonce，全程 state/nonce 一次性、
ID token 经 JWKS 验签；登录成功后回调签发一次性 ticket（60 秒，库存 SHA-256），
SPA 用它兑换与密码登录相同的 token 对。URL 中不出现任何 token。

| 步骤 | 端点 | 认证 | 成功 | 主要错误 |
|---|---|---|---|---|
| 1 | `GET /auth/providers` | 无 | `{oidc:{enabled,name}, ldap:{enabled}}` | 429 |
| 2 | `POST /auth/oidc/start` | 无 | `{authorization_url, state}` | 400 redirect_path 非法；429；503 |
| 3 | `GET /auth/oidc/callback` | 无 | 302 `?ticket=…` | 302 `?error=<固定码>` |
| 4 | `POST /auth/oidc/exchange` | 无 | `TokenResponse` | 401；429；503 |
| 5 | `GET /auth/identity` | JWT | `{active_provider, identities[]}` | 401 |
| 6 | `POST /auth/identity/unlink` | JWT + step-up/密码 | `OkResponse` | 400/401/404/409 |
| 7 | `POST /orgs/{orgId}/members/{userId}/identity/reset` | `member.manage` | `OkResponse` | 403/404/409/500 |

**无 JIT（O2）**：外部身份只绑定已存在的面板账户。绑定条件：ID token 的
`email` 非空、`email_verified` 为真（布尔或字符串 `"true"`），且该邮箱在
`users` 中唯一命中、账户邮箱已验证。未建号邮箱 → 回调 `?error=no_account`。

**稳定标识（O11）**：绑定按 `(provider, issuer, subject)` 识别，issuer 入库。
换 IdP 后旧行不命中、不删除，启动时打 WARN 列出条数；老用户需管理员 reset
一次才能重绑（见 operations §11）。

**冲突（O4）**：subject 已绑定 A 而邮箱命中 B → 拒绝并把 A 的行标记
`conflict_at`；之后 SSO 对该账户一律 `identity_conflict`，直到管理员 reset。

**本地第二因子（O5/O12）**：外部登录默认不叠加面板 TOTP。
`external.requireLocalSecondFactor=true` 时，**已启用 TOTP** 的账户在
exchange 处返回 401 `two_factor_required`（`methods:["totp"]`），
`POST /auth/2fa/verify` 完成第二步；未启用 TOTP 的账户直接发 token 并打 WARN。
文档不得宣称该开关等于强制全员 MFA。

**解绑**：`POST /auth/identity/unlink` 需 step-up 或当前密码（二选一）。
无密码、无 passkey 且只剩这条绑定时返回 409 —— 此类账户没有线上自救通道。
管理员 reset（端点 7）复用 2FA/passkey 的越权守卫；唯一例外：目标全部绑定
都已 `conflict_at` 时放行（O14，此时 SSO 本来就登不进）。

**错误码映射**：`oidc_failed`（state/签名/nonce/超时/token 端点失败，一律不
回显 IdP 原文）、`no_account`、`email_unverified`、`identity_conflict`。
IdP 不可达 → 503；**不降级为密码登录**。


### 3.18 LDAP 目录登录（v0.11.0）

部署级单一外部身份源之一（与 OIDC 互斥，同时启用会启动失败）。流程：服务账号
bind → 按用户名搜索 → 用户 DN bind 验证密码；成功后按目录 `mail` 属性绑定到
**已存在**的面板账户（无 JIT），直接返回与密码登录相同的 token 对。无浏览器
跳转、无 ticket（与 OIDC 的差别只在证明方式）。

`POST /auth/ldap/login`（未认证）→ 200 `TokenResponse`。

| 错误 | 条件 |
|---|---|
| 400 | 用户名或密码为空——**拒绝发生在触碰目录之前**（L1：空密码 + simple bind 在多数目录上等于匿名 bind） |
| 401 | bind 失败 / 用户名搜不到 / 搜索命中多于一条（L6 fail closed）；统一「用户名或密码错误」，不回显细节 |
| 403 | 目录账号无 `mail` 属性；邮箱无对应面板账户（无 JIT）；面板邮箱未验证 |
| 429 | 与 `/auth/login` 同源的 IP 桶与账户失败窗口（L9） |
| 503 | `ldap.enabled=false` 或目录连接/TLS/搜索协议错误（L5：目录挂了绝不能报「密码错」） |

用户名按 RFC 4515 逐字符转义（`\` `*` `(` `)` NUL）后进 filter；属性名
（`usernameAttribute`/`mailAttribute`）只来自启动配置且校验形状——请求输入
永远到不了 filter 的结构位（P-L2）。验证码启用时与 `/auth/login` 同一套。

绑定语义与 OIDC 完全一致（§3.17）：`(provider="ldap", issuer=配置 host 小写,
subject=用户名)` 唯一；冲突 409、面板邮箱未验证 403；管理员 reset 走同一条
路径。`external.requireLocalSecondFactor=true` 的门条件也一致（L12）：仅拦
已启用 TOTP 的账户。目录密码不落日志、审计或错误消息（P-L4）。


## 4. compat 层（RustDesk 原生客户端）

挂载于 `/api`，**协议形状冻结自官方客户端源码**（rustdesk flutter/sciter）——字段名不遵循管理 API 包络，迁移契约前不得擅改。

### 4.1 认证与会话

| 端点 | 说明 |
|---|---|
| `POST /api/login` | `{username, password, id, uuid, org?}`。`id`=rustdesk 设备 id，`uuid`=客户端实例 uuid。登录成功 = 签发 compat token + **认领设备** + **自动归属**（设备未归属、且本次提交的 `uuid` 与设备绑定一致时归给登录用户，v0.10.0） |
| `POST /api/devices/cli` | 客户端 `--assign` 调用点（v0.10.0，**个人令牌 + `device.write`**，不走 compat 会话）：见下 |
| `GET /api/login-options` | 登录能力协商（当前返回空列表） |
| `POST /api/logout` | 撤销当前 compat 会话 |
| `POST /api/currentUser` | 当前用户信息（需 Bearer） |
| `GET /api/peers` | 设备列表（需 Bearer）：v0.4.0 起按会话所属组织隔离；v0.9.0 起按访问规则过滤并隐藏停用设备，owner/admin 返回组织内全部**未停用**设备（见 §3.10） |

> **v0.10.0 两步登录（TOTP）**：账号启用 TOTP 后，`POST /api/login` 的密码步骤不再直接发 token，而是返回 **200** `{"type":"email_check","tfa_type":"totp","secret":"<挑战>","user":{...}}`（客户端对任何非 `email_check` 的 `tfa_type` 显示「2FA code」，已核对 `src/ui/index.tis`）。第二步用 `{"type":"email_code","id","uuid","verificationCode","tfaCode","secret"}`（客户端两个字段都填，服务端 `tfaCode` 优先）换取 token。挑战 5 分钟有效、**单次消费**、绑定 `id + uuid`（换机器 401）、失败 5 次作废；失败同样计入登录锁定计数。未启用 TOTP 的账号走 `email_code` 一律 401（不允许绕过密码）。**与面板共用同一 TOTP 秘密与防重放步进**：同一 30 秒窗口内先在面板登录、再用同码登录客户端会被判重放，这是预期行为。`email_check`（邮件验证码）本版本未实现——面板的邮箱验证只用于注册激活。

> **v0.10.0 `POST /api/devices/cli`（`--assign`）**：RustDesk 客户端 `rustdesk --assign` 的真实调用点（已核对上游 `core_main.rs`）。鉴权用**个人令牌**（`Authorization: Bearer rdt_...`，非 compat token）：令牌无效/过期/已撤销 → `401`；**有效权限 = 令牌申请集 ∩ 令牌所有者当前角色权限集**（实时重算），不含 `device.write` → `403`。
> 请求体白名单（其余字段一律 `400`，错误信息含字段名——**不静默忽略**，因为静默忽略会让调用方误以为下发成功）：`id`（rustdesk id，必填）、`uuid`（接受但**不落库**，绑定只由登录路径维护）、`user_name`（本组织成员的邮箱，精确匹配；非成员与平台内不存在的邮箱返回**同一个** `404`，响应不可区分——`users` 表是跨组织全局的，区分开就等于给持令牌者一个全局账号探针）、`device_group_name`（本组织的设备组名，大小写不敏感，不存在 → `404`）、`device_name`（设备显示名，≤128 字符）、`note`（运维备注，≤255 字符）。`strategy_name`（v0.10.0 起支持，反转波次 2 的 D5）：本组织策略名，大小写不敏感，不存在 → `404`；解析发生在设备更新**之前**，名字错则整单失败，失败不会留下「备注改了、策略没分配」的半状态。**该字段额外要求令牌具备 `strategy.manage`**（与三个分配端点同权）——`device.write` 可委派而 `strategy.manage` 不可，只校验前者会让自定义角色拿到目录明确不授予它的能力；缺权限返回 `403`。仍不支持 `address_book_*`、`device_username`：这两类在本系统无对应概念。
> 成功 `200 {"code":"ok"}`。设备或目标用户/组不属于令牌所在组织 → `404`（与"不存在"不可区分）。写入走与管理面 `PATCH` **同一个事务化 service**：每个实际变化的字段各写一条审计（`device.assign`/`device.rename`/`device.group`/`device.note`），请求级不再补记 HTTP 审计。设备的所有写入都限制在令牌绑定的组织内，**不存在跨组织改设备的路径**。

**设备认领语义**（重要，v0.4.0 事务化 + 绑定代数，v0.5.0 增加重置入口，v0.10.0 增加自动归属）：

- 设备 `rustdesk_id` 首次登录时绑定提交的 `uuid`（`BoundUUID`）；之后不同 uuid 登录同一 id → 403 `device is already bound`
- **登录自动归属（v0.10.0）**：认领成功（含复用既有绑定）后，若设备**尚无归属人**、且**本次登录提交的 `uuid` 与设备绑定相同**，则把 `owner_user_id` 置为本次登录用户（与认领同一事务）；**已归属他人的设备绝不被登录改写**（条件 UPDATE `owner_user_id IS NULL AND bound_uuid = <提交的 uuid>`），管理员改派过的归属保持不动。**未提交 `uuid` 的登录不产生归属**：uuid 是客户端协议里唯一的身份信号，归属是持久授权（本人可见 + 设备准入兜底），不能凭"知道一个 rustdesk id"取得（CWE-863）；登录本身仍成功（兼容既有客户端形态）。该归属不经 `--assign` 也可生效——这正是「成员登录后只看到自己那台设备」的默认路径（§3.10）。自动归属不单独写审计（登录路径本身不写领域审计；改派与清空由管理面 `PATCH` 或 `--assign` 完成，二者都留痕）
- **解绑只能走管理面 `POST .../devices/{deviceId}/rebind`**（owner/admin，`reason` 必填随审计留存）：清 `BoundUUID` + `binding_generation` **无条件 +1** + 同一事务写 `device.binding.reset` 审计。重复调用每次成功且代数继续 +1；审计写失败则绑定不变（fail closed）。**禁止直接改 `bound_uuid` 而不动代数**——那会让旧会话仍能驱动设备。重置不吊销旧机 token，重新认领是**先到先得**：要让新机赢得认领，先让旧机退出登录/离线
- **认领与会话在同一事务**（#40）：认领成功但会话落库失败会整体回滚——不存在「已绑定但无会话」或「有会话无绑定」的中间态；被拒绝的认领（403）不会留下任何会话行
- **绑定代数**：每次绑定变更（首次认领、管理员改绑）使 `binding_generation` +1；登录会话快照当时的代数，`heartbeat`/`sysinfo` 校验会话代数与设备当前代数一致——**旧代数会话的活动被丢弃**（不落库、不推进 `last_seen_at`）。绑定的所有权语义因此不依赖 uuid 的保密性
- uuid 非秘密且登录时不校验归属——这正是心跳必须按 `(uuid, device_id)` 双条件解析会话的原因
- `id` ≤ 64 字符、`uuid` ≤ 128 字符，超长直接 400（防止「绑定成功但会话建不出来」的死锁状态）
- **设备停用（v0.8.0）**：`disabled=true` 的设备拒绝 compat 登录（403，提示联系管理员恢复；停用时的活跃会话已在同一事务撤销），心跳与系统信息静默丢弃（不刷新 `last_seen_at`），票据兑换返回 409。恢复后保持原绑定，同 uuid 客户端可直接登录。v0.9.0 起 `GET /api/peers` 不返回停用设备（对 owner/admin 也一样），签发停用设备的票据返回 404。
- **成员失去组织访问时**（v0.6.0 已接线：`DELETE .../members/{userId}` 与 admin→member 降级；v0.8.0 起也包括会籍停用）在**同一事务**内调用 `compatapi.RevokeOrgSessions` 撤销该用户在该组织的全部活跃 compat 会话（#39）；撤销失败整体回滚、请求 500，绝不返回成功。撤销后该用户的 compat 请求 401、免凭据心跳不再生效。停用的会籍对 compat 登录不可见：该组织不参与 `email#orgID` 选择，单会籍用户登录返回 403（提示会籍已停用）。
- **会话有效 ≠ 会籍有效（v0.8.0 起）**：所有 compat 消费者在会话有效后**复核当前 membership**——`requireSession`（Bearer 端点）与免凭据 heartbeat/sysinfo 的 `activeSessionByUUID` 都要求 `(user_id, organization_id)` 仍存在且未停用（v0.8.0 增加 `disabled=false` 条件）。这样即使登录与成员移除/停用并发、会话在撤销之后才落库，后续请求也会 401，免凭据心跳也不会再刷新设备。membership 查询失败按“非成员”处理（fail closed）。

### 4.2 心跳与系统信息（无凭据）

| 端点 | 说明 |
|---|---|
| `POST /api/heartbeat` | `{id, uuid, ver, conns?, modified_at?}`。按 `(uuid, device_id)` 解析活跃会话；命中则更新 `last_seen_at`（30s 窗口合并，幂等）。任何匹配失败都**静默 200**（协议兼容；伪造 id 不会被记录） |
| `POST /api/sysinfo` | 同心跳语义，携带系统信息 |

心跳**响应**（v0.10.0 起可能带三个字段，全部可选）：

| 响应字段 | 语义 |
|---|---|
| `strategy: {config_options: {...}}` | 生效策略的选项；只在版本变化时出现 |
| `modified_at: <int64>` | 策略版本号（`strategies.version`）。**只与 `strategy` 同时出现**：客户端会独立持久化该值（`strategy_timestamp`），只发版本不发选项 = 告诉它「已是最新」而它仍跑旧配置，且此后再也不会请求 |
| `disconnect: [conn_id...]` | 要断开的连接编号，取自**本次请求**的 `conns`（客户端自报）。没有待处理请求或 `conns` 为空时不出现 |

`conns` 只接受能装进客户端 `Vec<i32>` 的正整数，其余（`-1`、`0`、字符串、小数）丢弃，不会被回显成断连目标。

**跨组织身份歧义（v0.10.0 安全边界）**：心跳会话按 `(uuid, device_id)` 全平台解析、取最新。若同一 `(rustdesk id, bound uuid)` 出现在**多个组织**（例如有人知道设备的 id 与 uuid 后在自己的组织注册同 id 设备并登录），心跳对该设备**不下发任何内容**——既没有 `strategy`/`modified_at`，也没有 `disconnect`，操作日志记 warning。配置与断连的权威不能建立在有歧义的身份上。恢复需要撤销影子组织对应的 compat 会话，或让合法客户端重新登录产生更新的会话——仅删除重复的设备行不够（最新会话仍会被解析选中、且其组织内已无设备行可触碰）。这条规则使「影子注册」无法把别的组织的策略推给真实客户端。订阅上报的连接编号只做排障线索（`device_heartbeats.conn_ids`，最多滞后一个心跳窗口），断连的真实依据是当次请求。

安全语义：无凭据写槽位按设备 30s 窗口收敛；伪造的 `(id, uuid)` 组合不会命中会话（#32 修复的 DoS：只按 uuid 解析会让攻击者压制他人设备）。策略与断连都**只对通过 `(uuid, device_id)` + 绑定代数校验的会话生效**——过期会话拿不到组织策略，也不会替别人断连。

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

### 4.5 客户端审计上报（v0.10.0）

客户端把连接、文件传输与告警记录 POST 到 `/api/audit/{conn,file,alarm}`。**三个端点都不带 `Authorization`**（客户端 `post_request(url, body, "")`，已核对 `src/common.rs` 与 `src/server/connection.rs`），因此真实性只能靠请求体里的 `(id, uuid)` 与设备绑定比对：

| 端点 | 载荷要点 |
|---|---|
| `POST /api/audit/conn` | `{id, uuid, action:"new"\|"close", ip, conn_id, session_id, nonce, conn_audit_ref?}`；`new` 建行、`close` 只关闭同一 `(id, conn_id, session_id)` 的 open 行，找不到则写一行已关闭的 orphan 行（证据不丢） |
| `POST /api/audit/conn`（备注） | 客户端的「发送备注」只发 `{id, session_id, note}`（无 uuid/action/nonce），服务端追加到该会话最近一条 open 行（≤512 字符） |
| `POST /api/audit/file` | `{id, uuid, peer_id, conn_id, type:0\|1, path, is_file, info, nonce}`；`type` 0=send、1=receive，`info` 是 JSON 字符串（ip/name/num/files） |
| `POST /api/audit/alarm` | `{id, uuid, typ, info, conn_id, nonce, conn_audit_ref?}`；落 `audit_logs`，动作 `client.alarm.<类型>`（未知类型保留编号，不丢弃） |

- 校验顺序：字段缺失/超长 → `400`；`id` 在本组织查不到设备或 `uuid` 与绑定不符（含空绑定）→ `403`。
- `nonce` 去重窗口 **5 分钟**（上游注释：api server only remembers a nonce for five minutes；客户端重试上限 120 秒）。重复 nonce 返回 **200** 幂等，不重复落行。去重标记由 `audit-nonce-sweep` 每 10 分钟清理。
- 风险边界：知道 `(id, uuid)` 的人可以伪造记录——uuid 不随请求加密，这与免凭据 heartbeat 同一信任级；不要在事故调查中把这两张表当作不可抵赖证据。
- **备注路径更弱**：客户端「发送备注」只带 `{id, session_id, note}`，没有 uuid。服务端要求该 `id` 在全平台唯一命中一台设备（0 或 >1 台一律 403），并用命中的组织 + `device_id` 收敛写入范围，因此不会跨租户；但同一组织内，知道正在进行的 rustdesk id 与会话编号的人仍可追加文本。备注只是标注，不承担证据强度。

---

## 5. 与官方客户端的兼容性注记

- 兼容层形状冻结自 rustdesk 客户端源码（flutter `ab_model.dart` / sciter / `hbbs.dart`），契约变更前必须核对客户端行为
- C7：客户端发送的、不匹配任何采集规则的日志按设计丢弃，不算处理失败
- 客户端把心跳当幂等操作：服务端 30s 合并对其不可见
- Step 5（真机回归）将用 RustDesk 1.5 客户端对以上协议逐条验证

---

## 6. 版本与变更管理

- 契约版本随 release 演进：v0.1.0（M0）→ v0.2.0（M1）→ v0.3.0（M2）→ v0.4.0（M3，会话治理域）→ v0.5.0（设备管理增量）→ v0.6.0（成员离场）→ v0.7.0（按组织 provisioning 开关）→ v0.8.0（M4：角色模型、审计查询/导出、停用、地址簿授权与回收站、令牌、2FA）→ v0.9.0（M5：访问控制——用户组/设备组/组规则、peers 过滤与票据准入）→ v0.10.0（M6：波次 1 交互式验证码——Altcha/GeeTest/Cap、三入口准入；波次 2 组模型下半场；**波次 3 控制角色、客户端审计上报与连接/文件日志、compat 登录 TOTP**）
- v0.6.0 为**加性变更**：新增 `DELETE/PATCH /orgs/{orgId}/members/{userId}`（#39 撤销接线）。v0.5.0 的新增设备列表与 rebind 保持不变；仍不提供 `DELETE` 设备
- v0.7.0 为**加性变更**：新增 `GET/PUT /orgs/{orgId}/provisioning` 与 `ProvisioningStatus.cleanup_pending`；既有端点请求/响应形状与字段不变
- v0.9.0 为**加性变更**（新增 user-groups/device-groups/access-rules 端点、`access.manage` 权限目录项与 `Device.device_group_id` 字段），但**票据访问语义有变化**：签发/兑换新增访问控制判定（拒绝 `404 not_found`），停用设备的签发由成功变为 `404`（兑换仍为 `409`）；客户端需处理该分支
- v0.10.0 为**加性变更**：新增 `GET /auth/captcha`、三个公开凭据请求的可选 `captcha` 字段与三个错误码。**行为变化仅在被部署显式启用验证码后生效**（默认关闭）：启用时三个入口新增 400/503 分支，客户端必须先取挑战；compat `/api/login` 不变
- v0.10.0（波次 2，组模型下半场）同样是**加性变更**：新增 compat `POST /api/devices/cli`、`Device.owner_user_id/owner_email/note` 三个字段、`AccessRule.target_kind` 的 `user_group` 取值、`AddressBookGrant(.Request).subject_group_id` 与 `AddressBookGrantKind.user_group`、`UserGroupDeleteData.removed_grants`；`PATCH .../devices/{deviceId}` 的 `operationId` 由 `setDeviceDisabled` 更名为 `updateDevice`（**重新生成客户端类型时方法名会变**，请求体形状不变）。**行为变化**：普通成员默认可见自己归属的设备（无需规则）；`memberships.role` 字符串列被一次性删除（数据库级不可回滚点，见[部署指南 §4.2](deployment.md)）
- v0.11.0 为**加性变更**（WEB/APP 侧）：新增 Passkey（`/auth/passkeys*` 等注册/登录/管理端点）、OIDC（`/auth/oidc/{start,callback,exchange}`）与 LDAP（`/auth/ldap/login`）登录、外部身份查看/解绑（`/auth/identity*`）与管理员重置（`/orgs/{orgId}/members/{userId}/identity/reset`）、`/auth/providers` 点亮；`two_factor_required` 响应新增 `data.methods`（标识后续校验方式，目前恒为 `["totp"]`）——重新生成客户端类型后需处理该字段。**compat 层协议无变化**；新错误码仅限 v0.10.0 已声明的三个 captcha 值。外部身份为部署级单 provider（`oidc` 与 `ldap` 配置互斥）且无 JIT：IdP/目录的邮箱必须先在面板建号并验证
- v0.4.0 的既有端点请求/响应形状与字段零变更，但 **`ErrorCode` 新增了 `approval_required`**（所有响应共用的 `code` 类型）——对穷尽式 `switch` 或严格枚举解码的客户端属于 **breaking**，重新生成类型后必须处理该分支（0.x 阶段按 C10 以 minor 承载，见 §3.6）
- v0.10.0 同样**新增了三个 `ErrorCode` 值**（`captcha_required`/`captcha_invalid`/`captcha_unavailable`），并且给 `/auth/login`、`/auth/2fa/verify`、`/invitations/accept` 补上了 `503` 响应声明——对穷尽式 `switch` 或严格枚举解码的客户端与 v0.4.0 同理属于 **breaking**：重新生成类型后必须处理这三个错误码与 503 分支，**即使部署未启用验证码**（枚举是共用的 `code` 类型）
- **契约变更的 PR 必须同步更新本文档 §3/§4 与 `openapi.yaml`**，并保证 `go generate` 零漂移
- WEB/APP 从 `openapi.yaml` 生成类型：任何字段/形状变更视为 breaking，需在 PR 描述中标注
