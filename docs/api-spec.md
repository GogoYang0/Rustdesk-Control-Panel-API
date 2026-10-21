# 后端 API 规范（Backend API Specification）

> 适用版本：v0.3.0（M2）。本文档是对 `openapi.yaml`（契约 v0.3.0）与 compat 层协议的人类可读摘要与语义说明；**字段与请求/响应形状以 `openapi.yaml` 为契约权威**，本文负责解释语义、边界与易错点。
> 本文档随版本演进持续更新——契约变更的 PR 必须同步更新 §3/§4。
> 配套文档：[部署指南](deployment.md) · [运维指南](operations.md)

---

## 1. 两族认证

| | 管理 API（WEB/APP） | compat 层（RustDesk 原生客户端） |
|---|---|---|
| 令牌 | JWT（`/api/v1/auth/login` 签发，15m）+ 刷新令牌（168h，**轮换 + 重放撤销**） | compat access token（`/api/login` 签发，TTL 见 `compat.accessTTL`） |
| 中间件 | 管理 JWT 中间件，写入 `api.*` 上下文 | compat 会话中间件，写入 `compat.*` 上下文（`compat.userID` / `compat.orgID` / `compat.jti`） |
| 审计 | 中间件回退记录（领域写用 `TxRecorder` 同事务） | 同一审计中间件回退读取 compat 键归因（v0.3.0 起） |
| 多组织 | 登录响应含组织列表，请求携带 `orgId` 路径参数 | 登录时选择组织（`org` 选择器），会话固定组织 |
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

`code` 取值（契约枚举）：`ok` `invalid_request` `not_found` `conflict` `forbidden` `email_not_verified` `rate_limited` `internal`。

### 2.2 租户隔离

一切组织内资源都带 `{orgId}` 路径参数；服务端通过 `ScopedByOrg` 强制租户过滤，跨组织访问返回 `404 not_found`（不泄露存在性）。

fail-closed 的适用范围必须分清：

- **ORM 作用域查询**（经 `ScopedByOrg` 包装的 Query/Create/Update/Delete）由租户插件注入条件；`orgID=0` 时注入的条件匹配不到任何行，即 fail-closed。
- **`Raw()` / `Exec()` 不经过租户插件**，不会被自动注入租户条件——未显式写入租户过滤的原始 SQL **不具备** fail-closed 保证，也不得用于访问租户数据（store 层硬性约定）。

### 2.3 错误码 → HTTP 映射

| code | HTTP | 典型场景 |
|---|---|---|
| `invalid_request` | 400 | 载荷校验失败、契约上限越界 |
| `email_not_verified` | 403 | 未验证邮箱登录 |
| `forbidden` | 403 | 角色不足、设备已绑定（compat） |
| `not_found` | 404 | 跨组织访问 / 不存在的资源 |
| `conflict` | 409 | 管理 API 资源冲突；compat 地址簿的 hash 冲突使用 compat 专用错误 `ab_conflict`（见 §4.3），不走此包络 |
| `rate_limited` | 429 | 登录锁定（LoginGuard） |

### 2.4 分页

列表端点（设备、日志事件、地址簿 peers）使用 `page`/`pageSize`（契约定义）；日志事件支持按时间与来源过滤。

---

## 3. 管理 API（WEB/APP）

### 3.1 认证

| 端点 | 说明 |
|---|---|
| `POST /api/v1/auth/login` | 邮箱+密码；未验证邮箱返回 `email_not_verified`；连续失败触发 LoginGuard 锁定（429，键含用户名规范化） |
| `POST /api/v1/auth/refresh` | 刷新令牌轮换：旧 refresh 即刻撤销，重放旧令牌会**整族撤销**（重放检测） |
| `POST /api/v1/auth/verify-email` | 邮箱验证（一次性令牌，邮件下发） |
| `POST /api/v1/auth/resend-verification` | 重发验证邮件（结果不明时令牌保留，可重试） |

### 3.2 组织与成员

| 端点 | 说明 |
|---|---|
| `POST /api/v1/orgs` | 创建组织（受 `maxOrgsPerUser` 限制，超出 409/400） |
| `GET /api/v1/orgs/{orgId}/members` | 成员列表及其组织内角色（**组织成员即可访问**，不限 admin） |
| `POST /api/v1/orgs/{orgId}/members` | 成员角色管理（admin） |
| `POST /api/v1/orgs/{orgId}/invitations` | 邀请（admin 生成邀请令牌，邮件下发） |
| `POST /api/v1/invitations/accept` | 接受邀请并加入组织 |

角色矩阵：`owner` > `admin` > `member`。共享地址簿写操作需要 `addressbook` 权限（owner/admin）；**列表地址簿只需组织成员身份**。

### 3.3 设备

| 端点 | 说明 |
|---|---|
| `GET /api/v1/orgs/{orgId}/devices` | 设备列表（含 `online` 判定、`last_seen_at`、心跳来源） |
| `DELETE .../devices/{deviceId}` | 删除设备 = 解绑 compat 客户端（admin）；客户端下次登录重新认领 |
| `POST .../devices/{deviceId}/heartbeat` | 管理端手动心跳（`source=api`，30s 窗口合并） |

### 3.4 地址簿

| 端点 | 说明 |
|---|---|
| `GET/POST .../address-books` | 列表（个人 + 共享）/ 创建（`personal` 或 `shared`） |
| `GET/PUT/DELETE .../address-books/{bookId}` | 详情 / 更新 / 删除 |
| `PUT .../address-books/{bookId}/peers` | **全量替换** peers（上限 2000；单 peer ≤64 tags；TagsJSON ≤2048 runes） |
| `PUT .../address-books/{bookId}/tags` | 全量替换 tags（上限 256；color 0..4294967295） |

语义要点：

- 替换是**最后写入者生效**；`revision` 随每次替换递增，仅供客户端同步对比，服务端不校验客户端提交的版本
- `peer_id` ≤64 runes 且请求内唯一；`alias/username/hostname` ≤128；`platform` ≤64
- color 越界（<0 或 >uint32）返回 400，不会被截断
- 审计：替换/创建/删除会产生审计条目（含 actor 与组织）

### 3.5 日志事件

| 端点 | 说明 |
|---|---|
| `GET .../log-events` | 采集到的事件（level/kind/source/device/时间过滤 + 分页） |

事件由采集器写入（见运维指南 §4），API 只读。

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

**设备认领语义**（重要）：

- 设备 `rustdesk_id` 首次登录时绑定提交的 `uuid`（`BoundUUID`）；之后不同 uuid 登录同一 id → 403 `device is already bound`（仅管理员删除设备行可解绑）
- uuid 非秘密且登录时不校验归属——这正是心跳必须按 `(uuid, device_id)` 双条件解析会话的原因
- `id` ≤ 64 字符、`uuid` ≤ 128 字符，超长直接 400（防止「绑定成功但会话建不出来」的死锁状态）

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

- 契约版本随 release 演进：v0.1.0（M0）→ v0.2.0（M1）→ v0.3.0（M2）
- **契约变更的 PR 必须同步更新本文档 §3/§4 与 `openapi.yaml`**，并保证 `go generate` 零漂移
- WEB/APP 从 `openapi.yaml` 生成类型：任何字段/形状变更视为 breaking，需在 PR 描述中标注
