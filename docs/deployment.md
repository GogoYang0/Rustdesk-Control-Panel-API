# 部署指南（Deployment Guide）

> 适用版本：v0.3.0（M2）。本文档随版本演进持续更新——每次发布前必须复核一遍。
> 配套文档：[运维指南](operations.md) · [后端 API 规范](api-spec.md)

---

## 1. 系统要求

| 项 | 要求 | 说明 |
|---|---|---|
| 操作系统 | Linux（推荐）或 Windows | panel 本身是单一 Go 二进制 |
| Go | 1.27+ | 仅构建时需要；发布产物为静态二进制 |
| Docker | 20.10+；**生产使用 rootless Docker 或受限的 Docker socket proxy**（见 §8） | 使用 provisioning 功能时需要（provisioning 无独立开关，始终启用）：panel 经 Docker CLI 操作容器，实际地址用 `DOCKER_HOST` 环境变量或 Docker CLI context 指定，**不要默认依赖 rootful 原始 socket** |
| 数据库 | SQLite（默认）/ PostgreSQL / MySQL | 生产建议 PostgreSQL |
| 端口 | `:8080`（panel API）、`21116–22115`（hbbs/hbbr，可配；逐端口协议分布见 §7——仅每组织的 `HbbsPort+1` 同时用 TCP+UDP，其余 TCP） | 反代后面只需暴露 panel 的 443 |

---

## 2. 构建

```bash
go build -o panel ./cmd/server
```

发布产物为单二进制；不依赖任何运行时。配置固定从工作目录下的 **`configs/config.yaml`** 读取（`config.Load("configs/config.yaml")`）——部署时保留 `configs/` 目录结构并按需修改，**不要拍平到工作目录**。

---

## 3. 配置全表

三个敏感项只从环境变量注入：

### 3.1 环境变量（敏感项，禁止写入配置文件）

| 变量 | 必须 | 说明 |
|---|---|---|
| `PANEL_AUTH_SECRET` | 是 | JWT 签名密钥。未设置时进程拒绝启动（`auth.secret must be configured`）。用 `openssl rand -base64 48` 生成；**泄漏等于任何人可伪造令牌** |
| `PANEL_SMTP_PASSWORD` | 条件 | `mail.devMode=false` 且设置了 `mail.smtp.username` 时必须；否则启动即失败 |
| `PANEL_WEB_BASE_URL` | 条件 | 覆盖 `web.baseURL`；`devMode=false` 时必须是公网 https origin，否则启动失败（验证码/邀请链接会嵌入此地址） |

### 3.2 配置节

| 节 | 键 | 默认 | 说明 |
|---|---|---|---|
| `server.addr` | | `:8080` | HTTP 监听地址 |
| `auth.accessTTL` / `auth.refreshTTL` | | `15m` / `168h` | 管理 JWT 的访问/刷新令牌有效期；刷新令牌轮换 + 重放撤销 |
| `database.driver` | | `sqlite` | `sqlite` \| `postgres` \| `mysql` |
| `database.dsn` | | `file::memory:?cache=shared` | **加载器默认是共享内存 SQLite（重启即失数据）**——生产必须显式设置持久化 DSN，如 `file:data/panel.db`；生产建议 PostgreSQL |
| `log.level` / `log.format` | | `info` / `json` | zap 结构化日志；`json` 便于采集 |
| `provision.portStart/End` | | `21116–22115` | 每组织占用**连续 5 个**主机端口（`PortBlockSize=5`，见 §7 协议分布）；默认范围最多支持 200 个组织 |
| `provision.relayHost` | | — | **必须是客户端可达的公网地址**，无回退 |
| `provision.orgLabel` / `provision.roleLabel` | | `com.rustdesk-panel.org` / `com.rustdesk-panel.role` | 容器标签键 |
| `provision.image` | | —（无加载器默认，未配置时供应失败） | 必须显式配置为 `rustdesk/rustdesk-server:1.1.11`；固定 tag 保证可复现；**日志采集规则按此镜像的日志格式编写**，换镜像必须重新校准 |
| `provision.dataDir` | | `./data/servergroups` | 各组织 hbbs/hbbr 的密钥与数据目录（挂载进容器） |
| `provision.maxOrgsPerUser` / `workers` | | `5` / `2` | 单用户组织上限 / 供应队列并发 |
| `mail.devMode` | | `true` | `true` 时邮件打印到 stdout（开发）；生产必须 `false` |
| `web.baseURL` | | `http://localhost:5173` | 前端 origin，用于构造邮件链接 |
| `logcollect.enabled` | | `false` | 日志采集总开关（见运维指南 §4） |
| `logcollect.containerPrefix` | | `panel-org` | 容器命名前缀，实际为 `panel-org-<orgId>-hbbs/hbbr` |
| `logcollect.rules` | | 内置 4 条 | 规则按序匹配、首条命中即停；命名捕获组 `device` 关联设备 |

---

## 4. 数据库与迁移

### 4.1 首次启动

启动序列（`cmd/server/main.go`）按以下顺序执行，任何一步失败都会 `Fatal` 退出：

1. 加载配置 → 构建 logger
2. 校验 `PANEL_AUTH_SECRET` → 打开数据库
3. **AutoMigrate** 全部模型（GORM 自动建表/加列）
4. **一次性回填**：`email_verified` 历史数据回填，成功后写迁移标记（MigrationMark）；已有标记则跳过
5. 校验邮件配置（`mail.devMode=false` 时的三项检查）
6. 启动后台 worker（日志采集 tailer、provision 队列、对账 reconciler）
7. 监听

### 4.2 升级

- 新版本新增列时 AutoMigrate 自动处理；**删除列/收窄列不会自动执行**（如 `Device.BoundUUID` 保持 255 的原因）
- **升级期间禁止并行启动实例**：回填会把当前所有未验证账户标为已验证——若另一实例在回填完成前启动并创建了新的未验证账户，该账户也会被误标为已验证，**绕过邮箱验证边界**。正确流程：先停止或隔离其他实例 → 启动一个实例完成回填并写入迁移标记 → 再启动其余实例
- 升级前备份 `panel.db`（或数据库快照）与 `data/servergroups/`

### 4.3 选择生产数据库

SQLite 的 `occurred_at` 等时间列按**文本比较**（UTC 格式化），行为已与 MySQL/PostgreSQL 对齐测试（`test-db` CI）。生产选 PostgreSQL：

```yaml
database:
  driver: postgres
  dsn: "host=127.0.0.1 user=panel password=... dbname=panel port=5432 sslmode=disable"
```

> ⚠️ 上面带 `sslmode=disable` 的片段**仅适用于 panel 与 PostgreSQL 同机的场景**。PostgreSQL 在其他主机时凭据与数据会明文传输（CWE-319），必须启用 TLS 校验：
> `sslmode=verify-full`（校验证书链与主机名），并提供 `sslrootcert=/path/to/ca.crt` 指向受信任 CA、确认 `host` 与证书 SAN 匹配。

---

## 5. 邮件投递

- `mail.devMode=true`：所有邮件写 stdout（开发/内网体验）
- 生产：`devMode=false` + 填 `mail.smtp.{host,port,username,from}` + 环境变量 `PANEL_SMTP_PASSWORD`
- 投递语义（运维含义见 [运维指南 §5](operations.md)）：
  - **非 465 端口**的服务器不支持 STARTTLS → 不发送（拒绝明文凭据）
  - **465 端口使用隐式 TLS**，不要求 STARTTLS（两种受支持形态）
  - 5xx 永久错误 → 不重试
  - 结果不明（连接中断）→ 保留验证码/令牌，可重发
- 验证码有效期与一次性语义见 [API 规范 §4.4](api-spec.md)

---

## 6. 日志采集启用清单

`logcollect.enabled=true` 前逐项确认：

1. panel 进程能访问 Docker（`docker ps` 可用）
2. `provision.image` 是 `rustdesk/rustdesk-server:1.1.11`（或已按其真实日志格式校准规则）
3. 用 `docker logs -t panel-org-<id>-hbbs` 抽样验证规则能匹配真实行（本地可跑 `TestExampleConfigRules_MatchServerFormat` 参照）
4. 首次连接只跟随新行（`--tail 0`），历史日志不会回灌——需要历史数据请在启用前导出
5. 启用后 30 天内的事件自动保留，超期在启动时清扫（见运维指南 §4）

---

## 7. 反向代理与 TLS

panel 自身只出 HTTP；对外必须经反向代理终止 TLS：

```nginx
server {
    listen 443 ssl;
    server_name panel.example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

- `web.baseURL`（或 `PANEL_WEB_BASE_URL`）必须是用户浏览器可达的 **https** 地址——邮件里的验证码/邀请链接指向它
- `provision.portStart..portEnd` 分配的主机端口需要直接暴露，不经反代。每个组织占用连续 5 个端口，协议分布不同：`HbbsPort`（TCP，nat-test）、`HbbsPort+1`（**TCP+UDP**，id registry/heartbeat）、`HbbsPort+2`（TCP，web client websocket）、`HbbrPort`（TCP，relay）、`HbbrPort+1`（TCP，web client relay ws）。默认端口从 21116 起、每组织连续 5 个——第一个组织就需要 `21116–21120`，**缺 21120 时第一个组织的 `HbbrPort+1` 即不可用**；完整放行范围以 `portStart..portEnd` 为准

---

## 8. 安全清单（上线前）

- [ ] `PANEL_AUTH_SECRET` 已轮换生成，且不在任何版本库/镜像层
- [ ] `mail.devMode=false`，SMTP 凭据走环境变量
- [ ] `web.baseURL` 是公网 https
- [ ] 数据库口令、`data/servergroups/`（含各组织密钥）权限已收紧
- [ ] **禁止直接挂载 rootful Docker 的原始 socket**（`/var/run/docker.sock`）：拿到它即可控制宿主机。生产环境使用 rootless Docker，或经由受限的 docker socket proxy（按需白名单 API）授予 panel 访问
- [ ] 审计表与 `panel.db` 的备份策略已建立（审计是安全证据，见运维指南 §7）

---

## 9. RustDesk 客户端接入

客户端「ID/中继服务器」指向该组织分配的 hbbs/hbbr 地址（provision 时按 `relayHost` + 分配端口生成）。客户端登录面板走 **compat 层**（协议与官方客户端一致）：

- 登录凭据 = 面板账号（邮箱 + 密码）+ 组织；首次登录会认领设备（rustdesk id + uuid 绑定）
- 换机器/重装后 uuid 变化会报 403「设备已绑定」。v0.3.0 **没有设备删除的管理面端点**（跟踪 [#43](https://github.com/GogoYang0/Rustdesk-Control-Panel-API/issues/43)），恢复需直接删除数据库中的设备行（临时流程）

详细协议见 [API 规范 §4](api-spec.md)。
