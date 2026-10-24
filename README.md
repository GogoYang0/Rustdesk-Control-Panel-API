# Rustdesk-Control-Panel-API

Rustdesk-Control-Panel 系列的控制平面 API 服务（Go + Gin）。

本仓库是三个独立仓库中的 API 端，持有 **OpenAPI 3.1 契约**（`openapi.yaml`），WEB 与 APP 的客户端类型均由该契约生成。

## 系列仓库

| 仓库 | 说明 |
|---|---|
| `Rustdesk-Control-Panel-API` | 控制平面 API（本仓库），契约事实源 |
| `Rustdesk-Control-Panel-WEB` | Web 管理台（React 19.3） |
| `Rustdesk-Control-Panel-APP` | 移动管理端（Expo SDK 57 / RN 0.86，仅 Android） |

## 技术栈

Go 1.27 · Gin · GORM（SQLite / MySQL / PostgreSQL）· Viper · zap · Testify · OpenAPI 3.1 + oapi-codegen

## 能力概览

- **多租户**：组织 / 成员 / 角色；租户条件由 GORM 插件统一注入，缺上下文时 fail-closed（`WHERE 1 = 0`）。
- **认证**：邮箱验证闭环（未验证不可登录）、邀请与邀请码、刷新令牌轮换、登录限流与锁定。
- **设备**：登记（RustDesk ID 指纹 upsert）、分页列表与改绑（`rebind`，绑定代数 +1 并审计）、客户端心跳、在线判定窗口。
- **供应**：以 `docker` CLI 编排每组织的 hbbs/hbbr 容器（端口池、异步队列、补偿扫描）；支持按组织开关（`GET/PUT /orgs/{orgId}/provisioning`）、启动端口探测与部署前预检。
- **会话治理**：连接票据（面板发起）、连接策略（并发/时长/时段/事前审批）、panel+native 会话记录、审批中心与违规告警（M3/v0.4.0）。
- **审计**：领域事件与调用方事务同事务写入（`audit.TxRecorder`），中间件兜底。
- **RustDesk 客户端兼容层**：`/api/*` 方言（登录 / 会话 / 心跳 / 设备列表 / 地址簿），让原生客户端把本面板当作 API 服务器。
- **日志采集**：跟随 hbbs/hbbr 容器日志，按配置规则解析为租户隔离的 `LogEvent`；连接类日志同时作为设备心跳的辅助源。

管理 API 全部挂在 `/api/v1/*`，以 `openapi.yaml` 为唯一事实源；兼容层挂在 `/api/*`，使用独立的会话令牌（`typ=compat`），与管理 JWT 互不覆盖。

## 开发约定

- 分支流：`feature/*`（或 `docs/*`）→ `develop` → `main`；`develop`/`main` 禁止日常直推。
- 提交信息使用 Conventional Commits（英文）；代码注释英文，文档中文。
- 命令一律在 Git Bash 中执行，路径使用 POSIX 形式。
- 提交与标签必须用 SSH 密钥签名（GitHub 显示 Verified）。
- 改动契约后必须 `make generate` 并提交 `gen/`，不得留下漂移。

## 本地运行

```bash
# 安装依赖
go mod download

# 生成 OpenAPI 代码
make generate

# 测试
make test

# 设置签名密钥（不要提交真实密钥；至少 32 字节）
export PANEL_AUTH_SECRET=$(openssl rand -base64 48)

# 启动（默认 :8080）
make run
```

默认配置使用 SQLite（`data/panel.db`）；`mail.devMode` 打开时邮件写标准输出、不实际投递，可直接在本地跑通注册 → 验证 → 登录。

## 环境变量

配置值来自 `configs/config.yaml` 与环境变量，敏感项只从环境注入。

| 变量 | 必填 | 说明 |
|---|---|---|
| `PANEL_AUTH_SECRET` | 是 | 访问/刷新令牌签名密钥，至少 32 字节；缺失则启动失败 |
| `PANEL_SMTP_PASSWORD` | 视配置 | `mail.devMode=false` 且 `mail.smtp.username` 非空时必须提供；缺失则启动失败（避免用空密码发起 AUTH）。`devMode=true` 时不读取该变量 |
| `PANEL_WEB_BASE_URL` | 生产建议 | 覆盖 `web.baseURL`：验证邮件与邀请链接的前端源。`mail.devMode=false` 时必须是 **https 公共源**（拒绝 localhost 与私有 IP），否则启动失败 |

## 配置要点

`configs/config.yaml` 是带注释的样例，以下几点容易踩：

- **`provision.relayHost`**：客户端可访问的地址，没有回环兜底；`provision.image` 必须钉住 tag 以保证可复现。
- **`provision.portStart` / `portEnd`**：每组织 hbbs/hbbr 的端口池范围。
- **`compat.accessTTL`**：兼容层会话有效期，默认 `720h`（原生客户端按长期会话设计）。
- **`web.baseURL`**：见上表；邮件里嵌的是明文令牌，源不可达等于把链接发进了死路。
- **`logcollect`**：默认关闭，见下节。

## 客户端接入（RustDesk 原生客户端）

把客户端的 **API 服务器**地址指向本面板（`https://<panel-host>`，或内网 http 地址），然后用面板账号在客户端登录。客户端会访问：

| 端点 | 说明 |
|---|---|
| `POST /api/login` | 账号密码登录，返回兼容层会话令牌 |
| `GET /api/login-options` | 登录方式探测 |
| `POST /api/logout` | 注销（撤销当前会话 jti） |
| `POST /api/currentUser` | 当前用户信息 |
| `GET /api/peers` | 该用户的设备列表 |
| `POST /api/heartbeat`、`POST /api/sysinfo` | 客户端上报（**不带 Bearer**，官方协议如此） |
| `/api/ab`、`/api/ab/get`、`/api/ab/personal` | 地址簿：legacy 整本读写（`data` 为内嵌 JSON 字符串） |
| `/api/ab/peers`、`/api/ab/tags/:guid`、`/api/ab/peer/*`、`/api/ab/tag/*` | 地址簿：granular 分页方言（1.4+ 客户端） |

两点需要知道：

- **兼容层只提供个人地址簿**。共享地址簿返回 404（personal-only），避免跨用户数据被客户端方言意外读写。
- **心跳与 sysinfo 的归属是推断的**：协议里这两个请求不带凭据，服务端用请求中的 `uuid` 找到一个**活跃会话**，并要求请求的 `id` 与该会话登录时绑定的设备一致，才刷新心跳。也就是说，这条路径不需要调用者自己持有账号，前置条件只是「存在匹配该 `uuid` 的活跃会话 + 设备 ID 对得上」——`uuid` 是稳定的硬件标识，不是秘密。这是协议限制，影响面收敛为「仅能刷新已绑定设备的 `last_seen_at`」。

## 日志采集

跟随每个已供应组织的 hbbs/hbbr 容器日志，解析为 `LogEvent` 并按租户隔离存储。

```yaml
logcollect:
  enabled: true                # 默认 false
  containerPrefix: "panel-org" # 容器名 <prefix>-<orgID>-hbbs / -hbbr
  rules:
    - name: connection
      pattern: '^\[[^\]]+\]\s+INFO\s+\[[^\]]+\]\s+.*?(?P<device>\d{6,12})'
      level: info
      kind: conn
```

行为说明：

- 走 `docker logs -f -t`，容器的 stdout 与 stderr **两个流都读**：Docker 把它们分开存放，而 CLI 自身的诊断也写 stderr，只读一个流会静默丢掉另一半。
- 首次连接只跟随新日志（`--tail 0`），**不回填历史**——面板不是日志归档系统。重连从最后观测时间戳继续（`+1ns`，因为 docker 的 `--since` 是闭区间）。
- 规则按顺序匹配，首个命中生效；命名捕获组进入事件 `detail`，特殊组 `device` 提取 RustDesk ID 用于设备关联。未匹配行只计数、不中断采集；规则配错会每分钟告警一次。
- 容器重启时按 5s → 60s 指数退避重连；组织下线时其 tailer 立即退场。
- 事件保留 30 天；保留期清扫默认每 6h 且启动时执行一次（`logcollect.retentionSweepInterval` 设为 0 可禁用清扫）。
- 连接类日志会顺带刷新设备心跳（`DeviceHeartbeat.Source = "log"`，与客户端上报的 `"api"` 区分），同一设备 30 秒内只记一次。

`configs/config.yaml` 内置的规则与 `rustdesk/rustdesk-server:1.1.11` 的 `flexi_logger::opt_format` 对齐（`[时间戳] 级别 [源文件:行] 消息`，注意级别在第一个方括号**之外**、时间戳本身含空格），并有测试加载该文件、用该格式的样例行验证；换成其他镜像时请按 `docker logs -t <container>` 的真实输出校准。

## 目录结构

```
cmd/server/          # 进程入口（配置加载、依赖装配、优雅关闭）
internal/api/        # 管理 API 处理器与中间件（审计、JWT）
internal/compatapi/  # RustDesk 客户端兼容层（/api/*）
internal/auth/       # 令牌签发与校验（管理 JWT 与兼容层会话两族）
internal/authz/      # 角色与成员校验
internal/addressbook/# 地址簿（个人簿、修订号、冲突检测）
internal/device/     # 设备登记、心跳、在线判定
internal/provision/  # hbbs/hbbr 容器编排、端口池、异步队列
internal/session/    # 会话治理（票据、策略、审批、告警、native 会话追踪）
internal/logcollect/ # 日志采集（解析器、tailer、服务）
internal/audit/      # 审计记录（事务内写入）
internal/mail/       # 邮件投递（devMode / SMTP）
internal/limit/      # 登录限流与锁定
internal/logger/     # zap 日志初始化
internal/model/      # 数据模型（租户注册表）
internal/store/      # 打开数据库、租户作用域助手与插件
internal/worker/     # 周期任务调度（panic 隔离、系统审计）
configs/             # 配置样例
openapi.yaml         # OpenAPI 3.1 契约（唯一事实源）
gen/                 # oapi-codegen 生成产物（提交入库）
```

## 测试与 CI

- `make test`：`go test -race ./...`（需要 cgo 与 C 编译器；纯 Linux/macOS 环境开箱可用）。
- CI 另跑 MySQL/PostgreSQL 矩阵、`golangci-lint`、`govulncheck`、CodeQL、spectral 契约校验，以及 `go generate` 后的零漂移检查。
- 租户隔离有独立回归：`internal/store/scopetest` 对每个已注册模型验证作用域注入，并覆盖「作用域必须最后链」这一顺序陷阱。

## 许可

私有项目，保留所有权利（见 `LICENSE`）。

## 文档

- [部署指南](docs/deployment.md)：系统要求、配置全表、数据库与迁移、邮件与日志采集启用清单、上线安全清单
- [运维指南](docs/operations.md)：设备与心跳、审计巡检、日志采集运维、供应对账、备份恢复、故障排查速查
- [后端 API 规范](docs/api-spec.md)：两族认证、管理端点语义、compat 协议边界、错误码与冲突语义

三份文档必须**边做边总结、沉淀、更新**：

- 契约变更 → 同步 `docs/api-spec.md` 与 `openapi.yaml`；
- 配置或部署面变更 → 更新 `docs/deployment.md`；
- 运维语义（心跳、采集、审计、备份）变更 → 更新 `docs/operations.md`；
- 每个 release PR 合并前复核三份文档一遍。
