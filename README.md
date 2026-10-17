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

Go 1.27 · Gin · GORM（M1 引入）· Viper · zap · Testify · OpenAPI 3.1 + oapi-codegen + Swagger UI · OpenTelemetry + Prometheus

## 开发约定

- 分支流：`feature/*` → `develop` → `main`；`develop`/`main` 禁止日常直推（唯一例外：本仓库 bootstrap 首提交）
- 提交信息使用 Conventional Commits（英文）；代码注释英文，文档中文
- 命令一律在 Git Bash 中执行，路径使用 POSIX 形式

## 本地运行

```bash
# 安装依赖
go mod download

# 生成 OpenAPI 代码
make generate

# 测试
make test

# 启动（默认 :8080）
make run
```

## 目录结构

```
cmd/server/          # 进程入口
internal/config/     # Viper 配置加载
internal/logger/     # zap 日志构建
internal/server/     # Gin 路由与处理器
configs/             # 配置样例
openapi.yaml         # OpenAPI 3.1 契约（唯一事实源）
gen/                 # oapi-codegen 生成产物（提交入库）
```

## 许可

私有项目，保留所有权利（见 `LICENSE`）。
