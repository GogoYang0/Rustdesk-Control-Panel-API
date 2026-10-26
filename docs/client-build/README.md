# 自定义客户端构建仓库模板

这个目录要复制到**部署方自己的私有仓库**，配合控制面板的「自定义客户端生成器」使用。面板负责品牌 profile、服务器推导、构建记录与产物存储；本仓库只负责在 GitHub Actions 上把固定版本的 RustDesk 编译成带品牌、指向本组织服务器的安装包。

模板锁定 RustDesk **v1.5.0**（commit `fada664df7a294d1d1a9ca3e7cd3637069122f17`），不接受任意源码 ref。平台与产物：

| platform | runner | 产物 |
|---|---|---|
| `windows-x64` | `windows-2022` | 安装 exe + 便携 zip |
| `linux-x64` | `ubuntu-24.04` | AppImage |
| `macos-arm64` | `macos-15` | dmg |
| `macos-x64` | `macos-15-intel` | dmg |
| `android-arm64` | `ubuntu-24.04` | APK（固定 debug key） |

5a **不签名**：Windows/macOS 包未签名，macOS arm64 只有工具链要求的 ad-hoc 签名，Android 使用固定 debug keystore。不要把这些包当作生产签名分发。

## 1. 创建私有构建仓库

1. 新建一个私有仓库（例如 `acme/rustdesk-client-build`）。
2. 把 `workflow.yml` 复制为 `.github/workflows/build-client.yml`。
3. 把 `prepare_source.py` 放在仓库根目录。
4. 把默认分支设为 `main`（与面板 `clientbuild.github.ref` 一致）。
5. 提交。不要在这个仓库放面板 token、bundle key 或签名证书。

## 2. 生成 GitHub PAT

使用 fine-grained personal access token，仅授权该构建仓库：

- `Actions: Read and write`
- `Metadata: Read`

把 token 只放进面板环境变量 `PANEL_CLIENTBUILD_GITHUB_TOKEN`，不要写进配置文件或提交到任何仓库。

## 3. 配置面板

面板配置示例（`configs/config.yaml` 的 `clientbuild` 段）：

```yaml
clientbuild:
  enabled: true
  publicBaseURL: "https://panel.example.com"
  github:
    repo: "acme/rustdesk-client-build"
    workflow: "build-client.yml"
    ref: "main"
```

`publicBaseURL` 同时是生成客户端的 **API server**，必须指向面板的 compat 入口（`https://<面板域名>`，反向代理终止 TLS）；它也是 runner 下载 bundle 的地址。bundle key 只从 `PANEL_CLIENTBUILD_BUNDLE_KEY` 注入，至少 32 字节。

## 4. 面板公网可达

GitHub 托管 runner 必须能访问 `publicBaseURL`：

- 面板使用公网 HTTPS（推荐，和 compat API 同一个入口）；
- 或改用自建 runner，把 `runs-on` 改成自建标签，并保证 runner 能访问面板。

`clientbuild.enabled=true` 只表示配置完整，不代表网络可达；第一次 smoke 必须验证 bundle 下载。

## 5. 手工 smoke 验收

1. 面板建 profile、上传 256–1024 PNG Logo。
2. 选择 5 个平台发起构建，状态从 `dispatched` 走到 `succeeded`。
3. 下载 6 个文件（Windows exe+zip、macOS 两个 dmg、Linux AppImage、Android APK），用面板返回的 SHA-256 校验。
4. Windows 安装 exe、macOS 打开 dmg、Linux 运行 AppImage、Android 安装 APK；确认应用名/Logo 生效，客户端连上本组织 hbbs/hbbr。
5. 确认面板能看到该设备心跳，分配一个 Strategy 并确认客户端收到。
6. 用同一 profile 再构建一次，确认 Android APK 能覆盖安装（固定 debug key）。
7. 确认 GitHub 端 artifacts 已删除、面板审计有 `succeeded`/`bundle served`/`artifact download`。

## 6. 失败排查

- **run 找不到**：面板用 `run-name: panel-client-<buildId>` 关联；不要手工 rerun 同一 workflow，重新发起构建。
- **bundle 下载失败**：检查面板公网 HTTPS、反向代理、`publicBaseURL` 和 token TTL（24h）。
- **artifact 名称不匹配**：工作流必须上传 `panel-client-<buildId>-<platform>`，zip 根目录直接放 `panel-client-<buildId>-<platform>[.ext]`。
- **Windows SmartScreen / macOS Gatekeeper / Android 未知来源**：5a 不签名，属于预期；不要把它当作构建失败。
- **Android 覆盖安装失败**：确认 `ANDROID_DEBUG_KEYSTORE_BASE64` 没有变化（见第 9 节）。

## 7. 模板升级与轮换

- 升级 RustDesk：修改 workflow 的 `RUSTDESK_COMMIT`/`RUSTDESK_VERSION` 和 `prepare_source.py` 的锚点断言，跑一次 5 平台 smoke，再更新面板 `rustdeskVersion`。
- 轮换 PAT：在 GitHub 重新生成，只更新面板 `PANEL_CLIENTBUILD_GITHUB_TOKEN`，重启面板。
- 轮换 bundle key：更新 `PANEL_CLIENTBUILD_BUNDLE_KEY`，旧 bundle URL 立即失效；重新构建即可。

## 8. 安装身份 / 共存

生成客户端沿用上游安装身份（macOS bundle identifier、Android `applicationId`、Windows 服务/安装身份），会**替换/升级**同机上的官方 RustDesk 或其他生成包，不会与它们共存。安装前关闭/卸载现有 RustDesk 服务；5a 不支持并行安装。

## 9. 更新行为与 Android debug keystore

应用名不是 `RustDesk` 时，上游 `is_custom_client()` 会关闭官方更新检查；5a 不提供自建更新通道。升级方式是重新构建并手动覆盖安装。

Android 使用**固定的 debug keystore**，否则每次构建签名不同、无法覆盖安装。一次性生成并保存为仓库 secret `ANDROID_DEBUG_KEYSTORE_BASE64`：

```bash
keytool -genkeypair -v -keystore debug.keystore \
  -storepass android -keypass android \
  -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Android Debug,O=Android,C=US"
base64 -w0 debug.keystore > debug.keystore.b64
# 把 debug.keystore.b64 的内容保存为 ANDROID_DEBUG_KEYSTORE_BASE64
```

这是非生产调试身份；keystore 丢失后已安装的 APK 只能卸载重装。不要把它替换成生产签名密钥。

## 10. 品牌替换边界

5a 替换应用名、窗口标题、图标/Logo、可执行文件名等主要品牌位置；上游其它 “RustDesk” 文案不保证全量替换，验收时按这个边界判断。

## 11. 许可证

RustDesk 是 AGPL-3.0。对外分发生成的客户端时，部署方需按 AGPL 提供对应源码（含本模板的 patch）与许可证文本；面板不代做源码分发。

---

模板的平台命令以 RustDesk v1.5.0 官方 `flutter-build.yml` 为基线裁剪；如果上游工具链或 AppImage 配方变化，以第一次 smoke 的结果校准模板，再更新本 README。
