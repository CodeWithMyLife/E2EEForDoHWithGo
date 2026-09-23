# fastime

本地加密中继，双协议入口：

- **GET 进** `/​?dns=X` → 加密 X → base64url → **GET 出** `<上游>?time=<加密帧>`
- **POST 进**（body 原样）→ 加密 body → **POST 出** `<上游>`（body=加密帧）

响应统一逐帧解密、流式回写、写入 LRU 缓存。纯内存，无数据库。

## 产物一览（GitHub Actions 自动构建）

| 产物 | 平台 | 形态 |
|---|---|---|
| `fastime-windows-amd64.exe` / `-arm64.exe` | Windows | 控制台程序 |
| `fastime-macos-app` | macOS | `.app` 包（universal2，双击运行，LSUIElement 无 Dock 图标） |
| `fastime-darwin-*` | macOS | CLI |
| `fastime-linux-amd64` / `-arm64` | Linux | CLI |
| `fastime-android-arm64` | Android | CLI（Termux） |
| `fastime-android.apk` | Android | APK：前台服务 + WakeLock + 看门狗常驻（免 root） |
| `fastime-magisk.zip` | Android（root） | Magisk 模块：开机 root 自启，不受 Doze/省电策略影响 |
| `fastime-ios.ipa` | iOS | IPA：gomobile 框架 + 静音音频保活（未签名，需侧载） |

## 运行逻辑

```
客户端                本机 fastime                    上游服务器
  │  GET /?dns=X          │                                  │
  │  或 POST (body=X)     │                                  │
  │──────────────────────>│                                  │
  │                       │ 缓存命中且保鲜？                  │
  │                       │ ├─ 是 → 直接返回（零网络耗电）     │
  │                       │ └─ 过期 → 返回旧值 + 后台刷新      │
  │                       │ 缓存未命中：                      │
  │                       │  AES-128-GCM 加密 X               │
  │                       │  [单飞: 并发同请求共享一次往返]    │
  │                       │  [闸门: 同时在飞上游请求 ≤ 32]     │
  │                       │  DoT(223.5.5.5:853) 解析上游 IP    │
  │                       │  多 IP 竞速拨号，记最快            │
  │                       │  HTTP/2 多路复用，                 │
  │                       │  上游支持则升级 HTTP/3(QUIC)       │
  │                       │  GET:  ?time=base64url(帧) ──────>│
  │                       │  POST: body=帧 + 自定义头 ───────>│
  │                       │                                  │ 解密处理
  │                       │<────────── 加密响应帧流 ──────────│
  │  <── 逐帧解密即时推送  │  （同时写入 LRU 缓存）             │
  │<──────────────────────│                                  │

缓存键 = HTTP方法 + 负载（GET 与 POST 同内容互不串缓存）

缓存语义：LRU 负责淘汰（无 TTL 过期删除），TTL 只是"静默期"
  ≤10s 命中 → 直接返回，零网络
  >10s 命中 → 照样返回缓存，同时后台刷新该条

网络切换（接口指纹 2s 轮询 + 移动端系统回调）：
  → 必做：清 DNS 缓存 / 最快IP记忆 / H3状态，关闭旧连接重建
  → refresh 模式：缓存保留可用，所有已缓存条目逐条强制刷新（间隔100ms防射频爆冲）
  → clear 模式：缓存一并清空
```

## 帧格式（服务端需一致）

```
请求-GET (time= 参数, 紧凑帧):  [12B nonce][密文 + 16B tag]  → base64url 无填充
请求-POST (body, 标准帧):       [u32be 长度][12B nonce][密文 + 16B tag]
响应 (帧流, 可多帧拼接):         [u32be 长度][12B nonce][密文 + 16B tag]...
```

GET 紧凑帧比标准帧省 4 字节（URL 参数定长，长度头冗余）；base64url 体积 +33%，
1KB 负载约 1.4KB，远低于 URL 长度限制。

GET 时帧整体做 **base64url 无填充**编码放进 `time=` 参数：
使用 `-_` 替代 `+/`、去掉 `=` 填充，彻底规避 URL 转义与中间设备截断问题；
服务端用 urlsafe 解码并自行补齐 `=` 即可（示例见 workers/crypto.js）。

## GitHub Secrets

| Secret | 说明 | 示例 |
|---|---|---|
| `LISTEN_PORT` | 本地监听端口 | `8080` |
| `UPSTREAM_URL` | 上游地址 | `https://api.example.com` |
| `UPSTREAM_PATH` | 上游路径 | `/gateway` |
| `ENC_KEY_B64` | base64 的 16 字节 AES-128 密钥 | `openssl rand 16 \| base64` |
| `CACHE_SIZE` | LRU 缓存条数（满时优先淘汰最久未用） | `128` |
| `CACHE_TTL_SEC` | 静默期秒数（默认 10）：期内命中零网络；过期仍返回缓存，后台同步刷新 | `10` |
| `NET_SWITCH_MODE` | 切网缓存策略：`refresh`（默认，保留缓存+强制逐条刷新）或 `clear`（清空） | `refresh` |
| `REQUEST_TIMEOUT_SEC` | 上游请求超时秒数 | `10` |
| `LOG_LEVEL` | 日志等级：`debug`（详细）/ `info` / `error`（仅错误） | `info` |
| `DIAL_MODE` | 拨号模式：`race`（默认，多 IP 竞速选最快）或 `single`（单 IP 直连，最省资源） | `race` |
| `PREFER_QUIC` | `true` 时首次请求直连 QUIC（有票据即 0-RTT），失败记黑名单 5 分钟并回退 h2 | `false` |

## 双版本构建

| 版本 | 体积 | 说明 |
|---|---|---|
| 完整版 | ~7.4MB | 含 HTTP/3(QUIC) + 0-RTT |
| lite 版（`-tags noquic`） | ~5.8MB | 无 HTTP/3，仅 h1/h2；上游不支持 QUIC 时选它 |

体积大头是 TLS/x509 与 Go runtime（刚需）。剩余可选：UPX 壳压缩（仅 Win/Linux，
约再省 60% 磁盘，但 Windows 上可能触发杀软误报，默认不开）。

## 移动端效能设计清单

射频唤醒 ≫ 握手 ≫ 字节数 ≫ CPU。全部杠杆已落地：

| 层 | 措施 |
|---|---|
| 请求 | 缓存静默期零网络；单飞去重；并发闸门削峰 |
| 连接 | h2 多路复用；QUIC 0-RTT + PREFER_QUIC 冷启动直连；空闲 10s 释放；关保活 ping |
| 拨号 | 最快 IP 记忆 10min 直达；DoT 结果缓存 5min |
| CPU | AES 硬件加速；sync.Pool 缓冲池；移动端堆上限 48MB 防 OOM 被杀 |
| 本地监听 | 回环网卡零射频成本，keep-alive 默认开启——此处无优化空间，不必加 h2c |

## 日志

同时输出到标准输出和程序工作目录下的 `fastime.log`（追加写入）。
`debug` 级含每次请求的缓存判定、拨号过程、上游耗时；`error` 级只记错误。
| `CUSTOM_HEADERS` | 发往上游的自定义请求头，**单行无空格 JSON**；设置后不发送任何默认头（含 User-Agent） | `{"X-Auth":"abc"}` |
| `DOT_SERVER` | DoT 服务器 | `223.5.5.5:853` |

> CUSTOM_HEADERS 的值内不要含空格、`$`、反引号（构建期 shell 展开限制）。

## 各端使用

- **Windows**：双击 exe 或命令行运行；开机自启可用任务计划程序
- **macOS**：`tar xzf Fastime-macos.app.tar.gz` 后把 `Fastime.app` 拖入"登录项"；未签名，首次运行需在 设置→隐私与安全性 中允许
- **Android APK（免 root）**：安装后点一次图标；**必须**在系统电池设置里设为"无限制"+ 允许自启动（国产 ROM）
- **Android Magisk（已 root）**：Magisk → 模块 → 从本地安装 `fastime-magisk.zip` → 重启即运行。日志在 `/data/adb/modules/fastime/fastime.log`。也可不装模块直接 `su -c ./fastime-android-arm64` 手动跑
- **iOS IPA**：未签名包，用 TrollStore / AltStore / Sideloadly 侧载；audio 后台模式 + 静音循环保活
- **CLI 通用**：运行时可用同名环境变量覆盖内置值调试

## 高并发能耗设计

| 手段 | 作用 |
|---|---|
| 单飞（singleflight） | 相同请求的并发调用只打一次上游，跟随者共享结果 |
| 并发闸门（≤32 在飞） | 防止突发流量瞬间打满射频与 CPU，排队削峰 |
| `sync.Pool` 帧缓冲池 | 加密缓冲区复用，降低 GC 压力与 CPU 能耗 |
| HTTP/2 多路复用 | 所有并发请求共享一条 TLS 连接，射频只唤醒一次 |
| HTTP/3(QUIC) 自动升级 | 弱网更快完成传输 = 射频工作时间更短 |
| QUIC 0-RTT + TLS1.3 会话恢复 | 重连首个数据包即携带请求；TCP 侧 PSK 恢复免完整握手 |
| QUIC 保活 ping 关闭 | 周期 ping 会持续唤醒射频，改为空闲超时 + 0-RTT 秒级重建 |
| 空闲连接 10s 释放 | TCP/QUIC 同策略：射频尽快回休眠，重建成本已被 0-RTT/会话恢复压到极低 |
| GET 紧凑帧 | time= 参数省略 4B 长度头，每请求少 6 个 base64 字符 |
| HPACK/QPACK 头部压缩 | h2/h3 原生，重复请求头（如自定义鉴权头）后续只传索引 |
| 缓存保鲜期 TTL | 期内命中零网络，移动端省电最关键的一环 |

> 0-RTT 理论上可被重放。本程序请求为幂等查询且 body 加密，风险可接受。

## Cloudflare Workers 上游

`workers/crypto.js` 提供与 Go 端逐字节互通的 WebCrypto 实现（零依赖）：
`encryptFrame` / `decryptFrames` / `encryptStream` / `b64urlEncode` / `b64urlDecode`，
以及一个完整的双协议 Worker 示例。已实测与 Go/Python 端加密结果互通。

## 本轮代码审查结论（已修复/已确认）

| 项 | 状态 | 说明 |
|---|---|---|
| 并发相同请求返回空响应 | ✅ 已修 | 改为单飞等待：后来者共享领导者结果 |
| 缓存每次命中都刷新 | ✅ 已修 | 新增 CACHE_TTL_SEC 保鲜期，期内零网络 |
| 竞速拨号失败时报错信息误导 | ✅ 已修 | 返回真实 lastErr |
| LRU 淘汰策略 | ✅ 确认 | 本就是"优先删最久未使用" |
| 密钥内嵌二进制 | ⚠️ 已知 | 拿到二进制即可提取密钥，勿分发给不可信者 |
| APK 未签名 | ⚠️ 已知 | CI 产出 unsigned release 包，安装前需自行签名（apksigner）或改 assembleDebug |
| iOS 真后台 | ⚠️ 平台限制 | iOS 无官方常驻后台，静音音频方案仅适合侧载，App Store 会被拒 |
| TLS 1.1 + RSA 密钥交换老套件 | ⚠️ 已知 | Go 1.22+ 需 `GODEBUG=tlsrsakex=1` |
| QUIC 依赖 UDP 443 | ✅ 已处理 | 被封时自动回退 HTTP/2 |

## 你可能没想到的点

1. **缓存没有持久化**——进程重启缓存即失，纯内存是需求但也是限制；如需要可加启动时预热接口
2. **请求超时**：上游慢时客户端会一直挂着，建议自行在前端设超时
3. **多实例**：同一端口只能跑一个实例，APK 与 CLI 不要同时启动
4. **日志**：Go 进程日志在 APK 中通过 logcat 可见（`adb logcat | grep fastime`）
