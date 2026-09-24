<div align="center">

# fastime

**本地加密 DNS 中继 · 全平台 · 移动端能耗优先**

AES-128-GCM 硬件加速 · HTTP/2 多路复用 · QUIC 0-RTT · DoT 拨号 · DNS 感知缓存

</div>

---

## 这是什么

运行在本机 `127.0.0.1` 的加密中继：接收本地 DNS 请求（HTTP），用 AES-128-GCM 加密后转发到上游（Cloudflare Workers），解密响应并流式返回。全程纯内存、无数据库、无磁盘状态（日志除外）。

```
客户端                   本机 fastime                     上游 Workers
  │  POST /e2e (DNS 报文)   │                                   │
  │  或 GET /e2e?dns=b64    │                                   │
  │────────────────────────>│ 缓存命中？                         │
  │                         │ ├─ 是 → 立即返回（期内零网络）      │
  │                         │ └─ 否 → 加密 ↓                    │
  │                         │   GET  <上游>?e2e=base64url(帧)    │
  │                         │   或 POST <上游> (body=加密帧)      │
  │                         │──────────────────────────────────>│
  │                         │<──────────────────────────────────│
  │<────────────────────────│ 逐帧解密 · 流式回写 · 写入缓存       │
```

## 功能一览

| 类别 | 特性 |
|---|---|
| 协议 | TLS 1.1/1.2/1.3 · HTTP/1.1 / HTTP/2 / HTTP/3（Alt-Svc 自动升级） |
| 本地入口 | `POST /e2e` 与 `GET /e2e?dns=`，同时支持 HTTP/1.1 与 **h2c**（q/dig 等 DoH 工具直连） |
| 状态页 | 浏览器访问 `http://127.0.0.1:端口/`：缓存条数、命中率、上游耗时、在飞请求，5s 自刷 |
| 拨号 | 自建 DoT（`223.5.5.5:853`）解析 + 全候选 IP **竞速**（250ms 错峰），胜出者记忆 **1 分钟** |
| 缓存 | DNS 感知键（域名小写+QTYPE+QCLASS+用户设置项，剔除随机 TID/Cookie）· 仅缓存上游 200 · 空响应不入缓存 · LRU 淘汰 |
| 省电 | 静默期（默认 10s）内命中**零网络**；过期返回缓存+后台刷新（stale-while-revalidate）；单飞去重；并发闸门 ≤32 |
| 切网 | 接口指纹 2s 轮询 + 移动端 OS 回调：清空缓存 **或** 保留+逐条强制刷新（可配），并重置拨号记忆 |
| 安全 | AES-128-GCM（AES-NI / ARM CE 硬件加速）· 每帧随机 nonce · 编译期密钥注入 · 可自定义/剥离全部请求头 |
| 日志 | debug / info / error 三级，stdout + `fastime.log` 双写 |

## GitHub Secrets（编译期注入）

仓库 → Settings → Secrets and variables → Actions：

| Secret | 作用 | 示例 |
|---|---|---|
| `LISTEN_PORT` | 本地监听端口 | `80` |
| `UPSTREAM_URL` | 上游地址（不含路径） | `https://xxx.workers.dev` |
| `UPSTREAM_PATH` | 上游路径 | `/e2e` |
| `ENC_KEY_B64` | AES-128 密钥，16 字节 base64 | `openssl rand 16 \| base64` |
| `CACHE_SIZE` | 缓存条数上限（LRU） | `512` |
| `CACHE_TTL_SEC` | 静默期秒数：期内命中零网络，过期后台刷新 | `10` |
| `DOT_SERVER` | DoT 服务器 | `223.5.5.5:853` |
| `CUSTOM_HEADERS` | 自定义请求头（纯 JSON；设置后不发送任何默认头含 UA） | `{"X-Auth":"abc"}` |
| `NET_SWITCH_MODE` | 切网策略：`refresh` 保留+强制刷新 / `clear` 清空 | `refresh` |
| `REQUEST_TIMEOUT_SEC` | 上游超时（秒） | `10` |
| `LOG_LEVEL` | 默认日志等级 | `info` |
| `DIAL_MODE` | `race` 竞速 / `single` 单 IP 直连 | `race` |
| `PREFER_QUIC` | `true` 时首请求直连 QUIC（0-RTT），失败回退 h2 | `false` |

> 上游最终地址 = `UPSTREAM_URL` + `UPSTREAM_PATH`。
> `CUSTOM_HEADERS` 无需手动 base64——CI 构建时自动编码，引号不会被 shell 吃掉。

## 运行方式

### 通用 CLI（Windows / macOS / Linux / Android-Termux）

```bash
# 直接运行（前台）
./fastime-linux-amd64

# 运行时覆盖日志等级（优先级：命令行 > 环境变量 > 编译值）
./fastime-linux-amd64 -log debug

# 环境变量临时覆盖任意编译参数（调试用）
LISTEN_PORT=8080 LOG_LEVEL=debug ./fastime-linux-amd64
```

### Windows

下载 `fastime-windows-amd64-bundle.zip`，解压后：

- `start-fastime.bat` —— 双击启动，窗口保持，报错可见
- `stop-fastime.bat` —— 双击停止（带成功/失败提示）
- 开机自启：任务计划程序添加 exe 即可

### macOS（.app）

```bash
tar xzf Fastime-macos.app.tar.gz
xattr -dr com.apple.quarantine Fastime.app   # 去掉下载隔离标记
open Fastime.app                              # LSUIElement：无 Dock 图标，后台运行
```

日志在 `~/fastime.log`。可拖入"系统设置 → 登录项"实现开机自启。

### Android APK（免 root）

安装后点一次图标：前台服务 + WakeLock + 看门狗常驻，界面显示服务状态与最近日志。
**国产 ROM 必须**：电池优化设为"无限制" + 允许自启动。

### Android Magisk（已 root）

刷入 `fastime-magisk.zip`（**纯安装，不开机自启**），手动控制：

```sh
sh /data/adb/modules/fastime/start.sh   # 启动（带成功/失败输出）
sh /data/adb/modules/fastime/stop.sh    # 停止
tail -f /data/adb/modules/fastime/fastime.log
```

### iOS IPA（未签名，需侧载）

TrollStore / AltStore / Sideloadly 安装。静音音频 + BGTask 保活。iOS 无官方真后台，此为平台限制下的最优方案。

### 构建产物一览

| 产物 | 说明 |
|---|---|
| `fastime-{windows,linux,darwin}-{amd64,arm64}` | 全量 CLI（含 HTTP/3），~7.4MB |
| `…-lite` | 精简版（`-tags noquic`），~5.8MB，上游不支持 QUIC 时选它 |
| `fastime-windows-*-bundle.zip` | exe + 启动/停止 bat |
| `Fastime-macos.app.tar.gz` | universal2 .app（ad-hoc 签名） |
| `fastime-android.apk` | 未签名 release 包（需自签或用 debug 包） |
| `fastime-magisk.zip` | Magisk 模块（arm64） |
| `fastime-ios.ipa` | 未签名 IPA |

打 tag（`v*`）自动发布 Release 并附全部产物。

## Cloudflare Workers 上游

`workers/crypto.js` 提供与 Go 端逐字节互通的 WebCrypto 实现（零依赖）。要点：

- 全局 `encode` 开关：`true` 加解密模式（读 `e2e=` 参数 / 解密 POST 帧流），`false` 明文直连（读 `dns=`）
- 密钥放 env：`wrangler secret put ENC_KEY_B64`（必须与编译进 fastime 的密钥一致）
- 帧格式：GET 紧凑帧 `[12B nonce][密文+tag]`；POST/响应帧流 `[u32 明文长度][12B nonce][密文+tag]...`
- **响应帧的长度头写明文长度**（`u8.length`），不是密文长度

## 缓存语义（DNS 感知）

缓存键 = HTTP 方法 + 规范化报文：

| 字段 | 处理 |
|---|---|
| 事务 ID / EDNS Cookie | 剔除（每次随机） |
| flags（RD/CD/DO…）· ECS 等其它 EDNS 选项 | 保留（用户设置，影响应答） |
| QNAME | 保留（小写化，防 0x20 随机化） |
| QTYPE + QCLASS | 保留（A/AAAA/TXT/MX… 全类型各自独立） |

行为：

- 静默期内命中 → 零网络直接返回
- 过期命中 → 立即返回缓存 + 后台刷新
- 命中/共享时响应事务 ID 自动回写为本次查询的 ID（否则客户端报 bad header id）
- 仅缓存上游 200；空响应永不入缓存（防缓存中毒）
- 切网时按 `NET_SWITCH_MODE` 清空或逐条强制刷新

## 高并发与能耗设计

射频唤醒 ≫ 握手 ≫ 字节数 ≫ CPU。全部杠杆已落地：

| 手段 | 作用 |
|---|---|
| 缓存静默期 | 期内零网络，移动端省电最关键一环 |
| 单飞（singleflight） | 相同请求并发只打一次上游，跟随者共享结果 |
| 并发闸门（≤32 在飞） | 突发流量削峰，防瞬间打满射频与 CPU |
| h2 多路复用 / h3 QUIC | 所有并发共享一条连接，射频只唤醒一次 |
| QUIC 0-RTT + TLS 会话恢复 | 重连首包即带请求；TCP 侧 PSK 免完整握手 |
| 空闲连接 10s 释放 | 射频尽快回休眠；QUIC 关保活 ping |
| 最快 IP 记忆 1min + DoT 缓存 5min | 跳过解析与竞速直连 |
| `sync.Pool` 帧缓冲 / 移动端堆上限 48MB | 降 GC 压力，防 OOM 被杀 |
| GET 紧凑帧 | 省 4B 长度头 ≈ 每请求少 6 个 base64 字符 |

## 日志

双写 stdout 与工作目录下 `fastime.log`（macOS .app 回退到 `~/fastime.log`）。

- `debug`：每次请求的缓存判定（含键指纹）、拨号竞速、上游耗时
- `info`：启动、网络切换、QUIC 升级/回退
- `error`：仅错误

## 已知限制

| 项 | 说明 |
|---|---|
| 密钥内嵌二进制 | 拿到二进制即可提取密钥，勿分发给不可信者 |
| 缓存纯内存 | 进程重启即失 |
| APK / IPA 未签名 | 需自签或侧载 |
| 0-RTT 可重放 | 请求幂等且 body 加密，风险可接受 |
| 同端口单实例 | APK 与 CLI 不要同时启动 |
