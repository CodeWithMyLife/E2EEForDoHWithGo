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
| 状态页 | 浏览器访问 `http://127.0.0.1:端口/`：分组卡片展示 CPU/内存/协程、缓存与命中、主/备上游耗时（ms）与成败、前台/后台失败分开统计、熔断状态、DNS 解析缓存与最快 IP 记忆、密钥指纹、运行时信息，5s 自刷 |
| 缓存查看页 | 状态页点「📋 缓存内容」或访问 `http://127.0.0.1:端口/cache`：逐条列出缓存的 **域名 / 查询类型(A/AAAA…) / 请求方法 / 应答 IP 与 TTL / 大小 / 缓存时间 / 新鲜度**，NXDOMAIN 等异常 RCODE 红色标注，排障时直接核对某个域名缓存了什么 |
| 后备上游 | 主上游（默认 3s 超时）失败自动切后备（默认 5s 超时）；每次请求独立决策，单次失败不影响后续。两上游加密与密钥相同、路径相同，h2/QUIC 各自独立探测 |
| 熔断 | 主备链连续 N 次全失败（默认 3 次）→ 熔断 M 秒（默认 3s，可配/可禁用）：缓存照给、MISS 本地快速失败、后台刷新暂停，断网/地铁场景省流省电；切网即重置 |
| 拨号 | 自建 DoT（`223.5.5.5:853`）解析，失败自动改用同 IP 的**阿里 DoH(443)**，两级都失败才报错（**绝不回退系统 DNS**）+ 全候选 IP **竞速**（250ms 错峰），胜出者记忆 **1 分钟** |
| 上游域名代答 | 经本地端口查询**主/备上游主机名本身**的 A/AAAA 时，直接走内置 DoT→DoH 链本地解析并构造应答，**不经 Worker**——避免"要连上游得先解析上游"的死循环；结果照常缓存、过期后台本地刷新，不受熔断影响 |
| 缓存 | DNS 感知键（域名小写+QTYPE+QCLASS+用户设置项，剔除随机 TID/Cookie）· 仅缓存上游 200 · 空响应不入缓存 · LRU 淘汰 |
| 省电 | 静默期（默认 10s）内命中**零网络**；过期返回缓存+后台刷新（stale-while-revalidate）；单飞去重；并发闸门 ≤32 |
| 切网 | 接口指纹 2s 轮询 + 移动端 OS 回调：清空缓存 **或** 保留+逐条强制刷新（可配），并重置拨号记忆 |
| 安全 | AES-128-GCM（AES-NI / ARM CE 硬件加速）· 每帧随机 nonce · 编译期密钥注入 · 可自定义/剥离全部请求头 |
| 日志 | debug / info / error 三级，stdout + `fastime.log` 双写 |
| 配置 | 13 个配置项全部支持**命令行参数**覆盖（`-port` `-key` `-headers`…，`-h` 查看），优先级：命令行 > 环境变量 > 编译注入值 |

## GitHub Secrets（编译期注入）

仓库 → Settings → Secrets and variables → Actions：

| Secret | 作用 | 示例 | 命令行参数 |
|---|---|---|---|
| `LISTEN_PORT` | 本地监听端口 | `80` | `-port` |
| `UPSTREAM_URL` | 上游地址（不含路径） | `https://xxx.workers.dev` | `-upstream` |
| `FALLBACK_URL` | 后备上游域名：主上游失败自动重试（可选，路径同主上游） | `https://yyy.workers.dev` | `-fallback` |
| `UPSTREAM_PATH` | 上游路径 | `/e2e` | `-path` |
| `ENC_KEY_B64` | AES-128 密钥，16 字节 base64 | `openssl rand 16 \| base64` | `-key` |
| `CACHE_SIZE` | 缓存条数上限（LRU） | `512` | `-cache-size` |
| `CACHE_TTL_SEC` | 静默期秒数：期内命中零网络，过期后台刷新 | `10` | `-cache-ttl` |
| `DOT_SERVER` | DoT 服务器（失败自动改用同 IP 的阿里 DoH:443） | `223.5.5.5:853` | `-dot` |
| `CUSTOM_HEADERS` | 自定义请求头（纯 JSON；设置后不发送任何默认头含 UA） | `{"X-Auth":"abc"}` | `-headers` |
| `NET_SWITCH_MODE` | 切网策略：`refresh` 保留+强制刷新 / `clear` 清空 | `refresh` | `-net-switch` |
| `REQUEST_TIMEOUT_SEC` | 主上游超时（秒） | `3` | `-timeout` |
| `FALLBACK_TIMEOUT_SEC` | 后备上游超时（秒） | `5` | `-fallback-timeout` |
| `BREAK_FAILS` | 连续失败几次触发熔断 | `3` | `-break-fails` |
| `BREAK_DURATION_SEC` | 熔断时长（秒），`0` = 禁用熔断 | `3` | `-break-duration` |
| `LOG_LEVEL` | 默认日志等级 | `info` | `-log` |
| `DIAL_MODE` | `race` 竞速 / `single` 单 IP 直连 | `race` | `-dial` |
| `PREFER_QUIC` | 旧版 QUIC 开关，`true` 等价于 `QUIC_PRIMARY=prefer` | `false` | `-quic` |
| `QUIC_PRIMARY` | 主上游 QUIC 策略：`auto` Alt-Svc 探测 / `prefer` 首请求直连 / `off` 禁用 | `auto` | `-quic-primary` |
| `QUIC_FALLBACK` | 后备上游 QUIC 策略：同上，主备独立控制 | `auto` | `-quic-fallback` |

> 上游最终地址 = `UPSTREAM_URL` + `UPSTREAM_PATH`。
> `CUSTOM_HEADERS` 无需手动 base64——CI 构建时自动编码，引号不会被 shell 吃掉；运行时解析容错（纯 JSON / base64 有/无填充 / URL 安全字母表均可），即使填错也**只告警不致命**，程序照常运行。

## 运行方式

### 通用 CLI（Windows / macOS / Linux / Android-Termux）

```bash
# 直接运行（前台）
./fastime-linux-amd64

# 所有配置项都能用命令行参数覆盖（优先级：命令行 > 环境变量 > 编译值）
./fastime-linux-amd64 -log debug -port 8053

# 查看全部参数（每个参数都标注了对应的环境变量/Secret 名）
./fastime-linux-amd64 -h

# 环境变量临时覆盖任意编译参数（调试用）
LISTEN_PORT=8080 LOG_LEVEL=debug ./fastime-linux-amd64
```

### 命令行参数（13 个，与 Secret 一一对应）

每个配置项都有同名语义的运行参数，**优先级：命令行 > 环境变量 > 编译注入值 > 默认值**：

| 参数 | 对应 Secret / 环境变量 | 可选值 / 示例 |
|---|---|---|
| `-port` | `LISTEN_PORT` | `8053` |
| `-upstream` | `UPSTREAM_URL` | `https://xxx.workers.dev` |
| `-fallback` | `FALLBACK_URL` | `https://yyy.workers.dev` |
| `-path` | `UPSTREAM_PATH` | `/e2e` |
| `-key` | `ENC_KEY_B64` | `openssl rand 16 \| base64` |
| `-cache-size` | `CACHE_SIZE` | `512` |
| `-cache-ttl` | `CACHE_TTL_SEC` | `10`（秒） |
| `-dot` | `DOT_SERVER` | `223.5.5.5:853` |
| `-headers` | `CUSTOM_HEADERS` | `'{"X-Auth":"abc"}'` 或其 base64 |
| `-net-switch` | `NET_SWITCH_MODE` | `refresh` / `clear` |
| `-timeout` | `REQUEST_TIMEOUT_SEC` | `3`（秒，主上游） |
| `-fallback-timeout` | `FALLBACK_TIMEOUT_SEC` | `5`（秒，后备上游） |
| `-break-fails` | `BREAK_FAILS` | `3`（次） |
| `-break-duration` | `BREAK_DURATION_SEC` | `3`（秒），`0` = 禁用 |
| `-log` | `LOG_LEVEL` | `debug` / `info` / `error` |
| `-dial` | `DIAL_MODE` | `race` / `single` |
| `-quic` | `PREFER_QUIC` | `true` / `false`（旧版，等价 `-quic-primary=prefer`） |
| `-quic-primary` | `QUIC_PRIMARY` | `auto` / `prefer` / `off` |
| `-quic-fallback` | `QUIC_FALLBACK` | `auto` / `prefer` / `off` |

```bash
# 组合示例：完全脱离编译值，纯参数运行
./fastime-linux-amd64 -port 8053 -upstream https://xxx.workers.dev -path /e2e \
  -key "$(openssl rand 16 | base64)" -log debug -dial race -cache-size 512

# 枚举参数拼错会立即报错提示可选值，不会静默走默认值
./fastime-linux-amd64 -log bogus
# [FATAL] 无效的 -log 值 "bogus"（可选 debug/info/error）
```

### Windows

下载 `fastime-windows-amd64-bundle.zip`，解压后（bat 与 exe 放同一目录）：

- `start-console.bat` —— 前台启动（有控制台，`-log debug`，日志实时可见）
- `stop.bat` —— 停止（带成功/失败提示）
- `autostart-enable.bat` —— 开机自启（无控制台静默运行，`-log error`，基于计划任务）
- `autostart-disable.bat` —— 取消开机自启

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
| `fastime-windows-*-bundle.zip` | exe + 4 个 bat（前台启动 / 停止 / 开机自启 / 取消自启） |
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

## 主备上游逻辑

配置了 `FALLBACK_URL` 后，**首次请求和后台刷新**都走同一条主备链：

```
请求 → 主上游（超时 3s，REQUEST_TIMEOUT_SEC）
        ├─ 成功 → 解密返回 + 写缓存
        └─ 失败 → 后备上游（超时 5s，FALLBACK_TIMEOUT_SEC）
                   ├─ 成功 → 解密返回 + 写缓存
                   └─ 失败 → 报错（前台 502 / 后台记入失败计数）
```

规则：

- 两个上游**域名和 IP 可以不同**，但**加密方式与密钥相同**（共用 `ENC_KEY_B64`），**路径相同**（共用 `UPSTREAM_PATH`）
- 两个上游**各自独立探测和控制 h2 / QUIC**：`QUIC_PRIMARY` / `QUIC_FALLBACK` 三档（`auto` Alt-Svc 探测 / `prefer` 首请求直连 0-RTT / `off` 禁用），Alt-Svc 记忆按域名分别存储互不影响
- **每次请求独立决策**：单次失败只是那一次，下一个请求仍然先打主上游，无任何冷却/惩罚
- **连续失败熔断**（断网/弱网保护）：主备链**连续 N 次**全失败（`BREAK_FAILS`，默认 3）→ 熔断 M 秒（`BREAK_DURATION_SEC`，默认 3，`0` = 禁用）。期间**缓存命中照常返回**（过期缓存也照给），新 MISS 请求**本地快速 502**（0ms，不碰射频），后台刷新暂停；熔断结束放行一个探测请求，成功即恢复，失败再熔断；**切网时熔断立即重置**。单次/偶发失败不会触发
- 已开始流式回写的请求不重试（客户端已收到部分数据）
- 主备各自的次数、成败、平均耗时（ms）在状态页独立统计；熔断状态（含快速跳过次数）实时可见

### 上游域名本地代答

手机/电脑自身的 DNS 也会解析上游域名（比如系统或加速器配置里写了 `dns.example.com`）。如果这个查询再发回上游，就成了"要连上游得先能连上游"的死循环。因此：

- 经本地端口查询的对象是**主上游或后备上游的主机名本身**，且类型为 **A / AAAA** 时，fastime 直接走内置解析链 **DoT(`223.5.5.5:853`) → 失败自动阿里 DoH(443) → 两级都失败才报错（绝不回退系统 DNS）**，本地构造应答返回，**完全不碰 Worker**
- 应答 TTL 60s，结果照常进缓存（后续查询零网络命中）；过静默期后**后台刷新也走本地解析**，不受熔断影响（上游宕机时照常能解析上游域名）
- 其它类型（TXT/HTTPS…）或同名的子域名不拦截，照常中继给上游
- 状态页「本地代答（上游域名）」计数，缓存查看页可核对代答出的 IP；响应头 `X-Cache: MISS-LOCAL` 标识首次代答

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

### 缓存查看页（排障）

浏览器访问 `http://127.0.0.1:端口/cache`（或状态页右上角「📋 缓存内容」按钮），逐条查看当前缓存：

| 列 | 内容 |
|---|---|
| 域名 / 类型 / 方法 | 从缓存键还原的 QNAME（小写）、QTYPE（A/AAAA/TXT/HTTPS…）、GET/POST |
| 应答内容 | 每条应答记录的 类型 + 数据（A/AAAA 直接显示 IP，CNAME 显示目标）+ TTL；NXDOMAIN/SERVFAIL 等异常 RCODE 红色标注 |
| 大小 / 缓存于 / 状态 | 应答字节数、入库时间、新鲜（剩余秒数，绿色）或已过期（待后台刷新，橙色） |

按最近使用排序（最上 = 最新），5 秒自动刷新。查"为什么这个域名解析错了"时，直接在这里核对缓存的应答内容即可。

## 高并发与能耗设计

射频唤醒 ≫ 握手 ≫ 字节数 ≫ CPU。全部杠杆已落地：

| 手段 | 作用 |
|---|---|
| 缓存静默期 | 期内零网络，移动端省电最关键一环 |
| 连续失败熔断 | 断网时 MISS 本地快速失败 + 暂停后台刷新，射频零唤醒 |
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
