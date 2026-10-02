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
| 状态页 | 浏览器访问 `http://127.0.0.1:端口/`：分组卡片展示 CPU/内存/协程、缓存与命中、运行缓存（持久化+定时刷新）、上游模式与竞速/主备耗时（ms）统计、前台/后台失败分开统计、熔断状态、DNS 解析缓存与最快 IP 明细（host→IP）、**系统 DNS（当前网络真实下发的服务器）**、IP 段列表与系统 DNS 代管状态、密钥指纹、运行时信息，5s 自刷 |
| 延迟曲线页 | 状态页点「📈 延迟曲线」或访问 `http://127.0.0.1:端口/latency`：浅色卡片风、纯 Canvas 无外部依赖。**六组图表**同窗联动：总往返耗时（蓝=主/橙=备双线）、主/备各自的**分阶段耗时构成堆叠图**（DNS 解析→TCP 连通→TLS/QUIC 握手→等待响应→传输，顶线=总耗时，QUIC 下握手为传输+TLS 合并的 1-RTT）、DNS 解析耗时、TLS/QUIC 握手耗时、传输耗时（首字节之后）三张独立曲线——历史数据与各阶段耗时一目了然；**滚轮/双指捏合缩放（以指针为中心）、拖动平移、双击/按钮一键重置**，所有图表共享同一时间窗，缩一处动全部；页头 +/−/⟳ 按钮便于触屏操作，**跟随最新**模式自动滚动，悬停/触摸十字线查看单点全部阶段数值；汇总卡展示 最新/均值/最低/最高、DNS 均值/TLS 均值、**连接复用率**（h2/QUIC 长连接复用占比）、数据点数；实心点=真实请求、空心点=探测、复用点标注；**页面打开期间每 2s 主动探测**（关页面即停），无流量时另有空闲探测（45s 断流后每 30s 一次）；数据保留最近 **1440 点**，移动端自动紧凑布局，高分屏按 DPR 渲染 |
| 缓存查看页 | 状态页点「📋 缓存内容」或访问 `http://127.0.0.1:端口/cache`：逐条列出缓存的 **域名 / 查询类型(A/AAAA…) / 请求方法 / 应答 IP 与 TTL / 大小 / 缓存时间 / 新鲜度**，NXDOMAIN 等异常 RCODE 红色标注；**命中 IP 段的条目带 🎯 徽标**（已代管 / 代管失败原因都可见）；每行另有**「🔄 强制刷新」**（无视新鲜度，立即向主备上游并发竞速重取该条目）和**「🚫 不走系统DNS」按钮**——点击后该域名即使命中 IP 段也始终用上游解析结果，且按 `NODIVERT_REFRESH_SEC`（默认 3 分钟）**独立周期强制换新**，豁免清单持久化到 `fastime-nodivert.json`（重启自动恢复，再点「↩️ 恢复系统DNS托管」即解除）；turbo 模式下另有「系统 DNS 代管」表；**移动端自动转卡片式布局**，排障时直接核对某个域名缓存了什么 |
| 运行模式 | 两套完整模式（`RUN_MODE`）：`standard` 现有模式（主 3s → 失败 → 备 5s 顺序重试）；`turbo` 新模式（主备并发竞速取最快 + IP 段分流 + 系统 DNS 代管）。每次请求独立决策，单次失败不影响后续。两上游加密与密钥相同、路径相同，h2/QUIC 各自独立探测 |
| 系统 DNS 代管 | turbo 模式可选：应答 IP 命中 `IPLIST_URL` 段内的域名改由系统 DNS（运营商）解析，按其 TTL 独立缓存、SWR 后台刷新，切网即清；网页绿色表格专栏展示 |
| 熔断 | 主备链连续 N 次全失败（默认 3 次）→ 熔断 M 秒（默认 3s，可配/可禁用）：缓存照给、MISS 本地快速失败、后台刷新暂停，断网/地铁场景省流省电；切网即重置 |
| 拨号 | 自建 DoT（`223.5.5.5:853`）解析，失败自动改用同 IP 的**阿里 DoH(443)**，两级都失败才报错（**绝不回退系统 DNS**）+ 全候选 IP **竞速**（250ms 错峰），胜出者记忆 **10 分钟**（**每次成功请求自动续期**，长连接复用下也不会过期归零；single 模式直连成功同样记忆） |
| 上游域名代答 | 经本地端口查询**主/备上游主机名本身**的 A/AAAA 时，直接走内置 DoT→DoH 链本地解析并构造应答，**不经 Worker**——避免"要连上游得先解析上游"的死循环；结果照常缓存、过期后台本地刷新，不受熔断影响 |
| 缓存 | DNS 感知键（域名小写+QTYPE+QCLASS+用户设置项，剔除随机 TID/Cookie）· 仅缓存上游 200 · 空响应不入缓存 · LRU 淘汰 |
| 运行缓存 | 上游结果**持久化到 `fastime-cache.json`**（工作目录），重启后整体恢复、前台立即可命中（过期则先返回旧值 + 后台刷新，不从 0 开始）；并按 `CACHE_REFRESH_SEC`（默认 1800s）**定时把已有缓存逐条向上游换新**，刷新期间前台始终用旧结果，失败保留旧值；熔断中暂停批量刷新；退出时自动落盘 |
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
| `RUN_MODE` | 运行模式：`standard`（默认，现有模式）/ `turbo`（新模式：主备并发竞速 + IP 段分流 + 系统 DNS 代管） | `standard` | `-run-mode` |
| `RACE_CACHE_SEC` | turbo 模式上游竞速结果缓存秒数（turbo 下替代 `CACHE_TTL_SEC`） | `60` | `-race-cache` |
| `IPLIST_URL` | IP 段列表 txt 下载地址（IPv4/IPv6 CIDR 或裸 IP，`#`/`;` 注释；12h 刷新）。主机名按内置链 DoT(223.5.5.5:853)→阿里 DoH(443) 解析、不回退系统 DNS；成功下载即持久化到 `fastime-iplist.txt`，重启先读本地再联网更新。turbo 模式下应答 IP 命中段内 → 该域名改由系统 DNS 代管 | `https://example.com/cn.txt` | `-iplist-url` |
| `CACHE_REFRESH_SEC` | 运行缓存定时刷新间隔秒数：到期把已有缓存逐条向上游换新（前台先用旧结果），`0` = 关闭定时刷新（持久化不受影响，过期仍按 SWR 按需刷新） | `1800` | `-cache-refresh` |
| `NODIVERT_REFRESH_SEC` | 「🚫 不走系统DNS」豁免域名的**独立刷新秒数**：豁免域名始终返回上游结果，按此时长强制换新（定时刷新与查询触发 SWR 都按它判定），默认 3 分钟远短于全局；`0` = 跟随 `CACHE_REFRESH_SEC` | `180` | `-nodivert-refresh` |

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

### 命令行参数（23 个，与 Secret 一一对应）

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
| `-run-mode` | `RUN_MODE` | `standard` / `turbo` |
| `-race-cache` | `RACE_CACHE_SEC` | `60`（秒） |
| `-iplist-url` | `IPLIST_URL` | `https://example.com/cn.txt` |
| `-cache-refresh` | `CACHE_REFRESH_SEC` | `1800`（秒），`0` = 关闭定时刷新 |
| `-nodivert-refresh` | `NODIVERT_REFRESH_SEC` | `180`（秒），`0` = 跟随全局 |

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

## 两种运行模式（RUN_MODE）

fastime 有两套**完整独立**的运行模式，用 `RUN_MODE` / `-run-mode` 切换：

| | `standard`（现有模式，默认） | `turbo`（新模式） |
|---|---|---|
| 上游策略 | 主 → 失败 → 备，顺序重试 | **主备同时并发竞速，取最快**，败者立即取消 |
| 上游结果缓存 | `CACHE_TTL_SEC` 静默期 + 后台刷新 | `RACE_CACHE_SEC` 秒（默认 60） |
| IP 段分流 | 无 | 应答 IP 命中 `IPLIST_URL` 段内 → 该域名改由**系统 DNS** 解析并代管 |
| 流式回写 | 边解密边回写 | 缓冲到胜出后统一返回（DNS 应答很小，无感） |
| 统计 | 主/备各自次数、成败、耗时 | 竞速 主胜/备胜/双败、胜出平均耗时 |

### turbo 模式完整流水线

```
请求 → 主上游（超时 3s）┐
                        ├─ 并发竞速 → 先到的 200 胜出（败者立即取消）→ 缓存 RACE_CACHE_SEC 秒
     → 后备上游（5s）  ┘   双败 → 报错（计入熔断）
                ↓ 胜出应答中的 A/AAAA IP
   ├─ 命中 IP 段 → 该域名改由【系统 DNS】解析：
   │     · 按系统应答的 TTL 独立缓存（与上游缓存完全隔离）
   │     · TTL 到期 → 前台仍返回旧结果 + 后台走系统 DNS 刷新（SWR）
   │     · 网页标记：状态页「系统 DNS 代管」行 + 缓存页绿色「系统 DNS 代管」表
   │     · 切网 → 只清系统 DNS 代管缓存，上游竞速结果缓存保留
   │     · 系统 DNS 解析失败 → 本次先返回竞速结果，下次再试
   └─ 不在段内 → 直接返回竞速结果
```

规则与参数：

- turbo 需要配置 `FALLBACK_URL`（只有一个上游时等同 standard）
- `IPLIST_URL`：txt 文件，一行一个 CIDR（`10.0.0.0/8`）或裸 IP（自动补 `/32`、`/128`），支持 `#`/`;` 注释，IPv4/IPv6 混合；启动时下载，之后**每 12 小时刷新一次**，下载失败沿用旧表；**首次成功前每 60s 重试**（避免启动时网络未就绪导致长时间无表）
- **IP 段列表的域名解析走内置链**：`IPLIST_URL` 主机名按 **DoT(`223.5.5.5:853`) → 失败自动阿里 DoH(443) → 两级都失败才报错** 解析（**绝不回退系统 DNS**），与上游拨号同一套解析器；随后对所有候选 IP（IPv4 优先）逐一拨号，TLS SNI 保持原域名
- **IP 段列表本地持久化**：每次成功下载即写入运行目录 `fastime-iplist.txt`（临时文件+原子改名）；**下次启动先读本地表立即可用**（断网/列表服务器宕机也能分流），随后照常按上面逻辑联网更新，更新成功再覆盖本地副本；状态页「IP 段列表」行可见当前表来自本地还是网络
- **应答中任一 A/AAAA IP 命中段内即触发代管**（CNAME 链末端地址也参与匹配）；只有 A/AAAA 查询参与匹配，其它类型直接返回竞速结果；命中即打标记，缓存页 🎯 徽标可见（含"代管失败"原因），状态页「IP 段列表」行有累计命中次数
- **重启不丢代管**：IP 段列表加载成功后会自动**补扫**全部已恢复的运行缓存——重启前已代管的域名无需等新查询即重新补建系统 DNS 代管（日志有「补扫：…」行）；被「🚫 不走系统DNS」豁免的域名跳过补扫
- **豁免域名独立保鲜**：被「🚫 不走系统DNS」豁免的域名始终返回上游竞速结果，并按 `NODIVERT_REFRESH_SEC`（默认 180s，远短于全局 `CACHE_REFRESH_SEC`）独立强制换新——定时刷新循环对它按独立时长到期判定，查询时超过该时长也立即触发后台换新（SWR）；`0` = 跟随全局
- 系统 DNS 取**当前网络真实下发的服务器**（运营商/企业 DHCP 推送的，不是配置文件里的静态值）——**只取当前正在上网的那张网卡/那条网络的 DNS**（连着 Wi-Fi 就是 Wi-Fi 的，切移动数据就是蜂窝下发的），不会把 VPN 虚拟网卡、未连接网卡、其他网络残留的 DNS 全列出来；状态页「系统 DNS」行两种模式下都展示：
  - **Windows**：`GetBestInterfaceEx` 找到访问公网实际使用的活动网卡（自动跟随 Wi-Fi/有线/蜂窝切换），只读该网卡在注册表里的 DNS（`Tcpip`+`Tcpip6` 的 `NameServer`/`DhcpNameServer`）；定位失败才回退旧行为（列出所有网卡的 DNS）
  - **Linux**：读 `/etc/resolv.conf`
  - **macOS**：cgo 构建直接调 libresolv `res_ninit` + `res_getservers` 读**系统解析器实际生效的服务器列表**（macOS 的 resolv.conf 常与实际配置不符，此途径最准）；无 cgo 的静态构建回退 resolv.conf
  - **iOS**：gomobile 构建（cgo 开启）同样走 libresolv `res_getservers`，拿到的就是系统当前正在用的 DNS（含 Wi-Fi/蜂窝 DHCP 下发）；iOS 上没有可读的 resolv.conf，这是唯一可靠途径
  - **Android 四级获取**（root 直跑二进制也能用 Java 层）：① APK Java 层 `ConnectivityManager` 网络回调实时推送**当前默认网络** `LinkProperties.getDnsServers()`（免 root，逐网络最准，Wi-Fi/蜂窝各用各的；root 机上照常生效）→ ② **root/shell 直跑无 APK 时**：内嵌 dex 经 `app_process` 直接经 binder 调 Java 层 `IConnectivityManager.getActiveLinkProperties()`，与 ① 同源同精度（dex 由 CI 编译注入，源码在 `android/tools/FastimeDns.java`）→ ③ `dumpsys connectivity` 按 `Active default network` 锁定**当前默认网络**（Wi-Fi 或移动数据，随切换自动跟随），只解析该网络块 `DnsAddresses` 段内的地址（不再把 LinkAddresses 的接口 IP、其他网络的残留 DNS 混进来；`0.0.0.0`/`::` 等无效值直接丢弃；需 root/shell）→ ④ `getprop net.dns1..4` 全局属性兜底（可能滞后，故排最后）→ 都失败回退 Go 系统解析器（无 TTL，按 60s 缓存）
- **服务器列表随当前网络缓存：网络不变一直复用，切网立即重新获取**（同时清空系统 DNS 代管缓存，上游竞速缓存保留）
- 查询走 UDP/53 wireformat（拿真实 TTL，代管缓存严格尊重该 TTL，下限 5s），截断自动转 TCP，CNAME 最多追 3 层；**多台系统 DNS 并发竞速，先到者胜出、其余立即取消**（与上游竞速同语义）
- 竞速统计独立：状态页「竞速 主胜/备胜/双败」「竞速胜出平均耗时」；双败计入熔断器

```bash
# 示例：turbo 模式 —— 主备竞速 + 命中 IP 段的域名走系统 DNS
./fastime -run-mode turbo -fallback https://yyy.workers.dev \
          -race-cache 60 -iplist-url https://example.com/cn-ip.txt
```

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
| 操作 | 「🔄 强制刷新」无视新鲜度立即把该条目向主备上游并发竞速重取（turbo 取最快、败者取消；standard 走主→备链），失败保留旧值；「🚫 不走系统DNS」/「↩️ 恢复系统DNS托管」切换该域名的代管豁免，选择持久化到 `fastime-nodivert.json`，重启后自动恢复；豁免域名按 `NODIVERT_REFRESH_SEC`（默认 3 分钟）独立周期强制换新，行内有「已豁免 · 每 Ns 独立刷新」徽标 |

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
| 缓存持久化在工作目录 | `fastime-cache.json` / `fastime-nodivert.json` / `fastime-iplist.txt` 与二进制同目录，多实例共目录会互相覆盖；换目录运行即互相隔离 |
| APK / IPA 未签名 | 需自签或侧载 |
| 0-RTT 可重放 | 请求幂等且 body 加密，风险可接受 |
| 同端口单实例 | APK 与 CLI 不要同时启动 |
