<div align="center">

# fastime

**本地加密 DNS 中继 · 全平台 · 单模式 · 移动端能耗优先**

AES-128-GCM 硬件加速 · HTTP/2 + HTTP/3(QUIC) · 主备并发竞速 · 虚假 IP 污染 · DoT 引导拨号

</div>

---

## 这是什么

运行在本机 `127.0.0.1` 的加密中继：接收本地 DNS 请求（HTTP），用 AES-128-GCM
加密后**并发**发往主、备两个上游（Cloudflare Workers），取最快成功的一个返回；
应答 IP 命中指定 IP 段时，向客户端返回**虚假 IP**（污染）。

```
客户端                   本机 fastime                     上游 Workers
  │  POST /e2e (DNS 报文)   │                                   │
  │  或 GET /e2e?dns=b64    │                                   │
  │────────────────────────>│ 强制污染名单？→ 直接回虚假 IP       │
  │                         │ 缓存命中？→ 回缓存（实时套用判定）   │
  │                         │ 上游自身域名？→ 本地 DoT/DoH 代答   │
  │                         │ 否则：主备并发加密请求 ─────────────>│
  │                         │  取最快「200+内容合法」者，另一个抛弃 │
  │                         │  双败 → 回空 DNS 应答（NOERROR/0）  │
  │<────────────────────────│ 读应答第一个 IP：命中 IP 段→虚假 IP  │
```

## 核心行为（唯一模式，无开关）

| 环节 | 行为 |
|---|---|
| 主备竞速 | 每次未命中缓存的请求**并发**打主、备上游，谁先返回「HTTP 200 + DNS 应答合法（QR=1 且问题区可解析）」用谁，另一个立刻取消；**两个都失败 → 返回空 DNS 应答**（NOERROR、ANCOUNT=0），不是 HTTP 错误也不是超时 |
| 污染判定 | 读上游应答的**第一个 IP**，在 IP 段表（`IPLIST_URL`）里查包含：命中则 A 查询回 `169.254.254.254`、AAAA 回 `::ffff:a9fe:fefe`（TTL 60s）。**判定发生在应答时刻**——缓存里存的是上游原始结果，改覆盖名单立刻生效，不用等缓存过期 |
| 污染模式（`POLLUTE_MODE`） | `fake`（默认）：命中 IP 段回虚假 IP，缓存 15 分钟换新、**切网不动缓存**；`off`：不做 IP 段判定、全部原样返回（手动覆盖名单仍生效），缓存 **5 分钟**换新、**切网立刻全量换新** |
| 熔断 | 连续 **3 次**主备双败 → 熔断 **2 秒**：期间**未缓存的请求**一律回 **HTTP 200 + 空 DNS 应答**（NOERROR/0 记录），不打上游；**缓存命中与强制污染照常返回**；一次成功即清零，切网立即解除 |
| 取消污染 🚫 | 缓存页按钮：该域名即便命中 IP 段也返回真实 IP。存 `fastime-nofake.json`，重启自动恢复 |
| 强制污染 🎯 | 缓存页按钮：该域名即便没命中也回虚假 IP，且**不打上游**（零流量）。存 `fastime-forcefake.json`。与取消污染互斥（设一个清另一个） |
| 缓存 | 成功结果按 DNS 感知键缓存（剔除随机 TID/Cookie，域名小写），**无过期**（LRU 只管容量）；后台**每 15 分钟**把已有条目**串行**逐条向上游换新（省电，不打满射频），换新期间一直回旧值；**每 30 秒**落盘 `fastime-cache.json`，下次启动先读缓存优先返回、再后台更新 |
| IP 段表 | 启动时先读运行目录下的 `fastime-iplist.txt`（有就先用），再联网下载覆盖；之后**每 12 小时**更新；首次成功前每 60s 重试 |
| 上游域名引导 | 主/备上游主机名本身的解析走内置 **DoT(223.5.5.5:853) → DoH(443)** 链，**绝不回退系统 DNS**——避免"连上游要先解析上游"的死循环；经本地端口查上游域名时直接本地代答 |
| 拨号 | DoT 解析 + 全候选 IP 竞速（250ms 错峰），胜出 IP 记忆 10 分钟、每次成功请求自动续期 |
| 传输 | 默认 H2 长连接多路复用；上游响应带 Alt-Svc 后自动升级 **H3/QUIC**（0-RTT 会话缓存），可用 `QUIC_PRIMARY`/`QUIC_FALLBACK` 控制（auto/prefer/off）；QUIC 空闲不 keep-alive（省电） |
| 切网 | 接口指纹 2s 轮询 + 移动端 OS 回调：清空拨号/QUIC 连接记忆（旧连接绑在旧通道上），业务缓存保留（15 分钟换新自然收敛）；Android root 模式下立即重写 resolv.conf |
| 省电 | 缓存命中零网络；串行换新；单飞去重；并发闸门 ≤32；探测只在空闲 45s 后每 30s 一次 |

## system-dns.com：查看当前网络的真实 DNS

程序持续探测本机「真实网络」下发的 DNS，并以特殊域名对外提供查询：

```bash
dig @127.0.0.1 -p <端口> system-dns.com       # A    → 全部 IPv4 DNS
dig @127.0.0.1 -p <端口> system-dns.com AAAA  # AAAA → 全部 IPv6 DNS
```

- **TTL=1s**、本地合成应答：不打上游、不进缓存、不受熔断影响
- **探测节奏**：启动即探测 → 切网立刻重探（1.2s 防抖）→ 网络无变化每 30s 周期探测；状态页「🔄 重新探测」按钮可随时强制重探
- 探测来源（按平台）：
  - **Android**：APK 内 Java 层实时推送（ConnectivityManager 回调，免 root；root 二进制会直接读 `/data/data/com.fastime.app/files/sysdns.txt`）→ root 时 dex 经 app_process 直取（双通道合并、VPN 跳过；dex 双来源：CI 内嵌注入 + 二进制旁 `fastime-dns.dex` 文件，Magisk 模块包内已附带）→ dumpsys connectivity（兼容 Android 12+ 逗号无空格 DnsAddresses 格式；活动网络匹配失败时自动宽松收集全部非 VPN 块）→ getprop 全量扫描（老设备兜底）；**上次成功的来源优先复用**，每个来源失败都会在日志给出原因；探测带 2s 最小间隔防抖，切网抖动不刷屏
  - **Windows**：PowerShell `Get-DnsClientServerAddress` 枚举全部网卡，**过滤 VPN/TAP/Wintun/虚拟化网卡**——拿到的是路由器下发的真实地址
  - **macOS**：`scutil --dns` 默认解析器；**iOS**：/etc/resolv.conf（沙盒限制时静默降级）
  - **Linux**：/etc/resolv.conf；只剩 systemd-resolved 本地桩时自动改读 `resolvectl dns`
- 全来源统一过滤占位地址（`0.0.0.0`、`::`、回环、链路本地）与 **TUN 假 DNS（198.18.0.0/15，如 sing-box 的 198.18.0.2）**
- 状态页首卡实时展示探测结果（IPv4/IPv6 分列、来源、更新时间、应答次数）

## 页面

### 状态页 `/`
现代卡片式设计（渐变页头 + 卡片宫格，移动端自动单列）：
**系统 DNS 卡**（system-dns.com 当前应答：IPv4/IPv6 分列 chips、来源、更新时间、应答次数，**🔄 重新探测**按钮强制重探）、
**概览卡**（污染模式、熔断状态、CPU/内存）、**上游与竞速卡**（主/备上游 + QUIC 策略 +
最近一次请求的实际耗时与协议 h2/h3、竞速与 429 统计）、**缓存与污染卡**（缓存/换新/IP 段表/判定计数）、
**运行配置卡**（运行环境与协程数、日志等级、AES 密钥指纹——核对两端密钥一致、请求头数、DoT 引导、
缓存策略、IP 段表更新周期与地址、系统 DNS 探测节奏）。

### 延迟页 `/latency`
纯 Canvas 无外部依赖，滚轮/双指缩放、拖动平移、双击重置，多图联动。
**探测走真实域名（www.cloudflare.com）的真实加密链路**——H2 就按 H2 请求、
H3 就按 H3 请求（依 QUIC 策略自动协商），汇总卡显示**实际协商协议**（h3/h2/h1
最新值与分布）；分阶段堆叠图：DNS 解析→TCP→TLS/QUIC 握手→等待→传输。
页面打开时每 2s 按需探测（实时反映当前网络），关闭后退回 30s 空闲探测。
空心点=探测，实心点=真实请求；数据保留最近 400 点。

### 缓存页 `/cache`
- **顶部置顶区**：取消污染 / 强制污染名单（按更改时间倒序，最新改的排最前，
  状态徽标 + 一键恢复）
- 条目表：域名/类型/方法、**当前判定**（强制污染 / 取消污染 / 命中污染段 / 真实 IP）、
  上游原始应答（IP+TTL）、缓存时间与大小
- 每行按钮：♻️ 立即刷新 · 🚫 取消污染 · 🎯 强制污染（互斥，点了立即生效）

## GitHub Secrets（编译期注入，名称不变）

仓库 → Settings → Secrets and variables → Actions：

| Secret | 作用 | 示例 | 命令行参数 |
|---|---|---|---|
| `POLLUTE_MODE` | 污染模式 fake（默认）/off | `fake` | `-pollute` |
| `LISTEN_PORT` | 本地监听端口 | `8080` | `-port` |
| `UPSTREAM_URL` | 主上游地址 | `https://a.workers.dev` | `-upstream` |
| `FALLBACK_URL` | 后备上游（并发竞速，可选） | `https://b.workers.dev` | `-fallback` |
| `UPSTREAM_PATH` | 上游路径 | `/gateway` | `-path` |
| `ENC_KEY_B64` | base64 的 16 字节 AES-128 密钥 | `AAAAAAAAAAAAAAAAAAAAAA==` | `-key` |
| `CACHE_SIZE` | 内存缓存条数（LRU） | `128` | `-cache-size` |
| `DOT_SERVER` | DoT 引导解析服务器 | `223.5.5.5:853` | `-dot` |
| `CUSTOM_HEADERS` | 自定义请求头（纯 JSON，CI 自动 base64） | `{"X-Auth":"abc"}` | `-headers` |
| `REQUEST_TIMEOUT_SEC` | 主上游超时秒数 | `3` | `-timeout` |
| `FALLBACK_TIMEOUT_SEC` | 后备上游超时秒数 | `5` | `-fallback-timeout` |
| `LOG_LEVEL` | 日志等级 debug/info/error | `info` | `-log` |
| `QUIC_PRIMARY` | 主上游 QUIC 策略 auto/prefer/off | `auto` | `-quic-primary` |
| `QUIC_FALLBACK` | 后备上游 QUIC 策略 | `auto` | `-quic-fallback` |
| `IPLIST_URL` | 污染 IP 段 txt 下载地址（12h 刷新） | `https://example.com/ip.txt` | `-iplist-url` |

固定值（写死在代码里，不占 Secret）：缓存换新 fake=15 分钟 / off=5 分钟、30s 落盘、
IP 段表 12h 刷新、resolv.conf 5 分钟刷新、熔断 3 次双败×2 秒。

## 全平台产物（GitHub Actions）

| 产物 | 说明 |
|---|---|
| `fastime-linux-amd64/arm64` | Linux CLI |
| `fastime-windows-amd64/arm64.exe`（+bat 包） | Windows |
| `fastime-darwin-amd64/arm64` · `Fastime-macos.app` | macOS CLI / 双击 App（universal2） |
| `fastime-android-arm64`（+-lite） | Android 二进制（Termux/root 直跑） |
| `fastime-android.apk` | Android App（前台服务保活，Go 核心以 libfastime.so 内嵌） |
| `fastime-magisk.zip` | Magisk 模块（root 开机手动启停：`start.sh`/`stop.sh`） |
| `fastime-ios.ipa` | iOS（gomobile 框架 + 静音保活，未签名需 AltStore/TrollStore 侧载） |

每个 CLI 平台另出 `-lite` 版（`-tags noquic`，去掉 QUIC 依赖，体积更小）。

## 本地运行

```bash
go build -o fastime .
LISTEN_PORT=8080 UPSTREAM_URL=https://a.workers.dev UPSTREAM_PATH=/gateway \
ENC_KEY_B64=AAAAAAAAAAAAAAAAAAAAAA== ./fastime

# 查询测试（DoH wire-format）
dig @127.0.0.1 -p 8080 +https=/e2e example.com   # 或任意 DoH 客户端
```

工作目录文件：`fastime-cache.json`（缓存落盘）· `fastime-iplist.txt`（IP 段表）·
`fastime-nofake.json` / `fastime-forcefake.json`（覆盖名单）·
`fastime-resolv.conf` + `fastime-dns.dex`（Android root）· `fastime.log`。

## 上游 Worker

`workers/crypto.js`：AES-128-GCM 解密 → 解析 DNS 查询 → 真实解析 → 加密回包。
密钥经 `wrangler secret` 注入，与二进制侧 `ENC_KEY_B64` 一致。
