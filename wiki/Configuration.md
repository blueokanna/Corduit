# 配置（Configuration）

配置是一个 **nextjson 原生 JSON 对象**（零 serde）。主体五段：`general` / `dns` / `inbounds` / `outbounds` / `rules`；另外两个顶层键 `rule_providers` / `proxy_providers` 用于外部规则集和订阅（由 API 层在启动/重载/校验时读取，不进入 `Config` 结构体）。所有枚举值都是字符串（见各表），未知字段或非法类型会在 `validate()` 时报错。

规则引擎的完整语义（三模式、规则顺序、DNS 行为、provider 刷新）见 [Rules](Rules)，本文只给配置字段本身。

## 完整示例

```json
{
  "general": {
    "port": 7890,
    "socks_port": 7891,
    "mixed_port": 7890,
    "allow_lan": false,
    "bind_address": "127.0.0.1",
    "mode": "rule",
    "log_level": "info",
    "ipv6": false,
    "tcp_concurrent": true
  },
  "dns": {
    "enable": true,
    "listen": "127.0.0.1:53",
    "nameservers": ["https://dns.google/dns-query", "8.8.8.8"],
    "fallback": ["8.8.4.4"],
    "enhanced_mode": "fake-ip"
  },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "DIRECT" },
    {
      "type": "shadowsocks",
      "tag": "ss-jp",
      "server": "1.2.3.4",
      "port": 8388,
      "password": "secret",
      "cipher": "aes-256-gcm"
    },
    {
      "type": "selector",
      "tag": "PROXY",
      "outbounds": ["DIRECT", "ss-jp"]
    }
  ],
  "rules": [
    { "type": "domain-suffix", "payload": "google.com", "outbound": "ss-jp" },
    { "type": "geoip", "payload": "cn", "outbound": "DIRECT" },
    { "type": "match", "payload": "", "outbound": "ss-jp" }
  ],
  "rule_providers": [],
  "proxy_providers": []
}
```

> 注意：代理组（selector 等）的成员键是 **`outbounds`**（tag 数组），不是 `proxies`。`use` 键用于引用代理订阅，见下。

## general（通用）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `port` | u16 | `7890` | HTTP 代理监听端口 |
| `socks_port` | u16? | — | SOCKS5 监听端口 |
| `redir_port` | u16? | — | Linux redir 透明代理端口 |
| `tproxy_port` | u16? | — | Linux TProxy 端口 |
| `mixed_port` | u16? | — | HTTP+SOCKS5 混合端口 |
| `authentication` | 数组 | — | `[{username,password}]` 入站认证 |
| `allow_lan` | bool | `false` | 是否允许局域网访问 |
| `bind_address` | string | `127.0.0.1` | 入站绑定地址 |
| `mode` | string | `rule` | `rule` / `global` / `direct`（三种模式的行为见 [Rules](Rules#1-三种模式)） |
| `log_level` | string | `info` | `silent` / `error` / `warning`(或 `warn`) / `info` / `debug`。运行中可用 `set_log_level` 改（真的改，不是只记一条日志）；`silent` 启动时不会安装订阅器，此时改级别会明确报错 |
| `ipv6` | bool | `false` | 启用 IPv6 |
| `tcp_concurrent` | bool | `false` | TCP 并发连接 |
| `external_controller` | string? | — | 外部控制器地址 |
| `external_ui` | string? | — | 外部 UI 路径 |
| `secret` | string? | — | 控制器密钥 |

## dns（DNS）

解析、缓存、上游传输与 fake-IP 全部由 [RecurseX](https://crates.io/crates/recurse-x) 负责（线格式、分层语义缓存、UDP/TCP/DoT/DoH/DoH3/DoQ、请求合并）；本仓库只做「profile → `ResolverConfig`」这一层适配。

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enable` | bool | `false` | 启动面向客户端的 DNS 监听器（UDP + TCP 同一地址） |
| `listen` | string | `127.0.0.1:53` | 监听地址；`enable` 为真时解析失败就算配置错误 |
| `nameservers` | string[] | `8.8.8.8, 1.1.1.1` | 主上游。写法见下 |
| `fallback` | string[] | `[]` | 回退上游。**故意为空**：配了它才会打开「可疑应答重问」闸门，默认打开会把内网节点地址也重问一遍 |
| `default_nameserver` | string[] | `[]` | 用于解析**上游自己的主机名**，必须是 IP 字面量。为空时自动用 `nameservers`/`fallback` 里的 IP 字面量；都没有才退回系统解析器 |
| `nameserver_policy` | map | `{}` | 按后缀指定上游（支持 `+.example.com` / `*.example.com` / `.example.com` / 裸域名），最长后缀命中优先 |
| `fallback_filter.geoip` | bool | `true` | 主上游落在该国时视为可疑。**只有引擎自己的拨号看得到这条信号**（RecurseX 不带国家库）；监听器用 bogon + `ipcidr` + `domain` 三条 |
| `fallback_filter.geoip_code` | string | `CN` | 上面那个国家码 |
| `fallback_filter.ipcidr` | string[] | `[]` | 命中这些网段即视为可疑（与内置 bogon 表叠加） |
| `fallback_filter.domain` | string[] | `[]` | 这些域名总是走 `fallback` |
| `enhanced_mode` | string | `normal` | `normal` / `fake-ip`。`fake-ip` 是 **netstack（TUN）** 的职责：只有它能反查合成地址；`dns.listen` 始终回真实地址 |
| `fake_ip_range` | string | `198.18.0.1/16` | fake-IP 池（必须 IPv4，/16–/24） |
| `fake_ip_filter` | string[] | `[]` | 不做 fake 的后缀 |
| `fake_ip_ttl` | u32 | `10` | 交给客户端的 fake 地址 TTL（秒） |
| `hosts` | map | `{}` | 静态解析，先于缓存与任何上游 |
| `use_hosts` | bool | `true` | 是否启用 `hosts` |
| `cache_size` | usize | `4096` | 缓存条数（RecurseX 的 warm 层） |

### 上游写法

| 写法 | 传输 |
|---|---|
| `8.8.8.8`、`8.8.8.8:53`、`8.8.8.8@53` | UDP |
| `udp://…`、`tcp://…` | UDP / TCP |
| `tls://dns.google`、`tls://8.8.8.8:853#dns.google` | DoT |
| `https://dns.google/dns-query` | DoH |
| `h3://dns.google/dns-query` | DoH3 |
| `quic://dns.adguard.com` | DoQ |

加密上游需要验证身份，`#name` 就是被验证的名字——不写时用主机名本身（与旧行为一致）。
RecurseX 只接受 **IP 字面量**：主机名上游会先通过 `default_nameserver`（或 profile 里的 IP 字面量上游）解析，再改写成 `https://8.8.8.8:443/dns-query#dns.google` 交给它。

## inbounds（入站）

```json
{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }
```

`type` 取值：`http` / `socks5` / `mixed` / `redir`（仅 Linux）/ `tproxy`（仅 Linux）/ `tun`。
其余字段会 flatten 进 `options`，如 `authentication` 等。

## outbounds（出站）

通用字段：`type`、`tag`、`server?`、`port?`，其余协议字段 flatten 进 `options`。

| 协议 | `type` 值 | 常用 options |
|---|---|---|
| 直连 | `direct` | — |
| 拒绝 | `reject` | — |
| Shadowsocks | `shadowsocks` / `ss` | `password`, `cipher`（如 `aes-256-gcm`、`chacha20-poly1305`） |
| ShadowsocksR | `shadowsocksr` / `ssr` | `password`, `cipher`（SSR 方法名，如 `aes-256-cfb`、`chacha20-ietf`、`rc4-md5`）, `protocol`（`origin` / `auth_sha1_v4` / `auth_aes128_md5` / `auth_aes128_sha1`）, `obfs`（`plain` / `http_simple` / `http_post` / `tls1.2_ticket_auth`）, `obfs-host`（伪装域名；逗号分隔时每次连接随机取一个，末位是数字的域名会被丢弃——SNI 里出现 IP 本身就是特征）, `protocol-param`（`uid:key`） |
| ShadowTLS v3（需 `shadowtls` feature） | `shadowtls` / `shadow-tls` | `password`, `sni`（要伪装成哪个真实站点，`;`/`,` 分隔可随机取一个；必填）, `fingerprint`（`chrome`/`randomized`/`off`，默认 `chrome`）, `alpn`, `insecure`/`skip-cert-verify`, `version`（只接受 `3`） |
| NaiveProxy | `naive` / `naiveproxy` / `naive-proxy` / `naive+https` | `username`, `password`（两者要成对出现）, `sni`, `skip-cert-verify`/`insecure`, `alpn`（必须包含 `h2`）, `tls`（写 `false` 只对本地回环监听器有意义） |
| Snell | `snell` | `psk`, `version`（`4` 或 `5`，默认 4）, `obfs`（`http`；`tls` 会报错，见下）, `obfs-host`（默认 `bing.com`）, `obfs-uri`（默认 `/`）, `client-id`（默认空）, `reuse`（未实现，配了会警告） |
| VMess | `vmess` | `uuid`, `alter_id`/`alterId`（**`> 0` 自动使用 legacy（pre-AEAD）握手**，因为这类服务器只认旧握手；`= 0` 使用 AEAD）, `cipher`, `tls`, `network`（`tcp`/`ws`；`h2`/`grpc`/`kcp`/`quic` 尚未实现——创建出站时会显式报错，不会静默按裸 TCP 连接）, `ws-opts`（`path`/`headers.Host`）, `alpn`（可选；缺省时 WebSocket 传输只宣告 `http/1.1`，其余传输宣告 `h2` + `http/1.1`）, `sni`, `skip-cert-verify` |
| VLESS | `vless` | `uuid`, `flow`, `tls` 等 |
| Trojan | `trojan` | `password`, `sni` |
| WireGuard | `wireguard` | `private-key`（或 `privateKey`）, `public-key`/`peer-public-key`（对端公钥）, `preshared-key?`, `local-address?`（默认 `10.0.0.2`）, `mtu?`（默认 1420）；`reserved` 不支持：出现即报错，不会被静默忽略 |
| TUIC（需 `tuic` feature） | `tuic` | `uuid`, `password`, `alpn`（默认 `["h3"]`）, `sni`, `skip-cert-verify`, `congestion-controller`（`cubic`/`new_reno`/`bbr`，均驱动 NewReno 控制器）, `udp-relay-mode`（`native`/`quic`）, `heartbeat-interval`（驱动 QUIC 传输保活，而非独立心跳流） |
| Hysteria2（需 `hysteria2` feature） | `hysteria2` / `hy2` | `password`/`auth`, `obfs`（`salamander` + `obfs-password`）, `sni`, `skip-cert-verify`, `alpn`, `up`/`down`（Mbps，仅用于 `hysteria-cc-rx` 速率提示）, `fingerprint`（解析但忽略）, `ports`/`hop-interval`（解析但忽略） |
| Hysteria v1（需 `hysteria` feature） | `hysteria` / `hysteria1` / `hy1` | `auth`（或 `auth-str`/`password`）, `obfs`（即 XPlus 预共享串，留空表示不混淆）, `sni`, `skip-cert-verify`, `alpn`（默认 `hysteria`）, `up`/`down`（BPS 提示，服务器侧计费用）, `disable-mtu-discovery`（无对应项，配了会警告）；`obfs` 写成 `faketcp`/`wechat` 会报错（未实现，且猜错会静默超时） |
| VLESS / Trojan / VMess + REALITY（需 `reality` feature） | `vless` / `trojan` / `vmess` | 在这些出站的 options 里加 `security: "reality"`, `public-key`（服务端 X25519 公钥，base64 或 64 位 hex）, `short-id`（hex，≤8 字节）, `server-name`（伪装 SNI）, `fingerprint`（`chrome`/`randomized`/`off`，默认 `chrome`） |
| SOCKS5 | `socks5` / `socks` | `username`, `password`, `udp` |
| SOCKS4 / SOCKS4a | `socks4` / `socks4a` / `socks4-a` | `version`（`4` 或 `4a`，默认 `4a`）, `user-id`（也接受 `username`）。“走 4 还是 4a”由目标决定：目标是域名时默认用 4a 让服务器解析；写 `version: 4` 则在本机解析域名（会把目标名字泄露给本机解析器，这是该选项的唯一存在理由），IPv6 目标在两种方言下都直接报错——请求格式里没有位置放它。 |
| HTTP / HTTPS | `http` | `username`, `password`, `tls`（`true` 即 HTTPS 代理；也接受 `security: tls`）, `sni`, `skip-cert-verify`, `alpn`（默认仅 `http/1.1`——宣告 `h2` 会让对端用 HTTP/2 回 `CONNECT`，而这个出站只会说 HTTP/1.1）, `fingerprint`（需 `tls13`） |
| 选择组 | `selector` / `select` | `outbounds: [tag,...]`，可选 `use: [provider]` |
| 测速组 | `url-test` / `urltest` | `outbounds`, `url`, `interval` |
| 回退组 | `fallback` | `outbounds`, `url` |
| 负载均衡 | `load-balance` | `outbounds` |
| 中继 | `relay` | `outbounds`（链式） |

> `tuic`、`hysteria`（v1）与 `hysteria2`/`hy2` 是**默认关闭的可选 feature**：需在 Cargo.toml 中显式启用（三者都会启用 `quic`）。未启用时，这些类型在配置校验阶段就会被拒绝，并提示缺失的 feature——不会静默退回直连。
>
> **Hysteria v1 与 Hysteria2 是两个协议**，`hysteria` 不会被当成 `hysteria2` 的别名。差异不只在认证：v1 在控制流上发 struct 编码的 hello，每连接一条双向流，UDP 是 struct 编码的 QUIC 数据报；v2 在双向流上用 HTTP/3 `POST /auth`，TCP 请求帧带 `0x401` 前缀。两者的混淆器也不兼容（XPlus 是 SHA-256 + 16 字节盐，Salamander 是 BLAKE2b-256 + 8 字节盐）。

> **ShadowsocksR 的边界**：实现 `origin` / `auth_sha1_v4` / `auth_aes128_md5` / `auth_aes128_sha1` 四个协议层，以及 `plain` / `http_simple` / `http_post` / `tls1.2_ticket_auth` 四个混淆层，线格式逐字段对照 `shadowsocksr-live/shadowsocksr`。`auth_chain_a/b` 会报错：它们的每帧填充长度不传输，靠双方各自按运行中的 HMAC 和一张 xorshift128+ 生成的表推算，猜错不会报错而是握手之后整体错位。`random_head` 也会报错：首包规则已知（随机串 + 其 CRC-32 的反码），但它要求把客户端整条流压住直到服务端自己的随机包到达，而中继的写路径没有第二个缓冲区。`table`（无密钥无 IV）与 AEAD 方法同样报错并给出替代（AEAD 请用 `shadowsocks` 出站）；UDP 不支持——SSR 的 UDP 帧带每关联的连接 id 与重放窗口，引擎的一次性 UDP 路径无处保存这份状态。填充长度在两种 `auth_*` 里都自描述（`0xFF` 转义 + 半字），所以不同的填充策略是协议合法的；本实现用参考实现的抽取规则，AES 族的填充分布简化为均匀取值，这一点写在模块文档里而不是假装复刻它的 MSS 启发式。

> **ShadowTLS v3 的边界**：只实现 v3 的客户端（`version: 2` 报错——v1/v2 用另一种握手签名构造，规则不同）。它做一次**真实的 TLS 1.3 握手**取伪装，`ClientHello` 的 session id 由 `HMAC-SHA1(password, …)` 签名，握手完成后同一 socket 切换到 ShadowTLS 帧（两个方向各自的滚动 HMAC-SHA1）。服务器协商出非 `0` 的 padding 时会报错：`padding` 请求头的方向位掩码在 `naive_protocol.h` 里没有写明，猜错不会失败而是把隧道整体错位。握手期服务端帧里的 payload 是「整条 TLS 记录」，本实现把它原样交给 TLS 客户端；参考实现保留自己的 5 字节头再改长度，得到一条「内容又是记录」的记录，只有它 fork 过的 rustls 能读——线上字节完全相同，差的只是呈现方式。

> **NaiveProxy 的边界**：ALPN 必须包含 `h2`（服务端用 HTTP/1.1 应答时这个隧道根本没法跑），`CONNECT` 只带 `:method` 与 `:authority`（RFC 9113 §8.3.1 禁止 `CONNECT` 携带 `:scheme`/`:path`），凭据走 `Proxy-Authorization: Basic`，并显式发 `padding-type-request: 0`。隧道是**自研的单流 h2 驱动**（帧编解码复用 `courierust_h2::frame` 与 HPACK，双向流控与窗口归还自己管）：仓库用的 h2 会话编解码器把 `CONNECT` 流当作无 body——收到 `DATA` 会回 `PROTOCOL_ERROR`——而 RFC 9113 §8.3.1 里 `DATA` 就是隧道本身，单流隧道需要的也不是复用与优先级。UDP 不支持：一条 `CONNECT` 只承载一条 TCP 流。
>
> **Snell 的边界**：实现 v4/v5（二者线格式相同）；`version: 6` 会报错（v6 的 shaped 记录需要按 Profile 生成盐块与记录前缀，猜错会表现为认证失败）；`obfs: tls` 也会报错（它靠伪造 ClientHello 的扩展序列骗过检测，那段序列无法逐字节核实，猜错是真服务器上的静默失败）。padding 长度由发送方自描述，因此任何一致策略都是协议正确的——本实现只用参考实现的初始区间，不复制其后继自适应算法，否则等于凭空发明一个指纹。
>
> 同样地，`fingerprint` 需要 `tls13` feature，`security: reality` 需要 `reality` feature（隐含 `tls13`）。REALITY 只实现客户端：session id 按参考格式密封（version/时间/short-id + AES-256-GCM，AAD 为 session-id 清零后的 ClientHello），服务端认证用临时证书证明（证书签名字段 = HMAC-SHA512）；`mldsa65-verify` 未实现，配置里出现会直接报错，收到真证书（回落/MITM）是硬错误。不宣告证书压缩（RFC 8879）与 ALPS。
>
> 三者跑在仓库内自研的 QUIC v1 客户端传输上（`protocol::quic`，RFC 9000/9001/9002，TLS 1.3-over-QUIC 握手，NewReno 拥塞控制）。TUIC 走 v5 线缆协议（uni 流认证 + bi 流 TCP + datagram UDP）；Hysteria2 按官方协议规范实现，认证是 HTTP/3 `POST /auth`；Hysteria v1 按 `apernet/hysteria` v1.3.5 的 `core/cs` 实现。
>
> 明确不支持的选项（配置里出现会报错或警告、不会静默假装）：TUIC 的 `reduce-rtt`/`zero-rtt-handshake`（无 0-RTT）、Hysteria2 的 `fingerprint`/`ports`/`hop-interval`、Hysteria v1 的 UDP（需要每关联一条长活会话流 + 按会话号过滤数据报，引擎的一次性 UDP 路径无处保存这份状态）。

> 任何出站都能加 `skip-cert-verify: true` 跳过 TLS 证书校验（默认关闭，仅显式配置时生效）。

代理组（selector/url-test/fallback/load-balance/relay）两个注意点：

- 成员写在 **`outbounds`** 数组里（tag 列表），至少一个；引用必须在 `outbounds` 段存在，或是 `DIRECT`/`REJECT`（大小写不敏感）；
- 配了 `proxy_providers` 后，`use: ["provider名"]` 会把该订阅的全部节点按 tag 展开进组成员，也可以直接引用订阅节点的 tag。

## rules（规则）

完整语义（含 DNS 解析行为、匹配顺序、`match` 兜底）见 [Rules](Rules#2-规则表rules)。这里只列类型：

| `type` | `payload` 含义 | 示例 |
|---|---|---|
| `domain` | 精确域名 | `"example.com"` |
| `domain-suffix` | 域名后缀（自身+子域） | `"google.com"` |
| `domain-keyword` | 域名关键词 | `"youtube"` |
| `domain-regex` | 域名正则 | `"^\\w+\\.cn$"` |
| `geoip` | 国家/地区代码，或定制库里的提供商标签 | `"cn"` / `"GOOGLE"` |
| `ip-cidr` | 目标 IP 段 | `"10.0.0.0/8"` |
| `src-ip-cidr` | 源 IP 段 | `"192.168.0.0/16"` |
| `src-port` | 源端口/范围 | `"53,80-90"` |
| `dst-port` | 目标端口/范围 | `"443"` |
| `process-name` | 进程名 | `"chrome"` |
| `rule-set` | 规则集名（见 rule_providers） | `"proxy"` |
| `match` | 兜底（所有流量） | `""` |

每条规则都需要 `outbound` 指向已定义的出站 tag；`match` 放最后兜底。

## rule_providers / proxy_providers（外部数据源）

字段、约束、与第三方规则集的对照、后台刷新机制，全部在 [Rules](Rules#4-provider把外部规则和节点拉进来) 里，本文不再重复。

## 校验规则（边界处一次性执行）

- 端口必须在 `1..=65535`，`0` 报错；
- `bind_address` 非空；启用 IPv6 前不能绑裸 IPv6 地址；
- 至少一个 inbound；inbound/outbound 的 `tag` 非空且唯一；
- `redir`/`tproxy` 只在 Linux 上允许；
- 普通出站必须有 `server` 和合法 `port`；代理组必须有 `outbounds`，成员必须可解析（静态 outbound / `DIRECT` / `REJECT` / 已声明的 provider 名；存在 provider 时也允许 provider 动态注入的 tag）；
- 所有规则的 `outbound` 必须通过交叉引用解析；`rule-set` 规则引用的名字必须存在于 `rule_providers`；
- provider 的 `interval ≥ 60`、`http` 必须 https、`file` 必须有 `path`。

## 加载方式

三种等价：

```rust
// 1. 字符串
api::start_proxy_from_yaml(config_json.to_string())?;
// 2. 文件
api::start_proxy_from_file("/path/config.json".to_string())?;
// 3. Rust 结构体
use corduit::engine::Config;
let cfg: Config = nextjson::from_str(&config_json)?;   // 或手写结构体
let engine = corduit::engine::Corduit::new(cfg)?;
```

> `rule_providers` / `proxy_providers` 两个键只在走 `api::*`（`initialize_corduit` / `reload_corduit` / `test_config` / `start_proxy_from_yaml`）时被读取和注入；直接 `Corduit::new(cfg)` 构建的 `Config` 结构体本身没有这两个字段。
