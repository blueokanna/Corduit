# 配置（Configuration）

配置是一个 **nextjson 原生 JSON 对象**（零 serde），包含五段：`general` / `dns` / `inbounds` / `outbounds` / `rules`。所有枚举值都是字符串（见各表），未知字段或类型不合法会在 `validate()` 时报错。

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
      "tag": "auto",
      "proxies": ["DIRECT", "ss-jp"]
    }
  ],
  "rules": [
    { "type": "domain-suffix", "payload": "google.com", "outbound": "ss-jp" },
    { "type": "geoip", "payload": "cn", "outbound": "DIRECT" },
    { "type": "match", "payload": "", "outbound": "ss-jp" }
  ]
}
```

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
| `mode` | string | `rule` | `rule` / `global` / `direct` |
| `log_level` | string | `info` | `silent` / `error` / `warning` / `info` / `debug` |
| `ipv6` | bool | `false` | 启用 IPv6 |
| `tcp_concurrent` | bool | `false` | TCP 并发连接 |
| `external_controller` | string? | — | 外部控制器地址 |
| `external_ui` | string? | — | 外部 UI 路径 |
| `secret` | string? | — | 控制器密钥 |

## dns（DNS）

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `enable` | bool | `false` | 启动本地 DNS 服务 |
| `listen` | string | `127.0.0.1:53` | DNS 服务监听地址 |
| `nameservers` | string[] | `8.8.8.8, 1.1.1.1` | 主上游（支持 DoH：`https://...`） |
| `fallback` | string[] | `8.8.4.4, 1.0.0.1` | 回退上游（抗污染） |
| `enhanced_mode` | string | `normal` | `normal` / `fake-ip` |

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
| VMess | `vmess` | `uuid`, `alter_id`, `cipher`, `tls` 等 |
| VLESS | `vless` | `uuid`, `flow`, `tls` 等 |
| Trojan | `trojan` | `password`, `sni` |
| WireGuard | `wireguard` | `private_key`, `public_key`, `endpoint`, `allowed_ips` |
| SOCKS5 | `socks5` / `socks` | `username`, `password`, `udp` |
| HTTP | `http` | `username`, `password` |
| TUIC | `tuic` | `uuid`, `password`, `congestion_control` |
| Hysteria2 | `hysteria2` / `hy2` | `password`, `up`, `down`, `sni` |
| QUIC | `quic` / `shadowquic` | `password`, `cipher` |
| 选择组 | `selector` / `select` | `proxies: [tag,...]` |
| 测速组 | `url-test` / `urltest` | `proxies`, `url`, `interval` |
| 回退组 | `fallback` | `proxies`, `url` |
| 负载均衡 | `load-balance` | `proxies` |
| 中继 | `relay` | `proxies`（链式） |

> 任何出站都能加 `skip-cert-verify: true` 跳过 TLS 证书校验（默认关闭，仅显式配置时生效）。

## rules（规则）

| `type` | `payload` 含义 | 示例 |
|---|---|---|
| `domain` | 精确域名 | `"example.com"` |
| `domain-suffix` | 域名后缀 | `"google.com"` 匹配 `*.google.com` |
| `domain-keyword` | 域名关键词 | `"youtube"` |
| `domain-regex` | 域名正则 | `"^\\w+\\.cn$"` |
| `geoip` | 国家/地区代码 | `"cn"` |
| `ip-cidr` | 目标 IP 段 | `"10.0.0.0/8"` |
| `src-ip-cidr` | 源 IP 段 | `"192.168.0.0/16"` |
| `src-port` | 源端口 | `"53"` |
| `dst-port` | 目标端口 | `"443"` |
| `process-name` | 进程名 | `"chrome"` |
| `rule-set` | 规则集名 | `"proxy"` |
| `match` | 兜底（所有流量） | `""` |

每条规则都需要 `outbound` 指向已定义的出站 tag；`match` 建议放在最后兜底。

## 校验规则（边界处一次性执行）

- 端口必须在 `1..=65535`，`0` 报错；
- `bind_address` 非空；启用 IPv6 前不能绑裸 IPv6 地址；
- 至少一个 inbound；inbound/outbound 的 `tag` 非空且唯一；
- `redir`/`tproxy` 只在 Linux 上允许；
- 所有规则的 `outbound` 必须能通过交叉引用解析。

## 加载方式

三种等价：

```rust
// 1. 字符串
api::start_proxy_from_yaml(config_json.to_string()).await?;
// 2. 文件
api::start_proxy_from_file("/path/config.json".to_string()).await?;
// 3. Rust 结构体
use corduit::engine::Config;
let cfg: Config = nextjson::from_str(&config_json)?;   // 或手写结构体
let engine = corduit::engine::Corduit::new(cfg).await?;
```
