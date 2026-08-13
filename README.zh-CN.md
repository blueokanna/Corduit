# Corduit

> **用 Rust 编写的统一、非组合式网络代理引擎。**
> 一个引擎，覆盖所有协议。

[![Crates.io](https://img.shields.io/crates/v/corduit-core)](https://crates.io/crates/corduit-core)
[![docs.rs](https://img.shields.io/docsrs/corduit-core)](https://docs.rs/corduit-core)
[![License](https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77-blue)](Cargo.toml)

---

## 为什么选择 Corduit

传统代理栈（Clash、sing-box、V2Ray、Xray）都是**组合式**的：它们把配置加载器、
规则引擎、DNS 解析器、TUN 驱动和一堆代理协议强行拼装在一起——每个部分来自
不同的上游，各有各的发布节奏、各自的 Bug、各自的破坏性变更。

**Corduit 作为全新的产品。** 它是一个统一设计、一体构建的引擎：配置、路由、
DNS、用户态网络、线缆协议每一层都是同一个工作区的头等公民，一起设计、一起
测试、一起发布。

| | Clash（组合式） | Corduit（统一式） |
|---|---|---|
| 协议实现 | Fork/嵌入第三方 | 仓库内原生实现，单一版本 |
| 规则引擎 | 多个 crate 胶水拼接 | 单一强类型 `RuleConfig` 流水线 |
| DNS | 多个可选 crate | 自带抗污染 `corduit-dns` |
| TUN 栈 | 外部库 | 仓库内用户态 TCP/IP（SolidTCP） |
| 配置 | 多种格式、多套加载器 | 单一校验过的 `Config` 模型 |
| 发布节奏 | 各组件各自为政 | 全工作区原子发布 |

---

## 核心特性

- **统一引擎** —— 一切围绕一个 `Corduit` 入口：配置校验、入站监听、出站池、
  路由、DNS 与流量统计。
- **完整协议覆盖** —— Shadowsocks、VMess、VLESS、Trojan、TUIC、Hysteria2、
  WireGuard、SOCKS5、HTTP(S)、QUIC，以及代理组（选择、URL 测速、故障回退、
  负载均衡、中继）。
- **抗污染 DNS** —— UDP/TCP/DoH/DoT 服务端与客户端、TTL 感知缓存、Fake-IP
  模式、hosts 文件、Bogon 过滤、国内外分流解析。
- **仓库内用户态网络栈** —— `corduit-netstack` 提供基于 smoltcp 的 TCP/IP
  栈（SolidTCP）与 NAT，在 Windows、Linux、macOS、Android 上实现透明 TUN
  代理。
- **高内聚、低耦合** —— 通过 `CountryMatcher` trait 反转 GeoIP 依赖，规则引擎
  不依赖任何具体数据库；每个 crate 只依赖稳定的最小接口。
- **手写 C ABI** —— `corduit-lib` 提供无依赖、手写的 `#[no_mangle] extern "C"`
  接口（不使用 `flutter_rust_bridge`，无代码生成），可被 Flutter/Dart、Kotlin、
  Swift、C/C++ 宿主直接绑定。
- **nextjson + rustbinary 序列化** —— FFI 边界使用 `nextjson`（schema 驱动
  JSON）承载可读负载，`rustbinary`（有界、类型标记二进制）承载紧凑高吞吐
  通道——API 层不再使用 `serde`/`serde_json`。
- **热重载** —— `Corduit::reload()` 原子化替换配置。
- **可观测性** —— 基于 `tracing` 的结构化日志，`jaeger` feature 下可导出
  OpenTelemetry / Jaeger，并提供逐连接流量统计。
- **移动端就绪** —— `corduit-lib` 提供 Android JNI（`VpnService`）、Windows
  VPN 集成，以及面向任意原生宿主的统一 `corduit_call` / `corduit_call_binary`
  分发入口。
- **对生态友好的许可** —— FSL-1.1-Apache-2.0：允许商业修改、集成与商业化，
  仅限制竞争性托管服务；发布 **2 年后自动转为 Apache 2.0**。

---

## 工作区架构

```
Corduit（工作区）
│
├── corduit-core        # 引擎：配置模型、规则流水线、出站编排、
│   │                   #       流量统计、健康检查
│   └── src/
│       ├── config/     #   强类型校验配置 + YAML 映射
│       ├── inbound/    #   HTTP / SOCKS5 / mixed 监听
│       ├── outbound/   #   Direct/Reject/SS/VMess/VLESS/Trojan/TUIC/Hy2/...
│       ├── routing.rs  #   规则 → 出站匹配（rule/global/direct）
│       ├── geoip.rs    #   CountryMatcher trait（依赖倒置）
│       └── proxy.rs    #   ProxyManager：总协调者
│
├── corduit-protocol    # 线缆协议：QUIC、TLS、WireGuard、TUIC、
│                       #   传输层（h2/gRPC/WebSocket/TLS）
│
├── corduit-dns         # DNS：DoH/DoT/UDP/TCP 服务端与客户端、缓存、
│                       #   fake-IP、hosts、抗污染、分流解析
│
├── corduit-netstack    # 用户态 TCP/IP（SolidTCP）、TUN 设备、NAT、
│                       #   Windows/macOS/Linux/Android VPN 驱动
│
└── corduit-lib         # 手写 C ABI + Android JNI + 移动端绑定
```

```
                       ┌─────────────────────────────┐
                       │          Corduit            │
                       │       (corduit-core)        │
                       │                             │
  HTTP/SOCKS ─────────►│  inbound/*  ──►  routing.rs  │
  redir/TProxy ────────►│              │      │       │
  TUN (netstack) ──────►│              ▼      ▼       │
                       │        outbound/*  DNS (dns) │
                       │              │      │       │
                       │              ▼      ▼       │
                       │       proxy groups   fake-IP │
                       └──────────────┬──────────────┘
                                      ▼
                          corduit-protocol (wire)
```

---

## 快速开始

### 作为库使用

```toml
[dependencies]
corduit-core = { version = "0.1", features = ["jaeger"] }   # 引擎
corduit-dns  = "0.1"                                         # DNS（可选）
corduit-netstack = "0.1"                                     # TUN（可选）
```

```rust,no_run
use corduit_core::{Config, Corduit};
use corduit_core::config::{GeneralConfig, DnsConfig, InboundConfig,
                          InboundType, Mode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 构建并校验配置（不 panic —— 错误全部是类型化的）。
    let config = Config {
        general: GeneralConfig {
            mode: Mode::Rule,
            allow_lan: false,
            mixed_port: Some(7890),   // HTTP + SOCKS5 同端口
            ..Default::default()
        },
        dns: DnsConfig {
            enable: true,
            nameservers: vec!["https://dns.google/dns-query".into()],
            fallback: vec!["8.8.8.8".into()],
            ..Default::default()
        },
        inbounds: vec![InboundConfig {
            inbound_type: InboundType::Mixed,
            tag: "mixed-in".into(),
            listen: "127.0.0.1".into(),
            port: 7890,
            ..Default::default()
        }],
        outbounds: vec![ /* ... */ ],
        rules: vec![ /* ... */ ],
    };

    let mut corduit = Corduit::new(config).await?;
    corduit.start().await?;
    println!("运行中，已运行 {} 秒", corduit.uptime_secs());

    // 热重载：运行时原子替换配置。
    // corduit.reload(new_config).await?;

    tokio::signal::ctrl_c().await?;
    corduit.stop().await?;
    Ok(())
}
```

### 独立 DNS 引擎

```rust,no_run
use corduit_dns::manager::DnsManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dns = DnsManager::new()?;                    // 合理默认值
    let addrs = dns.resolve("example.com").await?;   // -> Vec<IpAddr>
    println!("{addrs:?}");

    dns.start_server().await?;                       // 启动本地解析服务
    Ok(())
}
```

---

## 配置

Corduit 使用单一、经校验、可映射到 YAML 的 `Config` 模型——没有临时方言，
没有多种格式。最小 `config.yaml`：

```yaml
general:
  mode: rule                # rule | global | direct
  mixed_port: 7890          # HTTP + SOCKS5 同端口
  allow_lan: false
  log_level: info

dns:
  enable: true
  listen: 0.0.0.0:53
  nameservers:
    - https://dns.google/dns-query
  fallback:
    - 8.8.8.8
  enhanced_mode: fake-ip

inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    port: 7890

outbounds:
  - type: direct
    tag: DIRECT
  - type: selector
    tag: PROXY
    options:
      proxies: [proxy-1, proxy-2]
  - type: vmess
    tag: proxy-1
    server: vmess.example.com
    port: 443
    options:
      uuid: 00000000-0000-0000-0000-000000000000
      security: auto
  - type: tuic
    tag: proxy-2
    server: tuic.example.com
    port: 443
    options:
      uuid: 00000000-0000-0000-0000-000000000000
      password: secret
  - type: hysteria2
    tag: hy2
    server: hy2.example.com
    port: 443
    options:
      password: secret

rules:
  - type: domain_suffix
    payload: example.com
    outbound: DIRECT
  - type: geoip
    payload: cn
    outbound: DIRECT
  - type: match
    payload: ""
    outbound: PROXY
```

所有枚举均为强类型：`OutboundType` 覆盖 `direct`、`reject`、`shadowsocks`、
`vmess`、`vless`、`trojan`、`tuic`、`hysteria2`、`quic`、`socks5`、`http`、
`wireguard`，以及代理组 `selector`、`url-test`、`fallback`、`load-balance`、
`relay`。`RuleType` 覆盖 `domain`、`domain_suffix`、`domain_keyword`、
`domain_regex`、`geoip`、`ip_cidr`、`src_ip_cidr`、`src_port`、`dst_port`、
`process_name`、`rule_set`、`match`。

---

## 支持的协议

| 层次 | 协议 |
|---|---|
| 代理出站 | Shadowsocks、VMess、VLESS、Trojan、TUIC、Hysteria2、SOCKS5、HTTP(S)、QUIC、WireGuard、Direct、Reject |
| 代理组 | Selector、URL-test、Fallback、Load-balance、Relay |
| 入站 | HTTP、SOCKS5、Mixed（Linux 下 redir / TProxy） |
| 传输层 | WebSocket、h2、gRPC、TLS、QUIC |
| DNS | UDP、TCP、DoH、DoT —— 服务端与客户端 |
| TUN | 用户态 TCP/IP（SolidTCP）带 NAT |

---

## 平台支持

| 平台 | 入站 | TUN | 说明 |
|---|---|---|---|
| Windows | ✓ | ✓ | wintun（自动下载或 `embed-wintun` feature） |
| Linux | ✓ | ✓ | TUN 需要 `CAP_NET_ADMIN` |
| macOS | ✓ | ✓ | TUN 需要 root |
| Android | ✓ | ✓ | 经 JNI 使用 VpnService（`corduit-lib`） |
| Flutter | — | — | 经 `corduit-lib` 手写 C ABI（`corduit_call`） |

---

## 文档

- `corduit-core` —— [docs.rs/corduit-core](https://docs.rs/corduit-core)
- `corduit-protocol` —— [docs.rs/corduit-protocol](https://docs.rs/corduit-protocol)
- `corduit-dns` —— [docs.rs/corduit-dns](https://docs.rs/corduit-dns)
- `corduit-netstack` —— [docs.rs/corduit-netstack](https://docs.rs/corduit-netstack)
- `corduit-lib` —— [docs.rs/corduit-lib](https://docs.rs/corduit-lib)

每个 crate 都带有完整的 rustdoc：架构图与 `no_run` 示例，并在 docs.rs 上以
`all-features` 构建。

---

## 设计原则

1. **一个工作区、一个版本。** 每个 crate 共享工作区清单；任何 crate 都不在
   本地固定依赖版本——一律 `{ workspace = true }`。升级传递依赖只需改一处
   `Cargo.toml`。
2. **依赖抽象。** `routing` 依赖 `CountryMatcher` 而非 MaxMind；`Corduit`
   依赖 `ProxyManager` 的稳定接口而非各协议的内部细节。替换实现无需改动调用方。
3. **在边界处大声失败。** 配置在入口处一次性校验；内部代码只处理已校验、
   类型化的数据。
4. **不引入虚构依赖。** 锁文件中的每个依赖都是真实且被使用的；线缆格式为
   手写实现并由属性测试覆盖。

---

## 构建

```bash
# 全工作区检查 + 测试
cargo test --workspace

# 生成与 docs.rs 完全一致的文档
cargo doc --workspace --all-features --no-deps

# 发布构建
cargo build --release --workspace
```

MSRV：**Rust 1.77+**（edition 2021）。

### 发布到 crates.io

成员 crate 通过工作区清单中的 `path` + `version` 相互依赖，因此请**按依赖顺序**
发布：

```bash
cargo publish -p corduit-protocol   # 第 1 个（无内部依赖）
cargo publish -p corduit-dns        # 第 2 个（无内部依赖）
cargo publish -p corduit-netstack   # 第 3 个（依赖 corduit-dns）
cargo publish -p corduit-core       # 第 4 个（依赖 corduit-protocol）
cargo publish -p corduit-lib        # 第 5 个（依赖 core + netstack）
```

每个 crate 都会在 docs.rs 上以 `all-features` 构建。

---

## 许可证

[FSL-1.1-Apache-2.0](LICENSE) —— **Functional Source License, Version 1.1,
ALv2 Future License**（Sentry 推出的新一代许可证）。

- ✅ 允许自由使用、修改、集成与商业化
- ✅ 允许再分发，包括衍生作品
- ✅ 为许可目的授予专利
- 🚫 仅禁止**竞争性托管服务**
- 🔁 每个版本发布 **2 年后自动转为 Apache License 2.0**

SPDX 标识符：`FSL-1.1-Apache-2.0`

---

## 参与贡献

Corduit 在架构上就是一个连贯的整体。提交 PR 前请注意：

- **协议**在 `corduit-protocol`；保持线缆格式稳定并用往返测试覆盖。
- **路由 / 配置**在 `corduit-core`；保持规则流水线强类型，GeoIP 依赖通过
  `CountryMatcher` 倒置。
- **DNS** 在 `corduit-dns`；保持抗污染与缓存语义有测试覆盖。
- **网络**在 `corduit-netstack`；保持用户态栈自包含并通过 NAT 测试。
- 提交前运行 `cargo test --workspace`。
