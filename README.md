# Corduit

> **A unified, non-composite network proxy engine written in Rust.**
> One engine. Every protocol.

[![Crates.io](https://img.shields.io/crates/v/corduit-core)](https://crates.io/crates/corduit-core)
[![docs.rs](https://img.shields.io/docsrs/corduit-core)](https://docs.rs/corduit-core)
[![License](https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77-blue)](Cargo.toml)

---

## Why Corduit

Traditional proxy stacks (Clash, sing-box, V2Ray, Xray) are **composites**: they
bolt together a config loader, a rule engine, a DNS resolver, a TUN driver and a
handful of proxy protocols — each owned by a different upstream, each with its
own release cadence, its own bugs, and its own breaking changes.

**Corduit is a new product.** It is a single, purpose-built engine where every
layer — configuration, routing, DNS, userspace networking, and wire protocols —
is a first-class member of one workspace, designed together, tested together,
and released together.

| | Clash (composite) | Corduit (unified) |
|---|---|---|
| Protocol implementations | Forked/embedded third-party | Native, in-repo, one version |
| Rule engine | Separate crates glued together | Single typed `RuleConfig` pipeline |
| DNS | Multiple optional crates | Dedicated `corduit-dns` with anti-spoofing |
| TUN stack | External libraries | In-repo userspace TCP/IP (SolidTCP) |
| Configuration | Many formats, many loaders | One validated `Config` model |
| Release cadence | Per-component | Whole-workspace, atomic |

---

## Features

- **Unified engine** — one `Corduit` entry point for everything: config
  validation, inbound listeners, outbound pools, routing, DNS and traffic
  accounting.
- **Full protocol coverage** — Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria2,
  WireGuard, SOCKS5, HTTP(S), QUIC — plus proxy groups (selector, URL-test,
  fallback, load-balance, relay).
- **Anti-spoofing DNS** — UDP/TCP/DoH/DoT servers and clients, TTL-aware caching,
  fake-IP mode, hosts file, bogon filtering, domestic/foreign split resolution.
- **In-repo userspace network stack** — `corduit-netstack` brings a smoltcp-based
  TCP/IP stack (SolidTCP) with NAT for transparent TUN proxying on Windows,
  Linux, macOS and Android.
- **High cohesion, low coupling** — a `CountryMatcher` trait inverts the GeoIP
  dependency so the rule engine never depends on a concrete database; every
  crate depends only on stable, minimal interfaces.
- **Hand-written C ABI** — `corduit-lib` exposes a dependency-free, hand-written
  `#[no_mangle] extern "C"` surface (no `flutter_rust_bridge`, no codegen) for
  Flutter/Dart, Kotlin, Swift and C/C++ hosts.
- **nextjson + rustbinary serialization** — the FFI boundary speaks
  `nextjson` (schema-driven JSON) for human-readable payloads and `rustbinary`
  (bounded, type-tagged binary) for compact high-throughput channels — no
  `serde`/`serde_json` in the API layer.
- **Hot reload** — `Corduit::reload()` swaps configuration atomically.
- **Observability** — `tracing`-based structured logging, optional OpenTelemetry /
  Jaeger export behind the `jaeger` feature, and per-connection traffic stats.
- **Mobile-ready** — `corduit-lib` ships Android JNI (`VpnService`), Windows VPN
  integrations, and a unified `corduit_call` / `corduit_call_binary` dispatcher
  for any native host.
- **Licensed for the ecosystem** — FSL-1.1-Apache-2.0: commercial use and
  modification are allowed; only competing hosted service is restricted, and the
  code automatically becomes **Apache 2.0 after 2 years**.

---

## Workspace Architecture

```
Corduit (workspace)
│
├── corduit-core        # Engine: config model, rule pipeline, outbound
│   │                   #         orchestration, traffic stats, health checks
│   └── src/
│       ├── config/     #   Typed, validated configuration + YAML mapping
│       ├── inbound/    #   HTTP / SOCKS5 / mixed listeners
│       ├── outbound/   #   Direct/Reject/SS/VMess/VLESS/Trojan/TUIC/Hy2/...
│       ├── routing.rs  #   Rule → outbound matching (rule/global/direct)
│       ├── geoip.rs    #   CountryMatcher trait (dependency inversion)
│       └── proxy.rs    #   ProxyManager: the coordinator
│
├── corduit-protocol    # Wire protocols: QUIC, TLS, WireGuard, TUIC,
│                       #   transports (h2/gRPC/WebSocket/TLS)
│
├── corduit-dns         # DNS: DoH/DoT/UDP/TCP servers & clients, cache,
│                       #   fake-IP, hosts, anti-spoofing, split resolution
│
├── corduit-netstack    # Userspace TCP/IP (SolidTCP), TUN devices, NAT,
│                       #   Windows/macOS/Linux/Android VPN drivers
│
└── corduit-lib         # Hand-written C ABI + Android JNI + mobile bindings
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

## Quick Start

### As a library

```toml
[dependencies]
corduit-core = { version = "0.1", features = ["jaeger"] }   # engine
corduit-dns  = "0.1"                                         # DNS (optional)
corduit-netstack = "0.1"                                     # TUN (optional)
```

```rust,no_run
use corduit_core::{Config, Corduit};
use corduit_core::config::{GeneralConfig, DnsConfig, InboundConfig,
                          InboundType, Mode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build and validate a configuration (panics nowhere — errors are typed).
    let config = Config {
        general: GeneralConfig {
            mode: Mode::Rule,
            allow_lan: false,
            mixed_port: Some(7890),   // HTTP + SOCKS5 on one port
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
    println!("running, uptime = {}s", corduit.uptime_secs());

    // Hot reload: swap config at runtime.
    // corduit.reload(new_config).await?;

    tokio::signal::ctrl_c().await?;
    corduit.stop().await?;
    Ok(())
}
```

### Standalone DNS engine

```rust,no_run
use corduit_dns::manager::DnsManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dns = DnsManager::new()?;                    // sane defaults
    let addrs = dns.resolve("example.com").await?;   // -> Vec<IpAddr>
    println!("{addrs:?}");

    dns.start_server().await?;                       // local resolver
    Ok(())
}
```

---

## Configuration

Corduit uses a single validated, YAML-mapped `Config` model — no ad-hoc toml,
no multiple dialects. A minimal `config.yaml`:

```yaml
general:
  mode: rule                # rule | global | direct
  mixed_port: 7890          # HTTP + SOCKS5 on one port
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

All enums are strongly typed: `OutboundType` covers `direct`, `reject`,
`shadowsocks`, `vmess`, `vless`, `trojan`, `tuic`, `hysteria2`, `quic`,
`socks5`, `http`, `wireguard`, plus groups `selector`, `url-test`, `fallback`,
`load-balance`, `relay`. `RuleType` covers `domain`, `domain_suffix`,
`domain_keyword`, `domain_regex`, `geoip`, `ip_cidr`, `src_ip_cidr`, `src_port`,
`dst_port`, `process_name`, `rule_set`, `match`.

---

## Supported Protocols

| Layer | Protocols |
|---|---|
| Proxy outbounds | Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria2, SOCKS5, HTTP(S), QUIC, WireGuard, Direct, Reject |
| Proxy groups | Selector, URL-test, Fallback, Load-balance, Relay |
| Inbounds | HTTP, SOCKS5, Mixed, (redir / TProxy on Linux) |
| Transports | WebSocket, h2, gRPC, TLS, QUIC |
| DNS | UDP, TCP, DoH, DoT — client & server |
| TUN | Userspace TCP/IP (SolidTCP) with NAT |

---

## Platform Support

| Platform | Inbound | TUN | Notes |
|---|---|---|---|
| Windows | ✓ | ✓ | wintun (auto-download or `embed-wintun` feature) |
| Linux | ✓ | ✓ | requires `CAP_NET_ADMIN` for TUN |
| macOS | ✓ | ✓ | requires root for TUN |
| Android | ✓ | ✓ | VpnService via JNI (`corduit-lib`) |
| Flutter | — | — | Hand-written C ABI via `corduit-lib` (`corduit_call`) |

---

## Documentation

- `corduit-core` — [docs.rs/corduit-core](https://docs.rs/corduit-core)
- `corduit-protocol` — [docs.rs/corduit-protocol](https://docs.rs/corduit-protocol)
- `corduit-dns` — [docs.rs/corduit-dns](https://docs.rs/corduit-dns)
- `corduit-netstack` — [docs.rs/corduit-netstack](https://docs.rs/corduit-netstack)
- `corduit-lib` — [docs.rs/corduit-lib](https://docs.rs/corduit-lib)

Each crate ships complete rustdoc with architecture diagrams and `no_run`
examples, built with `all-features` on docs.rs.

---

## Design Principles

1. **One workspace, one version.** Every crate shares the workspace manifest;
   no crate pins a dependency version locally — everything is
   `{ workspace = true }`. Upgrading a transitive dependency is a single change
   in `Cargo.toml`.
2. **Depend on abstractions.** `routing` depends on `CountryMatcher`, not on
   MaxMind; `Corduit` depends on `ProxyManager`'s stable surface, not on the
   innards of each protocol. Swap implementations without touching callers.
3. **Fail loudly at the boundary.** Configuration is validated once at the
   edge; interior code works on already-validated, typed data.
4. **No fabricated dependencies.** Every dependency in the lockfile is real and
   used; the wire formats are hand-implemented and covered by property tests.

---

## Building

```bash
# Full workspace check + tests
cargo test --workspace

# Docs, exactly as docs.rs builds them
cargo doc --workspace --all-features --no-deps

# Release build
cargo build --release --workspace
```

MSRV: **Rust 1.77+** (edition 2021).

### Publishing to crates.io

Member crates depend on each other via `path` + `version` in the workspace
manifest, so publish them **in dependency order**:

```bash
cargo publish -p corduit-protocol   # 1st (no internal deps)
cargo publish -p corduit-dns        # 2nd (no internal deps)
cargo publish -p corduit-netstack   # 3rd (depends on corduit-dns)
cargo publish -p corduit-core       # 4th (depends on corduit-protocol)
cargo publish -p corduit-lib        # 5th (depends on core + netstack)
```

Each crate is built with `all-features` on docs.rs.

---

## License

[FSL-1.1-Apache-2.0](LICENSE) — **Functional Source License, Version 1.1, ALv2
Future License** (Sentry's next-generation license).

- ✅ Use, modify, integrate and commercialize freely
- ✅ Redistribute, including derivatives
- ✅ Patents granted for permitted purposes
- 🚫 **Competing hosted service** only
- 🔁 Automatically becomes **Apache License 2.0** on the second anniversary of
  each release

SPDX identifier: `FSL-1.1-Apache-2.0`

---

## Contributing

Corduit is a single, coherent engine by design. Before opening a PR, consider:

- **Protocols** live in `corduit-protocol`; keep wire formats stable and cover
  them with round-trip tests.
- **Routing / config** live in `corduit-core`; keep the rule pipeline typed and
  the GeoIP dependency inverted behind `CountryMatcher`.
- **DNS** lives in `corduit-dns`; keep anti-spoofing and cache semantics
  covered by tests.
- **Networking** lives in `corduit-netstack`; keep the userspace stack
  self-contained and NAT-tested.
- Run `cargo test --workspace` before submitting.
