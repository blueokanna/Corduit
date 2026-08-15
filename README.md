# Corduit

A unified network proxy engine in Rust. One crate holds the config model, the
rule router, the DNS stack, a userspace TCP/IP stack and every wire protocol —
nothing is bolted together from third-party proxy cores.

[![Crates.io](https://img.shields.io/crates/v/corduit)](https://crates.io/crates/corduit)
[![docs.rs](https://img.shields.io/docsrs/corduit)](https://docs.rs/corduit)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue)](Cargo.toml)

- **中文说明** → [README.zh-CN.md](README.zh-CN.md)
- **完整文档** → [Wiki](https://github.com/blueokanna/Corduit/wiki)（含 FFI / RPC / 全部方法参考）

---

## What it is

Traditional proxies are composites. Clash, sing-box, V2Ray: each one glues a
config loader, a rule engine, a DNS resolver and a handful of protocol kernels
together, and every piece comes from a different upstream with its own bugs and
release cadence.

Corduit is the opposite: a single engine where configuration, routing, DNS,
userspace networking and the wire protocols live in the same crate, are tested
together, and are released as one unit.

What you get out of the box:

- **Protocols**: Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria2, WireGuard,
  SOCKS5, HTTP(S), QUIC — plus proxy groups (selector, url-test, fallback,
  load-balance, relay).
- **Anti-pollution DNS**: UDP/TCP/DoH/DoT servers and clients, TTL-aware cache,
  fake-IP, hosts, bogon filtering, split resolution.
- **TUN support**: a userspace TCP/IP stack (SolidTCP) with NAT for transparent
  proxying on Windows, Linux, macOS and Android.
- **Hot reload**: `Corduit::reload()` swaps configuration atomically.
- **Traffic accounting**: per-connection upload/download, speed, active list.
- **Three ways to drive it** — see below — all backed by one typed dispatch
  table.

## How you talk to it

Whatever your frontend, it ends up at the same place (`rpc::dispatch`). Three
transports:

| Frontend | Transport | Docs |
|---|---|---|
| Flutter / Kotlin / Swift / C++ | Hand-written C ABI (`corduit_call`, `corduit_call_binary`) | [FFI-API](https://github.com/blueokanna/Corduit/wiki/FFI-API) |
| Browser dashboard / any language | Localhost HTTP + WebSocket JSON-RPC | [RPC-API](https://github.com/blueokanna/Corduit/wiki/RPC-API) |
| Rust application | Typed async `api::*` | [Rust-API](https://github.com/blueokanna/Corduit/wiki/Rust-API) |

## Quick start

```toml
[dependencies]
corduit = "0.1"
tokio = { version = "1", features = ["full"] }
```

```rust,no_run
use corduit::api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    api::start_proxy_from_yaml(r#"{
      "general": { "mode": "rule", "mixed_port": 7890, "log_level": "info" },
      "dns": { "enable": true, "nameservers": ["https://dns.google/dns-query"] },
      "inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }],
      "outbounds": [{ "type": "direct", "tag": "DIRECT" }],
      "rules": []
    }"#.to_string()).await?;

    let status = api::get_corduit_status().await?;
    println!("running = {}", status.running);
    api::stop_proxy().await?;
    Ok(())
}
```

Or expose it to a web dashboard in two lines:

```rust,no_run
use corduit::api;
api::start_rpc_server(8765, Some("my-token".into())).await?; // 127.0.0.1 only
```

```bash
curl -X POST http://127.0.0.1:8765/rpc \
  -H "Authorization: Bearer my-token" \
  -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'
# {"code":0,"data":"Corduit v0.1.0"}
```

## Configuration

A single validated JSON model: `general` / `dns` / `inbounds` / `outbounds` /
`rules`. Every enum is a string; invalid values are rejected at the boundary,
before the engine touches them. Full field-by-field reference:
[Configuration](https://github.com/blueokanna/Corduit/wiki/Configuration).

## Project layout

```
src/
├── lib.rs          # module wiring, globals, platform entry points
├── api.rs          # typed async API
├── ffi.rs          # hand-written C ABI
├── rpc/            # shared dispatch + localhost HTTP/WebSocket JSON-RPC
├── types.rs        # shared DTOs
├── common/         # URL parser + HTTP client
├── engine/         # config, routing, inbound/outbound, stats
├── crypto/         # in-repo crypto primitives
├── protocol/       # wire protocols (TLS, QUIC, TUIC, WireGuard…)
├── dns/            # DNS servers/clients, cache, fake-IP
└── netstack/       # userspace TCP/IP, TUN, NAT, VPN drivers
```

## Building & testing

```bash
cargo check --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
```

MSRV: Rust 1.95.

## Security

This is a local tool that controls network traffic, so the boundary matters:

- **FFI**: no panic ever unwinds across `extern "C"`; all arguments are
  type-checked; the binary channel is bounded (`rustbinary`, 64 MiB cap).
- **RPC server**: binds to `127.0.0.1` only, requires a bearer token compared
  in constant time, bodies capped at 16 MiB, idle connections reaped.
- **The rest**: DNS compression pointers capped, MMDB reads bounds-checked,
  HTTP response bodies capped, `skip-cert-verify` off by default.

More: [Security](https://github.com/blueokanna/Corduit/wiki/Security).

## License

PolyForm Perimeter 1.0.1. Use, modify and distribute freely; the only
restriction is offering a product that substitutes for Corduit itself.
