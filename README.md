# Corduit

A synchronous, no_std-ready unified network proxy engine in Rust. One crate
holds the config model, the rule router, the DNS stack, a userspace TCP/IP
stack and every wire protocol — nothing is bolted together from third-party
proxy cores, and **there is no async runtime anywhere in the dependency
tree**.

[![Crates.io](https://img.shields.io/crates/v/corduit)](https://crates.io/crates/corduit)
[![docs.rs](https://img.shields.io/docsrs/corduit)](https://docs.rs/corduit)
[![MSRV](https://img.shields.io/badge/MSRV-1.78-blue)](Cargo.toml)

- **中文说明** → [README.zh-CN.md](README.zh-CN.md)
- **完整文档** → [Wiki](https://github.com/blueokanna/Corduit/wiki)（含 FFI / RPC / 全部方法参考）

---

## Legal notice — read this before you build all components or run programs

Corduit is a network engineering toolkit: proxy protocols, a rule router, DNS
and a userspace TCP/IP stack. It is published for **lawful use only**.

- **Your local law governs.** Nothing in this repository, its license, or its
documentation grants you any permission that the law applying to you does not
already give you. You alone are responsible for how you use it.
- **Do not use it to break the law.** In some jurisdictions — mainland China
included — providing or using a proxy, VPN, or tunnel service to bypass state
network controls is illegal. Corduit grants no right to do that; the
maintainers neither authorize nor support it.
- **TUIC and Hysteria2 are opt-in.** Both are disabled Cargo features
(`tuic`, `hysteria2`) and are absent from a default build. Enabling them is
an explicit, deliberate decision of yours.
- **Unlawful use gets no support.** Issues, pull requests, and discussions
that would enable unlawful use will be closed.
- **No warranty, no liability.** The software is provided as is. See
[LICENSE](LICENSE), whose additional licensor terms make lawful use a
condition of every license granted.
- **This is not legal advice.** If you are unsure whether your intended use
is lawful, consult a qualified lawyer in your jurisdiction before building
or running anything.

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

- **Protocols**: Shadowsocks, VMess, VLESS, Trojan, WireGuard, SOCKS5,
  HTTP(S) — plus opt-in TUIC v5 (`tuic`) and Hysteria2 (`hysteria2`)
  outbounds, and proxy groups (selector, url-test, fallback, load-balance,
  relay).
- **Synchronous by design**: no tokio, no reactor, no `async`/`await` in the
  engine. Concurrency comes from courierust's work-stealing thread pool for
  short tasks and dedicated threads for long-lived relays. `cargo tree`
  reports **zero** `tokio` / `futures` / `async-trait` packages.
- **no_std core**: with `default-features = false` the crate compiles on
  `no_std + alloc` targets — the crypto primitives, URL parser and the pure
  wire codecs (SOCKS-style addresses, QPACK/HPACK, DNS wire) have zero OS
  dependencies.
- **Self-contained HTTP/TLS/QUIC**: every HTTP/1.1, HTTP/2, HTTP/3,
  TLS 1.2/1.3, WebSocket and QUIC v1 exchange runs on
  [courierust](https://crates.io/crates/courierust) plus in-tree codecs —
  including a from-scratch QUIC v1 client transport (RFC 9000/9001/9002)
  with its own TLS 1.3-over-QUIC handshake and QPACK/HPACK header codec
  (the QUIC transport is the optional `quic` feature).
  No hyper, no rustls, no quinn, no tokio.
- **Anti-pollution DNS**: UDP/TCP/DoH/DoT servers and clients, TTL-aware cache,
  fake-IP, hosts, bogon filtering, split resolution.
- **TUN support**: a userspace TCP/IP stack (SolidTCP) with NAT for transparent
  proxying on Windows, Linux, macOS and Android.
- **Hot reload**: `Corduit::reload()` swaps configuration atomically.
- **Traffic accounting**: per-connection upload/download, speed, active list.
- **Three ways to drive it** — see below — all backed by one typed dispatch
  table.

## Cargo features

| Feature | Default | What it adds |
|---|---|---|
| `std` | on | Threaded engine layer: engine, DNS servers, netstack, RPC, FFI. Implies `tls`. |
| `tls` | on | `protocol::tls` client/server layers and the TLS-based outbounds (HTTPS, Trojan, VMess/VLESS TLS, TLS inbounds). |
| `wireguard` | on | `protocol::wireguard` plus the WireGuard outbound. |
| `quic` | off | `protocol::quic` — the in-repo QUIC v1 client transport (RFC 9000/9001/9002). |
| `tuic` | off | TUIC v5 outbound. Implies `quic`. |
| `hysteria2` | off | Hysteria2 outbound (HTTP/3 `POST /auth`, Salamander obfuscation). Implies `quic`. |
| `tls13` | off | The in-repo TLS 1.3 client and the browser-shaped `ClientHello` fingerprints it can present (`chrome`, `randomized`, `off`). |
| `reality` | off | REALITY client authentication for VLESS/Trojan/VMess (`security: reality`). Implies `tls13`. |

A build without `tuic` / `hysteria2` **rejects** a `tuic` / `hysteria2`
outbound with an explicit config error naming the missing feature — it never
degrades to a direct connection. The same fail-closed rule applies to
`security: reality` and `fingerprint` without their features.

## REALITY and TLS fingerprints

The optional `tls13` / `reality` features add a second TLS engine next to
courierust's connector — one whose `ClientHello` is data-driven and whose
server authentication is a hook:

- **Fingerprints** (`fingerprint: chrome` | `randomized` | `off`): the
  cipher-suite list, extension set/order, groups, signature algorithms, ALPN
  and padding are built from
  [`courierust_fingerprint`](https://crates.io/crates/courierust)'s
  Chrome profile (the parameter set from the JA4 specification), with GREASE
  and 512-byte padding like a browser hello. The profile shapes are validated
  in tests by parsing the emitted bytes back and comparing JA3/JA4.
- **REALITY** (`security: reality` + `public-key`, `short-id`, `server-name`):
  the session id carries the reference format's `version || time || short-id`
  sealed with AES-256-GCM under the X25519-derived auth key, and the server
  is authenticated by the ephemeral-certificate proof (`HMAC-SHA512` over the
  key inside the certificate's signature field) instead of a CA chain.
- **Reported, never faked**: certificate compression (RFC 8879) and ALPS are
  not advertised (the client cannot decompress or present them), `mldsa65`
  verification is rejected as unsupported, and a REALITY *fallback* (a real
  certificate arrived) is a hard error rather than a silent downgrade.
- **Client side only**: a REALITY *server* would need an Ed25519 signer for
  `CertificateVerify`, which the in-repo crypto does not provide; the
  session-id *verification* half is implemented and tested
  (`protocol::reality::wire::unseal_session_id`).

```toml
[dependencies]
corduit = "0.1"                                    # std + tls + wireguard
# optional QUIC-based outbounds — enable deliberately, use lawfully:
# corduit = { version = "0.1", features = ["tuic", "hysteria2"] }
```

## How you talk to it

Whatever your frontend, it ends up at the same place (`rpc::dispatch`). Three
transports:

| Frontend | Transport | Docs |
|---|---|---|
| Flutter / Kotlin / Swift / C++ | Hand-written C ABI (`corduit_call`, `corduit_call_binary`) | [FFI-API](https://github.com/blueokanna/Corduit/wiki/FFI-API) |
| Browser dashboard / any language | Localhost HTTP + WebSocket JSON-RPC | [RPC-API](https://github.com/blueokanna/Corduit/wiki/RPC-API) |
| Rust application | Typed synchronous `api::*` | [Rust-API](https://github.com/blueokanna/Corduit/wiki/Rust-API) |

## Quick start

Corduit needs no runtime to set up: build a `Config`, construct the engine,
start it, stop it. That's the whole lifecycle.

```toml
[dependencies]
corduit = "0.1"
```

```rust,no_run
use corduit::engine::{
    Config, Corduit, GeneralConfig, InboundConfig, InboundType,
    OutboundConfig, OutboundType,
};

fn main() -> corduit::engine::Result<()> {
    let config = Config {
        general: GeneralConfig { mixed_port: Some(7890), ..Default::default() },
        inbounds: vec![InboundConfig {
            inbound_type: InboundType::Mixed,
            tag: "mixed-in".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 7890,
            options: Default::default(),
        }],
        outbounds: vec![OutboundConfig {
            outbound_type: OutboundType::Direct,
            tag: "DIRECT".to_string(),
            server: None,
            port: None,
            options: Default::default(),
        }],
        ..Config::default()
    };

    let engine = Corduit::new(config)?;
    engine.start()?;
    // ... run the proxy ...
    engine.stop()
}
```

Or drive the JSON facade — the same one the FFI and RPC layers call:

```rust,no_run
use corduit::api;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    api::start_proxy_from_yaml(r#"{
      "general": { "mode": "rule", "mixed_port": 7890, "log_level": "info" },
      "dns": { "enable": true, "nameservers": ["https://dns.google/dns-query"] },
      "inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }],
      "outbounds": [{ "type": "direct", "tag": "DIRECT" }],
      "rules": []
    }"#.to_string())?;

    let status = api::get_corduit_status()?;
    println!("running = {}", status.running);
    api::stop_proxy()?;
    Ok(())
}
```

Expose it to a web dashboard in two lines:

```rust,no_run
use corduit::api;
api::start_rpc_server(8765, Some("my-token".into()))?; // 127.0.0.1 only
```

```bash
curl -X POST http://127.0.0.1:8765/rpc \
  -H "Authorization: Bearer my-token" \
  -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'
# {"code":0,"data":"Corduit v0.1.3"}
```

## How the synchronous engine works

Corduit was async. It stopped being async for a reason: an async proxy is two
worlds welded together — a tokio reactor for the engine and a blocking
transport for the codecs (courierust, `std` sockets), with an adapter
pumping bytes across the seam. Every hop through that adapter costs a wakeup,
a channel and a context switch; every lock held across an `await` is a
latent deadlock.

The synchronous engine is one world. The concurrency model is layered, and
each layer is chosen for what it is actually good at:

1. **Short tasks** — accept dispatch, handshakes, DNS lookups, control plane,
   periodic refresh — run on **courierust's work-stealing thread pool**
   (per-worker LIFO caches, a global FIFO, cross-worker stealing, zero CPU
   when idle).
2. **Long-lived relays** run on **dedicated threads** (two per connection,
   one per direction, with proper half-close), bounded by a session gate so
   an unbounded number of relays can never starve the pool of handshake
   capacity.
3. **Accept loops** run **one thread per listener**, handing each accepted
   socket to the pool.

Blocking is bounded by socket timeouts (`SO_RCVTIMEO` / `SO_SNDTIMEO`):
`WouldBlock`/`TimedOut` mean "nothing happened yet", and loops re-check a
`CancellationToken` between operations. There is no reactor to wake and no
future to poll — a blocked worker is parked in the kernel, and a worker with
nothing to do parks on a condvar.

The price of this model is honest and documented: a proxy that relays mostly
idle long-lived connections occupies one thread per connection. The session
gate caps that cost, and the work-stealing pool keeps the short-task path
fast. For a desktop/mobile proxy engine — tens to low-hundreds of concurrent
connections, not tens of thousands — this is the right trade.

## Configuration

A single validated JSON model: `general` / `dns` / `inbounds` / `outbounds` /
`rules`. Every enum is a string; invalid values are rejected at the boundary,
before the engine touches them. Full field-by-field reference:
[Configuration](https://github.com/blueokanna/Corduit/wiki/Configuration).

## Project layout

```
src/
├── lib.rs          # module wiring, globals, no_std gating, platform entry points
├── api.rs          # typed synchronous API
├── ffi.rs          # hand-written C ABI
├── rpc/            # shared dispatch + localhost HTTP/WebSocket JSON-RPC
├── types.rs        # shared DTOs
├── common/         # sync scheduler, socket/timeout primitives, relay, timers,
│                   #   cancellation, URL parser, courierust HTTP client/server, roots
├── engine/         # config, routing, inbound/outbound, providers, stats
├── crypto/         # in-repo crypto primitives (no_std)
├── protocol/       # wire protocols (QUIC v1 client, TLS, WebSocket, QPACK…)
├── dns/            # DNS servers/clients, cache, fake-IP
└── netstack/       # userspace TCP/IP, TUN, NAT, VPN drivers
```

The no_std core lives in `crypto/`, `common/url`, `protocol/address`,
`protocol/qpack` and `protocol/error` — pure logic, no OS. The threaded
networking layer (engine, DNS servers, netstack, RPC, transports) is gated
behind the `std` feature.

## Building & testing

```bash
cargo check --all-targets
cargo test                            # unit + property tests (default features)
cargo test --features tuic,hysteria2  # include the optional QUIC-based outbounds
cargo test --doc
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo check --no-default-features                 # the no_std protocol core
cargo check --no-default-features --features std  # engine layer, no optional protocols
```

CI runs the default matrix on Linux, macOS and Windows, plus an all-features
job (so the gated QUIC/TUIC/Hysteria2 code is built and tested too) and the
`no_std` core check.

MSRV: Rust 1.78. The crate builds with **no HTTP/TLS/QUIC third-party
libraries and no async runtime** — the entire network stack is courierust
plus hand-rolled protocol codecs in-tree, and concurrency is courierust's
work-stealing pool plus `std::thread`.

## Why the network stack is hand-rolled

Corduit used to depend on hyper/h2/http, rustls + tokio-rustls, quinn and
tokio for its network layer. Each pulled its own dependency tree, its own TLS
provider, its own release cadence, and its own security advisories — three
different "one way to do TLS" ecosystems fighting over one socket. The engine
now talks HTTP/1.1, HTTP/2, HTTP/3, TLS 1.2/1.3 and WebSocket through
courierust (a zero-dependency codec suite) and runs its own concurrency.

QUIC is the interesting part. courierust ships the RFC 9000/9001 wire codecs
(packet headers, frames, varints, packet protection) and the TLS 1.3 crypto
primitives, but no QUIC connection runtime. Instead of shipping a stack that
can't talk to real servers, Corduit builds the missing layer in
`protocol::quic`: a real client-side QUIC v1 transport — the TLS
1.3-over-QUIC handshake (ClientHello → ServerHello →
EncryptedExtensions/Certificate/CertificateVerify/Finished), three
packet-number spaces, ACK/loss recovery with PTO, NewReno congestion control,
stream and connection flow control, and RFC 9221 datagrams — all on
courierust's public primitives. A dedicated driver thread per connection owns
the UDP socket; streams are synchronous `Read`/`Write` handles over
mutex-guarded buffers with condvar wakeups.

On top of that sit a QPACK/HPACK header codec (`protocol::qpack`) and, behind
the `quic` feature, the TUIC v5 (`tuic`) and Hysteria2 (`hysteria2`)
outbounds. Hysteria2 is implemented against the official protocol spec:
HTTP/3 `POST /auth` authentication, `0x401` TCP requests, session/UDP
datagram framing with fragmentation, and optional Salamander packet
obfuscation (BLAKE2b-256).

Deliberately not offered — and each is called out with an explicit warning
when a config asks for it, never silently faked: 0-RTT (early data), BBR /
TCP-Brutal congestion control (NewReno only), source-port hopping, and TLS
fingerprint mimicry.

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

[PolyForm Strict License 1.0.0](LICENSE), plus additional licensor terms.

- **Permitted**: personal use (research, experiment, testing, personal study,
hobby projects) and noncommercial purposes, including use by noncommercial
organizations.
- **Not permitted**: distributing the software in any form (free or paid) and
making changes or new works based on it.
- **Conditioned on lawful use**: no circumvention rights are granted, and use
must stay inside the law that applies to you.

Required Notice: Copyright 2026 blueokanna (https://github.com/blueokanna/Corduit)
