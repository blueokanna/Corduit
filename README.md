# Corduit

A synchronous network proxy engine for Rust, with a `no_std` core. The configuration model,
rule router, DNS stack, userspace TCP/IP stack and every wire protocol live in one crate,
built without a third-party proxy core; **there is no async runtime anywhere in the
dependency tree**.

[![Crates.io](https://img.shields.io/crates/v/corduit)](https://crates.io/crates/corduit)
[![docs.rs](https://img.shields.io/docsrs/corduit)](https://docs.rs/corduit)
[![CI](https://github.com/blueokanna/Corduit/actions/workflows/ci.yml/badge.svg)](https://github.com/blueokanna/Corduit/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue)](Cargo.toml)

- Chinese documentation → [README.zh-CN.md](README.zh-CN.md)
- Full documentation → [Wiki](https://github.com/blueokanna/Corduit/wiki) (FFI, RPC, method reference)

---

## Legal notice — read before building or running anything

Corduit is a network engineering toolkit: proxy protocols, a rule router, DNS and a
userspace TCP/IP stack. It is published for **lawful use only**.

- **Your local law governs.** Nothing in this repository, its license or its documentation
  grants any permission the law applying to you does not already give you. You alone are
  responsible for how you use it.
- **Do not use it to break the law.** In some jurisdictions, mainland China included,
  providing or using a proxy, VPN or tunnel service to bypass state network controls is
  illegal. Corduit grants no right to do that, and the maintainers neither authorize nor
  support it.
- **TUIC, Hysteria and Hysteria2 are opt-in.** They are disabled Cargo features (`tuic`,
  `hysteria`, `hysteria2`) and are absent from a default build; enabling them is your own
  decision.
- **Unlawful use gets no support.** Issues, pull requests and discussions that would enable
  unlawful use will be closed.
- **No warranty, no liability.** The software is provided as is. See [LICENSE](LICENSE),
  whose additional licensor terms make lawful use a condition of every license granted.
- **This is not legal advice.** If you are unsure whether your intended use is lawful,
  consult a qualified lawyer in your jurisdiction before building or running anything.

---

## Contents

- [Motivation](#motivation)
- [At a glance](#at-a-glance)
- [Protocol support](#protocol-support)
- [Architecture](#architecture)
- [Execution model](#execution-model)
- [Building](#building)
- [Running the engine](#running-the-engine)
- [Configuration](#configuration)
- [Rule engine](#rule-engine)
- [Security model](#security-model)
- [Testing and continuous integration](#testing-and-continuous-integration)
- [Platform support](#platform-support)
- [Project layout](#project-layout)
- [Known limitations](#known-limitations)
- [License](#license)

## Motivation

Proxy deployments are usually assembled: a configuration loader, a rule engine, a DNS
resolver and several protocol kernels, each from a different upstream with its own bug
tracker and release cadence. The seams between those parts are where behaviour drifts — a
rule that means one thing to the router and another to the resolver, a profile key that one
component accepts and the next silently drops.

Corduit is the opposite arrangement. One crate owns the whole data plane, so a configuration
key, a rule type or a wire detail has exactly one implementation and one set of tests. The
engine is synchronous: no async runtime, no reactor and no `async` / `await` in the data
path, which keeps the thread topology, the cancellation story and the failure modes
inspectable.

## At a glance

| Area | What is implemented |
|---|---|
| **Inbounds** | `http`, `socks5`, `mixed` (protocol auto-detection); TUN through the in-tree userspace stack |
| **Outbounds** | `direct`, `reject`, `socks5`, `socks4`/`socks4a`, `http` (plain or TLS), `shadowsocks` (2017 AEAD + SIP003 plugins), `shadowsocksr`, `snell` v4/v5, `vmess`, `vless`, `trojan`, `wireguard`, `naive`, and the opt-in `shadowtls` v3, `tuic` v5, `hysteria` v1, `hysteria2` |
| **Policy groups** | `selector`, `url-test` (with hysteresis), `fallback`, `load-balance` (round-robin / consistent hashing / sticky sessions), `relay` |
| **Rule types** | `domain`, `domain-suffix`, `domain-keyword`, `domain-regex`, `geosite`, `geoip`, `ip-cidr`, `src-ip-cidr`, `src-port`, `dst-port`, `in-port`/`in-type`/`in-name`/`in-user`, `process-name`, `process-path`, `network`, `rule-set`, `proxy-mode`, `and`/`or`/`not`, `match` |
| **Rule sets** | Text / YAML / JSON payloads; `.srs` (versions 1–5, zlib); `.mrs` (container version 1, zstd) |
| **Geo data** | `geosite.dat` (categories), `geoip.dat` and `Country.mmdb` (address ownership) |
| **DNS** | [RecurseX](https://crates.io/crates/recurse-x) resolver; profile-side policy, upstream bootstrap, answer filtering, optional listening resolver |
| **Runtime** | Hot reload, per-connection accounting, JSON-RPC control plane, C ABI, Android JNI |

Supported and unsupported features are held to the same standard: anything the engine
cannot honour is refused at configuration time with an error naming the missing capability,
rather than accepted and silently degraded. See [Known limitations](#known-limitations).

## Protocol support

### Inbounds

| Type | Notes |
|---|---|
| `http` | CONNECT and absolute-URI forwarding, optional authentication |
| `socks5` | CONNECT, UDP ASSOCIATE, username/password authentication |
| `mixed` | One listener that detects HTTP or SOCKS5 from the first bytes without consuming them |
| TUN | In-tree userspace TCP/IP (`netstack`), with a fake-IP pool and a DNS responder |
| `redir`, `tproxy`, `tun` (as an `inbounds` entry) | Parsed, then **rejected at validation**: no listener exists for them, and a build that accepted them would answer nothing while claiming otherwise |

### Outbounds

| Type | Notes |
|---|---|
| `direct`, `reject` | Direct dial; fail-closed rejection |
| `socks5`, `socks4`/`socks4a`, `http` | Plain or TLS-wrapped HTTP proxy |
| `shadowsocks` | 2017 AEAD ciphers; SIP003 plugins `obfs`, `v2ray-plugin`, `shadow-tls` resolved in-tree |
| `shadowsocksr` | Full protocol/obfs matrix |
| `snell` | v4 and v5, `obfs: http` / `obfs: tls` |
| `vmess`, `vless`, `trojan` | Full client implementations, including multiplexing where the protocol defines it |
| `wireguard` | Userspace WireGuard client (feature `wireguard`) |
| `naive` | NaiveProxy client |
| `shadowtls` v3, `tuic` v5, `hysteria` v1, `hysteria2` | Feature-gated (`shadowtls`, `tuic`, `hysteria`, `hysteria2`) |

Shadowsocks 2022 ciphers are refused with a named error rather than half-implemented.

## Architecture

```
        client ──▶ inbound ──▶ router ──▶ policy group ──▶ outbound ──▶ server
                     │           │
                     │           └── rule table · rule providers · geo databases
                     └── netstack (TUN) · DNS resolver · connection tracker
```

- **`engine/config`** — the validated configuration model and the encoding layer that maps
  profile dialects onto it.
- **`engine/routing`** — rule compilation and matching. Rules are compiled once (regexes,
  CIDRs, port ranges, transports), and domain/suffix lookups are indexed so an ordered rule
  table stays ordered without a linear scan per connection.
- **`engine/ruleset`** — the binary rule-set decoders (`.srs`, `.mrs`), the compressed domain
  set they share, and the headless rule model both formats decode into.
- **`engine/geo`** — the Geo databases: strict protobuf decoding, per-category and
  per-country compilation on first use, merged address interval sets.
- **`engine/outbound`** — one module per protocol, plus the policy groups.
- **`engine/inbound`** — the listeners.
- **`dns`** — the profile-to-resolver adaptation on top of RecurseX.
- **`netstack`** — the userspace stack: TCP state machine, UDP sessions, TUN integration,
  platform routing.
- **`protocol`**, **`crypto`** — the wire codecs and the cryptographic primitives, both
  `no_std`-compatible.
- **`common`** — synchronisation primitives, sockets, buffered streams, timers,
  cancellation, and the HTTP client used by provider updates.

The dependency direction is one-way: `protocol` and `crypto` know nothing about `engine`,
and `engine` never reaches into `netstack` internals.

## Execution model

There is no executor. Concurrency is explicit:

- a work-stealing pool (from [`courierust`](https://crates.io/crates/courierust)) runs short,
  bounded tasks — accepts, handshakes, provider refreshes;
- long-lived relays own a thread each and stop when their cancellation token fires;
- every blocking wait is either bounded by a deadline or interruptible by that token, so
  shutdown does not depend on a network operation completing.

This is why the engine can be driven from a `main` thread, a Flutter worker, an Android
service or a C caller without an adapter layer: there is no runtime to adopt.

## Building

**Requirements**: Rust 1.95 (edition 2024). No C toolchain is needed: the zlib backend for
`.srs` is `zlib-rs`, and the zstd decoder for `.mrs` is implemented in-tree
(`engine::ruleset::zstd`).

```bash
cargo build --release
cargo build --release --no-default-features --features std   # engine layer only
```

### Feature flags

| Feature | Default | Effect |
|---|---|---|
| `std` | yes | The threaded engine layer (implies `tls`) |
| `tls` | yes | TLS client/server layers used by the TLS-based outbounds |
| `wireguard` | yes | The WireGuard protocol and outbound |
| `quic` | no | The in-tree QUIC v1 transport (RFC 9000/9001/9002) |
| `tuic`, `hysteria`, `hysteria2` | no | The respective outbounds (imply `quic`) |
| `tls13` | no | The in-tree TLS 1.3 client with profile-shaped `ClientHello` fingerprints |
| `reality`, `shadowtls` | no | REALITY and ShadowTLS v3 (imply `tls13`) |

With `default-features = false` the crate compiles for `no_std + alloc`; the pure wire codecs
and the crypto primitives carry no OS dependency.

## Running the engine

```rust
use corduit::engine::{Config, Corduit};

fn main() -> corduit::engine::Result<()> {
    let text = std::fs::read_to_string("config.yaml")?;
    let config = Config::from_str(&text)?;
    let engine = Corduit::new(config)?;
    engine.start()?;
    // ... serve until shutdown ...
    engine.stop()
}
```

A JSON facade (`api::start_proxy_from_yaml` and friends) and a JSON-RPC control plane
(`rpc`) sit on top of the same engine; the C ABI in `ffi` and the Android JNI bridge call
those. Runnable examples live in [`examples/`](examples) and are documented on docs.rs.

## Configuration

Profiles are YAML (or JSON) documents whose shape stays close to the dialects the engine
consumes, with one rule: every key has exactly one meaning, and an unimplemented key is an
error rather than a no-op.

```yaml
general:
  mode: rule
  log-level: info

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  nameserver: [https://1.1.1.1/dns-query]

inbounds:
  - { type: mixed, tag: mixed-in, listen: 127.0.0.1, port: 7890 }

outbounds:
  - { type: selector, tag: PROXY, outbounds: [ss-a, ss-b], tolerance: 50 }
  - { type: shadowsocks, tag: ss-a, server: 203.0.113.10, port: 8388, cipher: aes-256-gcm, password: "..." }
  - { type: direct, tag: DIRECT }

rule-providers:
  ads:
    type: http
    behavior: classical
    url: https://example.org/ads.srs
    interval: 86400

rules:
  - { type: geosite,  payload: category-ads-all, outbound: REJECT }
  - { type: geoip,    payload: CN,               outbound: DIRECT }
  - { type: rule-set, payload: ads,              outbound: REJECT }
  - { type: match,    payload: "",               outbound: PROXY }
```

[`wiki/Configuration.md`](wiki/Configuration.md) documents every key;
[`wiki/Rules.md`](wiki/Rules.md) documents the rule engine, the rule-set formats and the Geo
databases in detail.

## Rule engine

Rules are evaluated top to bottom and the first match wins. Three properties are worth
stating explicitly, because they are easy to get wrong elsewhere:

1. **Nothing is dropped silently.** A rule whose payload cannot be compiled, a rule set whose
   format cannot be decoded, a Geo category that does not exist — each is reported at load
   time with the entry named. A rule that can never match is a routing bug that is very hard
   to find later.
2. **The index never reorders the table.** Domain and suffix rules are indexed for lookup,
   but candidates are still evaluated in configuration order, so an indexed rule cannot jump
   ahead of an earlier regex or process rule.
3. **Domain resolution is opt-in.** `ip-cidr` and `geoip` rules see addresses the router
   resolved only when the rule did not ask for `no-resolve`, and a configuration whose IP
   rules are all `no-resolve` never pays for a DNS lookup.

Rule sets are identified by content, never by file name: a payload is classified as text,
`.srs`, `.mrs` or a Geo database from its bytes, because an extension on a subscription URL
is not evidence of anything.

## Security model

- **Fail closed.** A configuration naming a protocol this build disabled is rejected; it
  never falls back to a direct connection. Global mode without a proxy outbound rejects
  rather than leaking.
- **Bounded input.** Every decoder in the tree has explicit limits: rule-set payloads
  (256 MiB decoded), Geo databases (512 MiB), HTTP bodies, DNS message sizes, and nesting
  depth in logical rules and protobuf messages.
- **No trust in profile strings.** Values that reach a wire format (hostnames, paths,
  credentials) are validated; control characters are rejected rather than escaped.
- **In-tree cryptography.** The AEAD, hash, KDF and stream primitives are implemented in
  `crypto` and covered by known-answer tests; there is no OpenSSL or ring dependency.
- **No certificate bypass by default.** `skip-cert-verify` is an explicit opt-in per
  outbound.

Details are in [`wiki/Security.md`](wiki/Security.md).

## Testing and continuous integration

```bash
cargo test --all-features      # 1097 tests
cargo test                     # 1008 tests with default features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The suite covers the pure codecs with known-answer and property tests, the rule engine with
ordering and precedence tests, the binary format decoders with byte-exact fixtures (including
hand-assembled ones, so a decoder cannot be validated only against its own writer), and the
engine end to end over loopback.

CI runs on three desktop platforms, checks the declared MSRV, cross-checks Android (aarch64
and x86_64 through the NDK) and iOS, verifies the `no_std` core against a bare-metal target,
and fails on any compiler warning or broken rustdoc link.

## Platform support

| Platform | Status |
|---|---|
| Linux, macOS, Windows | Supported; desktop CI |
| Android | Supported (`jni` bridge, TUN through `VpnService`) |
| iOS | Supported (TUN; `sysinfo`-based metrics replaced by platform APIs) |
| HarmonyOS (`target_env = ohos`) | Supported for the engine layer |
| `no_std + alloc` targets | The protocol core compiles; the threaded engine does not |

## Project layout

```
src/
  engine/    config, routing, ruleset, geo, inbound, outbound, dns, providers
  netstack/  userspace TCP/IP, TUN integration, platform routing
  dns/       profile → RecurseX adaptation, listening resolver
  protocol/  wire codecs: TLS 1.3, QUIC, WebSocket, WireGuard, address types
  crypto/    AEAD, hashes, KDFs, stream ciphers, RNG
  common/    sync primitives, sockets, streams, timers, HTTP client
  api.rs     typed synchronous facade
  rpc/       JSON-RPC control plane
  ffi.rs     C ABI
```

## Known limitations

These are deliberate, and each is visible at configuration time rather than at runtime.

| Area | Status | Consequence |
|---|---|---|
| Traffic sniffing (TLS ClientHello SNI / HTTP Host recovery) | Not implemented | Hostnames come from the DNS side (fake-IP, redir-host). A client that dials a literal IP cannot match domain rules; use `ip-cidr` / `geoip` for those flows |
| Sub-rules (`sub-rules` sections) | Not implemented | Use a named rule provider plus a `rule-set` rule |
| `.srs` client conditions (`wifi_ssid`, `package_name`, …) | Recognised and refused | The rule set is rejected with the condition named; a set without them loads |
| `DOMAIN-KEYWORD` matching | Linear in the keyword count | Keep keyword sets small, or express them as `domain-regex` |

## License

See [LICENSE](LICENSE). Corduit is released for lawful use only: it is a network engineering
tool for proxy protocols, routing, DNS and userspace TCP/IP.
