# Corduit

> **A unified, non-composite network proxy engine written in Rust 1.95.**
> One engine. Every protocol.

[![Crates.io](https://img.shields.io/crates/v/corduit-core)](https://crates.io/crates/corduit-core)
[![docs.rs](https://img.shields.io/docsrs/corduit-core)](https://docs.rs/corduit-core)
[![License](https://img.shields.io/badge/license-PolyForm--Perimeter--1.0.1-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue)](Cargo.toml)

---

## Why Corduit

Traditional proxy stacks (Clash, sing-box, V2Ray, Xray) are **composites**: they
bolt together a config loader, a rule engine, a DNS resolver, a TUN driver and a
handful of proxy protocols — each owned by a different upstream, each with its
own release cadence, its own bugs, and its own breaking changes.

**Corduit is a new product, not a wrapper.** It is a single engine where every
layer — configuration, routing, DNS, userspace networking, and wire protocols —
lives in one workspace and ships as one unit: one design, one test run, one
release.

|                          | Clash (composite)              | Corduit (unified)                          |
| ------------------------ | ------------------------------ | ------------------------------------------ |
| Protocol implementations | Forked/embedded third-party    | Native, in-repo, one version               |
| Rule engine              | Separate crates glued together | Single typed `RuleConfig` pipeline         |
| DNS                      | Multiple optional crates       | Dedicated `corduit-dns` with anti-spoofing |
| TUN stack                | External libraries             | In-repo userspace TCP/IP (SolidTCP)        |
| Configuration            | Many formats, many loaders     | One validated `Config` model               |
| Release cadence          | Per-component                  | Whole-workspace, atomic                    |

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
- **nextjson + rustbinary serialization** — **zero serde anywhere**, including
  `Cargo.lock`: the entire dependency graph is serde-free (no `serde`,
  `serde_json`, `serde_core`, `serde_derive`, …). The FFI boundary speaks
  `nextjson` (schema-driven JSON) for human-readable payloads and `rustbinary`
  (bounded, type-tagged binary) for compact high-throughput channels.
- **Self-implemented core components** — instead of third-party crates, Corduit
  ships its own hyper-based HTTP client, its own URL parser, its own MaxMind
  MMDB v2 reader and its own DNS wire codec, all bounds-checked and
  dependency-light (`corduit-common`, `corduit-core::mmdb`, `corduit-dns::wire`).
- **Every cryptographic primitive is in-repo** — `corduit-crypto` implements the
  full stack from scratch with **zero external dependencies** and a `no_std`
  core: AES-GCM, ChaCha20-Poly1305, Poly1305, HMAC, HKDF, MD5, SHA-1, SHA-2,
  SHA-3, BLAKE2, BLAKE3, X25519, base64/hex, UUIDv4 and a ChaCha-based CSPRNG.
  Only the OS entropy source (`getrandom`) is external. The proxy protocols
  (Shadowsocks, VMess, WireGuard, QUIC, …) all call into it directly; the old
  `aes-gcm`, `chacha20poly1305`, `blake2/3`, `sha1/2`, `hkdf`, `md-5`, `uuid`,
  `rand`, `x25519-dalek` dependencies are gone from the workspace.
- **Hot reload** — `Corduit::reload()` swaps configuration atomically.
- **Observability** — `tracing`-based structured logging and span helpers with
  per-connection traffic stats.
- **Mobile-ready** — `corduit-lib` ships Android JNI (`VpnService`), Windows VPN
  integrations, and a unified `corduit_call` / `corduit_call_binary` dispatcher
  for any native host.
- **Licensed for the ecosystem** — PolyForm Perimeter 1.0.1: use, modify and
  distribute freely; only a product that competes with Corduit (e.g. a hosted
  clone) is restricted — and unlike FSL, it **never** converts to MIT/Apache.

---

## Workspace Architecture

```
Corduit (workspace)
│
├── corduit-common       # Shared minimal utilities: dependency-free URL parser
│   │                    #   + self-implemented hyper HTTP client
│
├── corduit-core        # Engine: config model, rule pipeline, outbound
│   │                   #         orchestration, traffic stats, health checks
│   └── src/
│       ├── config/     #   Typed, validated configuration + JSON mapping
│       ├── inbound/    #   HTTP / SOCKS5 / mixed listeners
│       ├── outbound/   #   Direct/Reject/SS/VMess/VLESS/Trojan/TUIC/Hy2/...
│       ├── routing.rs  #   Rule → outbound matching (rule/global/direct)
│       ├── geoip.rs    #   CountryMatcher trait (dependency inversion)
│       ├── mmdb.rs     #   Self-implemented MaxMind MMDB v2 reader
│       └── proxy.rs    #   ProxyManager: the coordinator
│
├── corduit-crypto      # Dependency-free, no_std crypto primitives: AES-GCM,
│                       #   ChaCha20-Poly1305, SHA-1/2/3, BLAKE2/3, MD5, HMAC,
│                       #   Poly1305, HKDF, X25519, base64/hex, UUIDv4, CSPRNG
│
├── corduit-protocol    # Wire protocols: QUIC, TLS, WireGuard, TUIC,
│                       #   transports (h2/gRPC/WebSocket/TLS)
│
├── corduit-dns         # DNS: DoH/DoT/UDP/TCP servers & clients, cache,
│   │                   #   fake-IP, hosts, anti-spoofing, split resolution
│   └── src/wire.rs     #   Self-implemented DNS wire codec (RFC 1035)
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
  HTTP/SOCKS ─────────►│  inbound/*  ──►  routing.rs │
  redir/TProxy ────────►│              │      │      │
  TUN (netstack) ──────►│              ▼      ▼      │
                       │        outbound/*  DNS (dns)│
                       │              │      │       │
                       │              ▼      ▼       │
                       │       proxy groups  fake-IP │
                       └──────────────┬──────────────┘
                                      ▼
                          corduit-protocol (wire)
```

---

## Quick Start

### As a library

```toml
[dependencies]
corduit-core = { version = "0.1" }   # engine
corduit-dns  = "0.1"                  # DNS (optional)
corduit-netstack = "0.1"              # TUN (optional)
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

Corduit uses a single validated, **nextjson-native JSON** `Config` model — no
ad-hoc toml, no YAML, no multiple dialects. `nextjson`'s schema-driven derive
handles the whole model (defaults, aliases, rename rules) with zero serde. A
minimal `config.json`:

```json
{
  "general": {
    "mode": "rule",
    "mixed_port": 7890,
    "allow_lan": false,
    "log_level": "info"
  },
  "dns": {
    "enable": true,
    "listen": "0.0.0.0:53",
    "nameservers": ["https://dns.google/dns-query"],
    "fallback": ["8.8.8.8"],
    "enhanced_mode": "fake-ip"
  },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "DIRECT" },
    {
      "type": "selector",
      "tag": "PROXY",
      "options": { "proxies": ["proxy-1", "proxy-2"] }
    },
    {
      "type": "vmess",
      "tag": "proxy-1",
      "server": "vmess.example.com",
      "port": 443,
      "options": {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "security": "auto"
      }
    },
    {
      "type": "tuic",
      "tag": "proxy-2",
      "server": "tuic.example.com",
      "port": 443,
      "options": {
        "uuid": "00000000-0000-0000-0000-000000000000",
        "password": "secret"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "server": "hy2.example.com",
      "port": 443,
      "options": { "password": "secret" }
    }
  ],
  "rules": [
    { "type": "domain_suffix", "payload": "example.com", "outbound": "DIRECT" },
    { "type": "geoip", "payload": "cn", "outbound": "DIRECT" },
    { "type": "match", "payload": "", "outbound": "PROXY" }
  ]
}
```

All enums are strongly typed: `OutboundType` covers `direct`, `reject`,
`shadowsocks`, `vmess`, `vless`, `trojan`, `tuic`, `hysteria2`, `quic`,
`socks5`, `http`, `wireguard`, plus groups `selector`, `url-test`, `fallback`,
`load-balance`, `relay`. `RuleType` covers `domain`, `domain_suffix`,
`domain_keyword`, `domain_regex`, `geoip`, `ip_cidr`, `src_ip_cidr`, `src_port`,
`dst_port`, `process_name`, `rule_set`, `match`.

---

## Supported Protocols

| Layer           | Protocols                                                                                            |
| --------------- | ---------------------------------------------------------------------------------------------------- |
| Proxy outbounds | Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria2, SOCKS5, HTTP(S), QUIC, WireGuard, Direct, Reject |
| Proxy groups    | Selector, URL-test, Fallback, Load-balance, Relay                                                    |
| Inbounds        | HTTP, SOCKS5, Mixed, (redir / TProxy on Linux)                                                       |
| Transports      | WebSocket, h2, gRPC, TLS, QUIC                                                                       |
| DNS             | UDP, TCP, DoH, DoT — client & server                                                                 |
| TUN             | Userspace TCP/IP (SolidTCP) with NAT                                                                 |

---

## Platform Support

| Platform | Inbound | TUN | Notes                                                 |
| -------- | ------- | --- | ----------------------------------------------------- |
| Windows  | ✓       | ✓   | wintun (auto-download or `embed-wintun` feature)      |
| Linux    | ✓       | ✓   | requires `CAP_NET_ADMIN` for TUN                      |
| macOS    | ✓       | ✓   | requires root for TUN                                 |
| Android  | ✓       | ✓   | VpnService via JNI (`corduit-lib`)                    |
| Flutter  | —       | —   | Hand-written C ABI via `corduit-lib` (`corduit_call`) |

---

## Cross-Language API (FFI)

`corduit-lib` ships a **hand-written C ABI** — no `flutter_rust_bridge`, no
codegen, no runtime. Any language that can call C can drive the whole engine
through **two** entry points:

| Entry point                                 | Payload format        | Use case                     |
| ------------------------------------------- | --------------------- | ---------------------------- |
| `corduit_call(method, args_json)`           | `nextjson` (JSON)     | Human-readable control plane |
| `corduit_call_binary(method, payload, len)` | `rustbinary` (binary) | Compact, high-throughput     |

Memory rules (identical for both):

1. Every call returns an `FfiResponse { code: i32, data: *mut c_char }` (or
   `FfiBinaryResponse { code, data, len }`).
2. `code == 0` means success; non-zero means error (message in `data`).
3. Free returned buffers with `corduit_string_free(ptr)` /
   `corduit_binary_free(resp)`.

Introspection helpers (so bindings never hard-code method lists):

```c
const char *corduit_api_version(void);  /* ABI version, e.g. "0.1.0" */
char       *corduit_methods(void);      /* JSON array of supported methods */
void        corduit_string_free(char *);/* free both of the above */
```

### Example: Python (`ctypes`)

```python
import ctypes, json

lib = ctypes.CDLL("rust_lib_corduit.dll")   # .so / .dylib / .a
lib.corduit_call.restype = ctypes.POINTER(None)
# ... bind FfiResponse layout ...

def call(method: str, args: dict) -> dict:
    payload = json.dumps(args).encode()
    resp = lib.corduit_call(method.encode(), payload or None)
    code, data = resp.code, ctypes.string_at(resp.data)
    lib.corduit_string_free(resp.data)
    if code != 0:
        raise RuntimeError(data.decode())
    return json.loads(data) if data else None
```

### Example: JavaScript / TypeScript (via `koffi` or `ffi-napi`)

```ts
const koffi = require("koffi");
const lib = koffi.load("rust_lib_corduit");

const FfiResponse = koffi.struct("FfiResponse", {
  code: "int32",
  data: "str",
});
lib.func("FfiResponse corduit_call(const char* method, const char* args_json)");
lib.func("void corduit_string_free(char* ptr)");

export async function corduit(method: string, args: object = {}) {
  const resp = lib.corduit_call(method, JSON.stringify(args));
  if (resp.code !== 0) throw new Error(resp.data);
  return resp.data ? JSON.parse(resp.data) : null;
}
```

### Example: Dart / Flutter (via `dart:ffi`)

```dart
import 'dart:ffi';
import 'dart:convert';

typedef CorduitCallNative = Pointer<FfiResponse> Function(
    Pointer<Utf8> method, Pointer<Utf8> args);
typedef CorduitCall = Pointer<FfiResponse> Function(
    Pointer<Utf8> method, Pointer<Utf8> args);

final call = lib.lookupFunction<CorduitCallNative, CorduitCall>('corduit_call');

Future<dynamic> corduit(String method, Map<String, dynamic> args) async {
  final m = method.toNativeUtf8();
  final a = jsonEncode(args).toNativeUtf8();
  final resp = call(m, a);
  final code = resp.ref.code;
  final data = resp.ref.data.cast<Utf8>().toDartString();
  calloc.free(m); calloc.free(a);
  if (code != 0) throw Exception(data);
  return data.isEmpty ? null : jsonDecode(data);
}
```

### Full method reference

Use `corduit_methods()` at runtime for the authoritative list. The current
dispatch table (also enforced by a unit test) covers:

- **Lifecycle** — `init_app`, `start_proxy_from_yaml`, `start_proxy_from_file`,
  `stop_proxy`, `is_proxy_running`, `reload_config_from_yaml`,
  `reload_config_from_file`
- **Modern engine** — `initialize_corduit`, `start_corduit`, `stop_corduit`,
  `reload_corduit`, `get_corduit_status`, `test_config`
- **Dashboard** — `get_traffic_stats`, `get_connections`, `close_connection`,
  `close_all_connections`, `get_logs`, `set_log_level`, `get_system_info`,
  `get_version`, `get_build_info`
- **Proxies & groups** — `get_proxies`, `get_proxy_groups`, `select_proxy`,
  `select_proxy_in_group`, `get_selected_proxy_in_group`, `get_rules`,
  `get_dns_config`, `set_proxy_mode`, `get_proxy_mode`
- **Latency testing** — `test_proxy_latency`, `test_outbound_latency`,
  `test_tcp_connectivity`, `test_shadowsocks_latency`, `test_proxies_latency`,
  `test_proxy_latency_dto`, `test_all_proxies_latency`
- **TUN / VPN** — `start_tun_mode`, `stop_tun_mode`, `enable_tun_mode`,
  `enable_tun_mode_with_mode`, `disable_tun_mode`, `get_tun_status`,
  `is_wintun_available`, `get_wintun_dll_path`, `ensure_wintun_dll`,
  `set_windows_proxy_mode`, `get_windows_proxy_mode_str`,
  `get_windows_tun_stats`, `enable_uwp_loopback`, `open_uwp_loopback_utility`
- **Android** — `set_android_vpn_fd`, `get_android_vpn_fd`,
  `clear_android_vpn_fd`, `set_android_proxy_mode`, `get_android_proxy_mode`,
  `start_android_vpn`, `stop_android_vpn`, `set_vpn_fd`, `clear_vpn_fd`,
  `set_protect_socket_callback_enabled`

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
4. **No dead weight, no serde.** serde / serde_json / serde_core /
   serde_derive are gone **from the entire dependency graph, `Cargo.lock`
   included** — every type in the workspace (config, DTOs, protocol metadata)
   derives `nextjson`'s `NsonSerialize` / `NsonDeserialize`. Unused
   dependencies are removed and every declared dependency is actually used.
5. **Serialization is built in, not bolted on.** The FFI boundary uses
   `nextjson` + `rustbinary` (typed, schema-driven, `no_std`, `unsafe`-free),
   so cross-language clients get stable, self-describing payloads with zero
   serde anywhere in the graph.

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

MSRV: **Rust 1.95** (verified with `cargo +1.95.0 check/test`; `resolver = "2"`
with an MSRV-aware fallback in `.cargo/config.toml` keeps the lock
compatible).

### Publishing to crates.io

Member crates depend on each other via `path` + `version` in the workspace
manifest, so publish them **in dependency order**:

```bash
cargo publish -p corduit-common    # 0th (no internal deps)
cargo publish -p corduit-protocol   # 1st (no internal deps)
cargo publish -p corduit-dns        # 2nd (depends on corduit-common)
cargo publish -p corduit-netstack   # 3rd (depends on corduit-dns)
cargo publish -p corduit-core       # 4th (depends on corduit-protocol + common)
cargo publish -p corduit-lib        # 5th (depends on core + netstack)
```

Each crate is built with `all-features` on docs.rs.

---

## Security

Corduit is audited as a dependency graph **and** at the source level:

### Dependency audit (`cargo audit`)

- All direct dependencies are recent and maintained. The entire serde family
  (`serde`, `serde_json`, `serde_core`, `serde_derive`) has been removed from
  **both the source and `Cargo.lock`** and replaced by first-party `nextjson`
  (schema-driven, `#![deny(unsafe_code)]`, bounded) and `rustbinary`; the
  former `reqwest` (HTTP), `url`, `hickory-proto` (DNS) and `maxminddb`
  dependencies are replaced by in-repo implementations (`corduit-common`,
  `corduit-dns::wire`, `corduit-core::mmdb`).
- The only remaining advisory is _informational_: `paste` (a transitive
  build-time macro helper pulled in by the Linux netlink stack) is
  unmaintained — it is not a security vulnerability and cannot be removed
  without replacing the whole `tun-rs` dependency chain.

### Source-level hardening (CWE review)

| Check                                                      | Verdict                                      |
| ---------------------------------------------------------- | -------------------------------------------- |
| CWE-78 OS command injection                                | Fixed — interface names are validated before |
| PowerShell/netsh interpolation (`sanitize_interface_name`) |
| CWE-190 integer truncation                                 | Fixed — QUIC request payloads > 64 KiB are   |

rejected instead of truncated; SOCKS5 credentials are length-checked
(RFC 1929) |
| CWE-295 TLS certificate verification | Verified — `skip_cert_verify` is
off by default; native roots are used and verification is only bypassed
when explicitly configured |
| CWE-22 path traversal | Verified — wintun extraction uses fixed entry names;
no user-controlled paths reach the filesystem |
| CWE-502 deserialization | Verified — `nextjson`/`rustbinary` are
memory-safe, bounded, schema-driven formats |
| CWE-798 hard-coded credentials | Verified — no credentials in production
code (test-only fixtures) |
| CWE-120 / CWE-416 memory safety | Verified — `unsafe` is confined to the
hand-verified FFI/platform boundary |

### Runtime posture

- **TLS 1.3 by default** via rustls (ring), AEAD ciphers only
  (AES-GCM / ChaCha20-Poly1305), X25519/Curve25519 key exchange.
- **All symmetric/key-agreement crypto is self-implemented and audited** in
  `corduit-crypto` against RFC/NIST/IRTF vectors: the AEAD, hash and X25519
  suites are verified against RFC 8439, NIST SP 800-38D, RFC 7748, RFC 7693,
  the official BLAKE3 test vectors and RFC 5869, and the MAC comparisons and
  field arithmetic are constant-time.
- **Memory safety by construction** — a Rust panic cannot become memory
  corruption; all buffer sizes are bounds-checked before use.
- **Fail-closed configuration** — unknown protocols and malformed options are
  rejected at the boundary, not silently ignored.

---

## License

[PolyForm Perimeter 1.0.1](LICENSE) — a source-available license from
[PolyForm Project](https://polyformproject.org/licenses/perimeter/1.0.1).

- ✅ Use, modify and create new works freely
- ✅ Distribute copies, including derivatives
- ✅ Patents granted; fair use preserved
- 🚫 **Noncompete** — you may not offer a product that substitutes for
  Corduit's functionality or value
- 🔒 **No automatic relicensing** — the license stays PolyForm Perimeter
  forever; it never converts to MIT or Apache-2.0

License: [PolyForm Perimeter 1.0.1](LICENSE) — declared via `license-file` in
the manifests (PolyForm Perimeter has no SPDX identifier).

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
