# Corduit

> **用 Rust 编写的统一、非组合式网络代理引擎。**
> 一个引擎，覆盖所有协议。

[![Crates.io](https://img.shields.io/crates/v/corduit-core)](https://crates.io/crates/corduit-core)
[![docs.rs](https://img.shields.io/docsrs/corduit-core)](https://docs.rs/corduit-core)
[![License](https://img.shields.io/badge/license-PolyForm--Perimeter--1.0.1-blue)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](Cargo.toml)

---

## 为什么选择 Corduit

传统代理栈（Clash、sing-box、V2Ray、Xray）都是**组合式**的：它们把配置加载器、
规则引擎、DNS 解析器、TUN 驱动和一堆代理协议强行拼装在一起——每个部分来自
不同的上游，各有各的发布节奏、各自的 Bug、各自的破坏性变更。

**Corduit 作为全新的产品。** 它是一个统一设计、一体构建的引擎：配置、路由、
DNS、用户态网络、线缆协议每一层都是同一个工作区的头等公民，一起设计、一起
测试、一起发布。

|          | Clash（组合式）      | Corduit（统一式）               |
| -------- | -------------------- | ------------------------------- |
| 协议实现 | Fork/嵌入第三方      | 仓库内原生实现，单一版本        |
| 规则引擎 | 多个 crate 胶水拼接  | 单一强类型 `RuleConfig` 流水线  |
| DNS      | 多个可选 crate       | 自带抗污染 `corduit-dns`        |
| TUN 栈   | 外部库               | 仓库内用户态 TCP/IP（SolidTCP） |
| 配置     | 多种格式、多套加载器 | 单一校验过的 `Config` 模型      |
| 发布节奏 | 各组件各自为政       | 全工作区原子发布                |

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
- **nextjson + rustbinary 序列化** —— **任何地方都零 serde，包括
  `Cargo.lock`**：整个依赖图无 serde（无 `serde`、`serde_json`、`serde_core`、
  `serde_derive` 等）。FFI 边界使用 `nextjson`（schema 驱动 JSON）承载可读
  负载，`rustbinary`（有界、类型标记二进制）承载紧凑高吞吐通道。
- **自研核心组件** —— 替代第三方 crate：自研 hyper HTTP 客户端、自研 URL
  解析器、自研 MaxMind MMDB v2 读取器、自研 DNS wire 编解码，全部带边界
  检查且依赖极轻（`corduit-common`、`corduit-core::mmdb`、`corduit-dns::wire`）。
- **热重载** —— `Corduit::reload()` 原子化替换配置。
- **可观测性** —— 基于 `tracing` 的结构化日志与 span 辅助，并提供逐连接
  流量统计。
- **移动端就绪** —— `corduit-lib` 提供 Android JNI（`VpnService`）、Windows
  VPN 集成，以及面向任意原生宿主的统一 `corduit_call` / `corduit_call_binary`
  分发入口。
- **许可简单直接** —— PolyForm Perimeter 1.0.1：可以自由使用、修改、分发，
  唯一限制是**不能拿它做与 Corduit 直接竞争的产品**（比如托管式克隆）；与 FSL
  不同，这个许可**永远**不会自动变成 MIT/Apache。

---

## 工作区架构

```
Corduit（工作区）
│
├── corduit-common       # 共享最小工具：无依赖 URL 解析器 + 自研 hyper HTTP 客户端
│
├── corduit-core        # 引擎：配置模型、规则流水线、出站编排、
│   │                   #       流量统计、健康检查
│   └── src/
│       ├── config/     #   强类型校验配置 + JSON 映射
│       ├── inbound/    #   HTTP / SOCKS5 / mixed 监听
│       ├── outbound/   #   Direct/Reject/SS/VMess/VLESS/Trojan/TUIC/Hy2/...
│       ├── routing.rs  #   规则 → 出站匹配（rule/global/direct）
│       ├── geoip.rs    #   CountryMatcher trait（依赖倒置）
│       ├── mmdb.rs     #   自研 MaxMind MMDB v2 读取器
│       └── proxy.rs    #   ProxyManager：总协调者
│
├── corduit-protocol    # 线缆协议：QUIC、TLS、WireGuard、TUIC、
│                       #   传输层（h2/gRPC/WebSocket/TLS）
│
├── corduit-dns         # DNS：DoH/DoT/UDP/TCP 服务端与客户端、缓存、
│   │                   #   fake-IP、hosts、抗污染、分流解析
│   └── src/wire.rs     #   自研 DNS wire 编解码（RFC 1035）
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
corduit-core = { version = "0.1" }   # 引擎
corduit-dns  = "0.1"                  # DNS（可选）
corduit-netstack = "0.1"              # TUN（可选）
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

Corduit 使用单一、经校验、**nextjson 原生 JSON** 的 `Config` 模型——没有临时
dialect、没有 YAML、没有多种格式。`nextjson` 的 schema 驱动 derive 处理整个
模型（默认值、别名、重命名规则），全程零 serde。最小 `config.json`：

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

所有枚举均为强类型：`OutboundType` 覆盖 `direct`、`reject`、`shadowsocks`、
`vmess`、`vless`、`trojan`、`tuic`、`hysteria2`、`quic`、`socks5`、`http`、
`wireguard`，以及代理组 `selector`、`url-test`、`fallback`、`load-balance`、
`relay`。`RuleType` 覆盖 `domain`、`domain_suffix`、`domain_keyword`、
`domain_regex`、`geoip`、`ip_cidr`、`src_ip_cidr`、`src_port`、`dst_port`、
`process_name`、`rule_set`、`match`。

---

## 支持的协议

| 层次     | 协议                                                                                                 |
| -------- | ---------------------------------------------------------------------------------------------------- |
| 代理出站 | Shadowsocks、VMess、VLESS、Trojan、TUIC、Hysteria2、SOCKS5、HTTP(S)、QUIC、WireGuard、Direct、Reject |
| 代理组   | Selector、URL-test、Fallback、Load-balance、Relay                                                    |
| 入站     | HTTP、SOCKS5、Mixed（Linux 下 redir / TProxy）                                                       |
| 传输层   | WebSocket、h2、gRPC、TLS、QUIC                                                                       |
| DNS      | UDP、TCP、DoH、DoT —— 服务端与客户端                                                                 |
| TUN      | 用户态 TCP/IP（SolidTCP）带 NAT                                                                      |

---

## 平台支持

| 平台    | 入站 | TUN | 说明                                          |
| ------- | ---- | --- | --------------------------------------------- |
| Windows | ✓    | ✓   | wintun（自动下载或 `embed-wintun` feature）   |
| Linux   | ✓    | ✓   | TUN 需要 `CAP_NET_ADMIN`                      |
| macOS   | ✓    | ✓   | TUN 需要 root                                 |
| Android | ✓    | ✓   | 经 JNI 使用 VpnService（`corduit-lib`）       |
| Flutter | —    | —   | 经 `corduit-lib` 手写 C ABI（`corduit_call`） |

---

## 跨语言 API（FFI）

`corduit-lib` 提供**手写 C ABI**——无 `flutter_rust_bridge`、无代码生成、无
运行时。任何能调用 C 的语言都可以通过**两个**入口驱动整个引擎：

| 入口                                        | 负载格式               | 适用场景     |
| ------------------------------------------- | ---------------------- | ------------ |
| `corduit_call(method, args_json)`           | `nextjson`（JSON）     | 可读的控制面 |
| `corduit_call_binary(method, payload, len)` | `rustbinary`（二进制） | 紧凑高吞吐   |

内存规则（两者一致）：

1. 每次调用返回 `FfiResponse { code: i32, data: *mut c_char }`（或
   `FfiBinaryResponse { code, data, len }`）。
2. `code == 0` 表示成功；非零表示错误（消息在 `data` 中）。
3. 用 `corduit_string_free(ptr)` / `corduit_binary_free(resp)` 释放返回缓冲区。

自描述辅助函数（让绑定不再硬编码方法列表）：

```c
const char *corduit_api_version(void);  /* ABI 版本，例如 "0.1.0" */
char       *corduit_methods(void);      /* 支持的方法列表（JSON 数组） */
void        corduit_string_free(char *);/* 释放以上两者 */
```

### 示例：Python（`ctypes`）

```python
import ctypes, json

lib = ctypes.CDLL("rust_lib_corduit.dll")   # .so / .dylib / .a
lib.corduit_call.restype = ctypes.POINTER(None)
# ... 绑定 FfiResponse 布局 ...

def call(method: str, args: dict) -> dict:
    payload = json.dumps(args).encode()
    resp = lib.corduit_call(method.encode(), payload or None)
    code, data = resp.code, ctypes.string_at(resp.data)
    lib.corduit_string_free(resp.data)
    if code != 0:
        raise RuntimeError(data.decode())
    return json.loads(data) if data else None
```

### 示例：JavaScript / TypeScript（`koffi` 或 `ffi-napi`）

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

### 示例：Dart / Flutter（`dart:ffi`）

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

### 完整方法参考

以运行时 `corduit_methods()` 返回的列表为准。当前分发表（由单元测试强制
同步）覆盖：

- **生命周期** —— `init_app`、`start_proxy_from_yaml`、`start_proxy_from_file`、
  `stop_proxy`、`is_proxy_running`、`reload_config_from_yaml`、
  `reload_config_from_file`
- **现代引擎** —— `initialize_corduit`、`start_corduit`、`stop_corduit`、
  `reload_corduit`、`get_corduit_status`、`test_config`
- **仪表盘** —— `get_traffic_stats`、`get_connections`、`close_connection`、
  `close_all_connections`、`get_logs`、`set_log_level`、`get_system_info`、
  `get_version`、`get_build_info`
- **代理与代理组** —— `get_proxies`、`get_proxy_groups`、`select_proxy`、
  `select_proxy_in_group`、`get_selected_proxy_in_group`、`get_rules`、
  `get_dns_config`、`set_proxy_mode`、`get_proxy_mode`
- **延迟测试** —— `test_proxy_latency`、`test_outbound_latency`、
  `test_tcp_connectivity`、`test_shadowsocks_latency`、`test_proxies_latency`、
  `test_proxy_latency_dto`、`test_all_proxies_latency`
- **TUN / VPN** —— `start_tun_mode`、`stop_tun_mode`、`enable_tun_mode`、
  `enable_tun_mode_with_mode`、`disable_tun_mode`、`get_tun_status`、
  `is_wintun_available`、`get_wintun_dll_path`、`ensure_wintun_dll`、
  `set_windows_proxy_mode`、`get_windows_proxy_mode_str`、
  `get_windows_tun_stats`、`enable_uwp_loopback`、`open_uwp_loopback_utility`
- **Android** —— `set_android_vpn_fd`、`get_android_vpn_fd`、
  `clear_android_vpn_fd`、`set_android_proxy_mode`、`get_android_proxy_mode`、
  `start_android_vpn`、`stop_android_vpn`、`set_vpn_fd`、`clear_vpn_fd`、
  `set_protect_socket_callback_enabled`

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
4. **不引入死重，零 serde。** serde / serde_json / serde_core / serde_derive
   已从**整个依赖图（含 `Cargo.lock`）**彻底移除——工作区中每个类型（配置、
   DTO、协议元数据）都派生 `nextjson` 的 `NsonSerialize` / `NsonDeserialize`；
   未使用的依赖一律删除，每个声明的依赖都真实被使用——由构建期检查保证。
5. **序列化是内建能力，不是事后补丁。** FFI 边界使用 `nextjson` + `rustbinary`
  （类型化、
   schema 驱动、`no_std`、`unsafe` 零容忍），跨语言客户端获得稳定、自描述
   的负载，依赖图中没有任何 serde。

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

MSRV：**Rust 1.85+**（edition 2021）。

### 发布到 crates.io

成员 crate 通过工作区清单中的 `path` + `version` 相互依赖，因此请**按依赖顺序**
发布：

```bash
cargo publish -p corduit-common    # 第 0 个（无内部依赖）
cargo publish -p corduit-protocol   # 第 1 个（无内部依赖）
cargo publish -p corduit-dns        # 第 2 个（依赖 corduit-common）
cargo publish -p corduit-netstack   # 第 3 个（依赖 corduit-dns）
cargo publish -p corduit-core       # 第 4 个（依赖 corduit-protocol + common）
cargo publish -p corduit-lib        # 第 5 个（依赖 core + netstack）
```

每个 crate 都会在 docs.rs 上以 `all-features` 构建。

---

## 安全

Corduit 同时进行**依赖图审计**与**源码级审查**：

### 依赖审计（`cargo audit`）

- 所有直接依赖均为较新且维护中的版本。整个 serde 家族（`serde`、
  `serde_json`、`serde_core`、`serde_derive`）已从**源码与 `Cargo.lock`**
  中彻底移除，由自研 `nextjson`（schema 驱动、`#![deny(unsafe_code)]`、
  有界）与 `rustbinary` 替代；原先的 `reqwest`（HTTP）、`url`、
  `hickory-proto`（DNS）、`maxminddb` 依赖替换为仓库内实现
  （`corduit-common`、`corduit-dns::wire`、`corduit-core::mmdb`）。
- 唯一剩余的公告为*提示性*：`paste`（Linux netlink 栈带入的传递性构建期
  宏辅助）不再维护——它不是安全漏洞，且在不替换整个 `tun-rs` 依赖链的
  前提下无法移除。

### 源码级加固（CWE 审查）

| 检查项                            | 结论                                               |
| --------------------------------- | -------------------------------------------------- |
| CWE-78 操作系统命令注入           | 已修复——接口名在进入 PowerShell/netsh 插值前       |
| 经 `sanitize_interface_name` 校验 |
| CWE-190 整数截断                  | 已修复——QUIC 请求负载 > 64 KiB 时拒绝而非截断；    |
| SOCKS5 凭据按 RFC 1929 做长度校验 |
| CWE-295 TLS 证书校验              | 已验证——`skip_cert_verify` 默认关闭；使用系统根    |
| 证书，仅显式配置时才绕过校验      |
| CWE-22 路径穿越                   | 已验证——wintun 解压使用固定条目名；无用户可控路径  |
| 到达文件系统                      |
| CWE-502 反序列化                  | 已验证——`nextjson`/`rustbinary` 为内存安全、有界、 |
| schema 驱动的格式                 |
| CWE-798 硬编码凭据                | 已验证——生产代码无凭据（仅测试夹具）               |
| CWE-120 / CWE-416 内存安全        | 已验证——`unsafe` 仅限手写并核对的                  |
| FFI/平台边界                      |

### 运行时态势

- **默认 TLS 1.3**（rustls/ring），仅 AEAD 密码套件（AES-GCM /
  ChaCha20-Poly1305），X25519/Curve25519 密钥交换。
- **构造即内存安全** —— Rust 的 panic 不会变成内存破坏；所有缓冲区大小
  在使用前均做边界检查。
- **失败即关闭** —— 未知协议与畸形选项在边界处被拒绝，而非静默忽略。

---

## 许可证

[PolyForm Perimeter 1.0.1](LICENSE) —— 来自
[PolyForm Project](https://polyformproject.org/licenses/perimeter/1.0.1) 的
源码可用（source-available）许可。

- ✅ 允许自由使用、修改与创作衍生作品
- ✅ 允许再分发，包括衍生作品
- ✅ 授予专利许可；保留合理使用（fair use）权利
- 🚫 **不竞争条款** —— 不得提供替代 Corduit 功能或价值的产品
- 🔒 **无自动重新授权** —— 许可永久保持 PolyForm Perimeter，绝不转为
  MIT 或 Apache-2.0

许可证：[PolyForm Perimeter 1.0.1](LICENSE) —— 通过 manifest 中的
`license-file` 字段声明（PolyForm Perimeter 没有 SPDX 标识符）。

---

## 参与贡献

Corduit 在架构上就是一个连贯的整体。提交 PR 前请注意：

- **协议**在 `corduit-protocol`；保持线缆格式稳定并用往返测试覆盖。
- **路由 / 配置**在 `corduit-core`；保持规则流水线强类型，GeoIP 依赖通过
  `CountryMatcher` 倒置。
- **DNS** 在 `corduit-dns`；保持抗污染与缓存语义有测试覆盖。
- **网络**在 `corduit-netstack`；保持用户态栈自包含并通过 NAT 测试。
- 提交前运行 `cargo test --workspace`。
