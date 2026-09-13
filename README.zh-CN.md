# Corduit

一个同步、no_std-ready 的 Rust 统一网络代理引擎。配置模型、规则路由、DNS 栈、用户态 TCP/IP 栈和所有线缆协议都收在一个 crate 里——不拼接任何第三方代理内核，**依赖树里没有任何 async runtime**。

[![Crates.io](https://img.shields.io/crates/v/corduit)](https://crates.io/crates/corduit)
[![docs.rs](https://img.shields.io/docsrs/corduit)](https://docs.rs/corduit)
[![MSRV](https://img.shields.io/badge/MSRV-1.78-blue)](Cargo.toml)

- **English** → [README.md](README.md)
- **完整文档** → [Wiki](https://github.com/blueokanna/Corduit/wiki)（含 FFI / RPC / 全部方法参考）

---

## 法律声明 —— 所有的构建或运行前必读

Corduit 是网络工程工具：代理协议、规则路由、DNS 与用户态 TCP/IP 协议栈。它只面向**合法用途**发布。

- **以你所在司法辖区的法律为准。** 本仓库、其许可证与文档都不授予你任何当地法律未曾给予的许可；使用后果完全由你承担。
- **不得用于违法用途。** 在某些司法辖区——包括中国大陆——提供或使用代理、VPN、隧道类服务规避国家网络管控属于违法。Corduit 不授予此类权利，维护者既不授权也不支持。
- **TUIC 与 Hysteria2 默认关闭。** 两者是可选 Cargo feature（`tuic`、`hysteria2`），默认构建中不包含；开启它们是你显式且经过考虑的决定。
- **违法用途不提供支持。** 涉及违法用途的 issue、PR、讨论一律关闭。
- **无担保、无责任。** 软件按“现状”提供，见 [LICENSE](LICENSE)——其中的附加许可人条款把合法使用作为所有许可的前提条件。
- **本声明不是法律意见。** 若不确定你的用途是否合法，请先咨询你所在辖区的执业律师，再构建或运行。

---

## 这是什么

传统代理都是"拼"出来的：Clash、sing-box、V2Ray 把配置加载器、规则引擎、DNS 解析器和一堆协议内核粘在一起，每个部件来自不同上游，各有各的版本、各有各的坑。

Corduit 反过来：**一个 crate 装下全部**——配置、路由、DNS、用户态网络、线缆协议一起开发、一起测试、一起发版。

开箱即有的东西：

- **协议**：Shadowsocks、VMess、VLESS、Trojan、WireGuard、SOCKS5、HTTP(S)，外加**可选**的 TUIC v5（`tuic`）与 Hysteria2（`hysteria2`）出站，以及代理组（selector、url-test、fallback、load-balance、relay）。
- **同步设计**：没有 tokio、没有 reactor、引擎里没有 `async`/`await`。并发来自 courierust 的 work-stealing 线程池（短任务）+ 专用线程（长连接中继）。`cargo tree` 里 **零** `tokio` / `futures` / `async-trait`。
- **no_std 核心**：`default-features = false` 时 crate 以 `no_std + alloc` 编译——加密原语、URL 解析器和纯线缆编解码（SOCKS 式地址、QPACK/HPACK、DNS wire）零 OS 依赖。
- **HTTP/TLS/QUIC 全部自包含**：HTTP/1.1、HTTP/2、HTTP/3、TLS 1.2/1.3、WebSocket、QUIC v1 全走 [courierust](https://crates.io/crates/courierust) 加仓库内手写编解码——包括一套从零写的 QUIC v1 客户端传输（RFC 9000/9001/9002），自带 TLS 1.3-over-QUIC 握手和 QPACK/HPACK 头编解码（QUIC 传输由可选 `quic` feature 控制）。不再有 hyper、rustls、quinn、tokio。
- **抗污染 DNS**：UDP/TCP/DoH/DoT 服务端与客户端、TTL 感知缓存、fake-IP、hosts、bogon 过滤、内外分流。
- **TUN 支持**：仓库内用户态 TCP/IP 栈（SolidTCP）加 NAT，Windows / Linux / macOS / Android 都能做透明代理。
- **热重载**：`Corduit::reload()` 原子换配置。
- **流量统计**：逐连接上下行、速度、活跃列表。
- **三种调用方式**（见下），背后是同一张分发表。

## Cargo feature

| Feature | 默认 | 作用 |
|---|---|---|
| `std` | 开 | 线程化引擎层：engine、DNS 服务端、netstack、RPC、FFI。隐含 `tls`。 |
| `tls` | 开 | `protocol::tls` 客户端/服务端层，以及依赖它的出站（HTTPS、Trojan、VMess/VLESS TLS、TLS 入站）。 |
| `wireguard` | 开 | `protocol::wireguard` 与 WireGuard 出站。 |
| `quic` | 关 | `protocol::quic`——仓库内自研的 QUIC v1 客户端传输（RFC 9000/9001/9002）。 |
| `tuic` | 关 | TUIC v5 出站。隐含 `quic`。 |
| `hysteria2` | 关 | Hysteria2 出站（HTTP/3 `POST /auth`、Salamander 混淆）。隐含 `quic`。 |
| `tls13` | 关 | 仓库内 TLS 1.3 客户端与浏览器对于 `ClientHello` 指纹（`chrome`、`randomized`、`off`）设计。 |
| `reality` | 关 | VLESS/Trojan/VMess 的 REALITY 客户端认证（`security: reality`）。隐含 `tls13`。 |

未开启 `tuic` / `hysteria2` 的构建会**直接拒绝**对应出站配置，并报出指出缺失 feature 的明确错误——绝不会静默退回直连。`security: reality` 与 `fingerprint` 在没有对应 feature 时同样如此。

## REALITY 与 TLS 指纹

可选的 `tls13` / `reality` feature 在 courierust 连接器之外增加第二套 TLS 引擎：`ClientHello` 由数据驱动，服务端认证是可插拔钩子。

- **指纹**（`fingerprint: chrome` | `randomized` | `off`）：密码套件表、扩展集合与顺序、groups、签名算法、ALPN 与填充都来自 [courierust_fingerprint](https://crates.io/crates/courierust) 的 Chrome profile（JA4 规范里给出的参数集），并按浏览器习惯加入 GREASE 与 512 字节对齐填充。测试会把发出去的字节反解析成 profile，对比 JA3/JA4。
- **REALITY**（`security: reality` + `public-key`、`short-id`、`server-name`）：session id 携带参考实现的 `version || time || short-id`，用 X25519 派生密钥下的 AES-256-GCM 密封；服务端认证用“临时证书证明”（证书签名字段 = `HMAC-SHA512(key, 证书公钥)`）代替 CA 链。
- **只上报、不伪造**：证书压缩（RFC 8879）与 ALPS 不对外宣告（本客户端无法解压/呈现）、`mldsa65` 校验直接报不支持、REALITY *回落*（收到真证书）是硬错误而不是静默降级。
- **仅客户端**：REALITY *服务端* 需要 Ed25519 签名能力（仓库内加密层不提供）；会话 id 的**验证**方向已实现并测试（`protocol::reality::wire::unseal_session_id`）。

```toml
[dependencies]
corduit = "0.1"                                    # std + tls + wireguard
# 可选的 QUIC 出站——请有意开启，且仅在合法前提下使用：
# corduit = { version = "0.1", features = ["tuic", "hysteria2"] }
```

## 怎么调用

不管前端是什么，最终都走同一个 `rpc::dispatch`。三种传输：

| 前端 | 传输 | 文档 |
|---|---|---|
| Flutter / Kotlin / Swift / C++ | 手写 C ABI（`corduit_call` / `corduit_call_binary`） | [FFI-API](https://github.com/blueokanna/Corduit/wiki/FFI-API) |
| 网页仪表盘 / 任意语言 | 本地 HTTP + WebSocket JSON-RPC | [RPC-API](https://github.com/blueokanna/Corduit/wiki/RPC-API) |
| Rust 应用 | 类型化同步 `api::*` | [Rust-API](https://github.com/blueokanna/Corduit/wiki/Rust-API) |

## 快速开始

Corduit 不需要 runtime：构造 `Config`、建引擎、启动、停止——生命周期就这些。

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
    // ... 跑代理 ...
    engine.stop()
}
```

或者用 JSON facade——FFI 和 RPC 层调的就是它：

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

两行开一个网页仪表盘：

```rust,no_run
use corduit::api;
api::start_rpc_server(8765, Some("my-token".into()))?; // 只绑 127.0.0.1
```

```bash
curl -X POST http://127.0.0.1:8765/rpc \
  -H "Authorization: Bearer my-token" \
  -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'
# {"code":0,"data":"Corduit v0.1.3"}
```

## 同步引擎怎么工作

Corduit 曾经是异步的。后来不是了，原因很实在：异步代理是两个世界焊在一起——tokio reactor 管引擎、阻塞传输管编解码（courierust、`std` socket），中间靠一个适配器来回泵字节。每过一道适配器就多一次唤醒、一次通道、一次上下文切换；每个跨 `await` 持有的锁都是一个潜在死锁。

同步引擎只有一个世界。并发分层，每层只做它擅长的事：

1. **短任务**——accept 分发、握手、DNS 查询、控制面、周期刷新——跑在 **courierust 的 work-stealing 线程池**上（每 worker 私有 LIFO、全局 FIFO、跨 worker 偷取、空闲零 CPU）。
2. **长连接中继**跑在**专用线程**上（每连接两条、每方向一条、带半关闭），由会话门限（`SessionGate`）限制并发，避免中继饿死握手容量。
3. **accept 循环**每个监听器一条专用线程，把接到的 socket 交给池。

阻塞由 socket 超时约束（`SO_RCVTIMEO` / `SO_SNDTIMEO`）：`WouldBlock`/`TimedOut` 就是"暂时无事"，循环在两次操作之间检查 `CancellationToken`。没有 reactor 要唤醒、没有 future 要 poll——阻塞的 worker 停在内核里，没事干的 worker 停在 condvar 上。

代价是诚实且写进文档的：大量空闲长连接的代理会每连接占一条线程。会话门限把成本封顶，work-stealing 池保证短任务路径够快。对桌面/移动代理引擎——几十到几百并发连接，不是几万——这是正确的取舍。

## 配置

一份校验过的 JSON 模型：`general` / `dns` / `inbounds` / `outbounds` / `rules`。枚举全是字符串；非法值在边界就被拒绝，不会进引擎。逐字段参考：
[Configuration](https://github.com/blueokanna/Corduit/wiki/Configuration)。

## 项目结构

```
src/
├── lib.rs          # 模块装配、全局单例、no_std 门控、平台入口
├── api.rs          # 类型化同步 API
├── ffi.rs          # 手写 C ABI
├── rpc/            # 分发表 + 本地 HTTP/WebSocket JSON-RPC
├── types.rs        # 共享 DTO
├── common/         # 同步调度器、socket/超时原语、双向中继、定时器、
│                   #   取消、URL 解析、courierust HTTP 客户端/服务端、根证书
├── engine/         # 配置、路由、入站/出站、provider、统计
├── crypto/         # 仓库内加密原语（no_std）
├── protocol/       # 线缆协议（QUIC v1 客户端、TLS、WebSocket、QPACK…）
├── dns/            # DNS 服务端/客户端、缓存、fake-IP
└── netstack/       # 用户态 TCP/IP、TUN、NAT、VPN 驱动
```

no_std 核心在 `crypto/`、`common/url`、`protocol/address`、`protocol/qpack`、`protocol/error`——纯逻辑、无 OS。线程化网络层（engine、DNS 服务器、netstack、RPC、传输）由 `std` feature 门控。

## 构建与测试

```bash
cargo check --all-targets
cargo test                            # 单元 + 属性测试（默认 feature）
cargo test --features tuic,hysteria2  # 连同可选的 QUIC 出站一起测
cargo test --doc
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo check --no-default-features                 # no_std 协议核心
cargo check --no-default-features --features std  # 引擎层，不含可选协议
```

CI 在 Linux、macOS、Windows 上跑默认矩阵，另有一个 all-features 任务（保证门控的 QUIC/TUIC/Hysteria2 代码也被构建和测试）与 `no_std` 核心检查。

MSRV：Rust 1.78。**没有任何 HTTP/TLS/QUIC 第三方库、没有任何 async runtime**——整个网络栈是 courierust 加仓库内手写协议编解码，并发是 courierust 的 work-stealing 池加 `std::thread`。

## 为什么网络栈是手写的

Corduit 曾经依赖 hyper/h2/http、rustls + tokio-rustls、quinn 和 tokio。每个都拖着自己的依赖树、自己的 TLS 提供者、自己的发版节奏、自己的安全通告——三个"做 TLS 的方式"在一个 socket 上打架。引擎现在通过 courierust（零依赖编解码套件）讲 HTTP/1.1、HTTP/2、HTTP/3、TLS 1.2/1.3 和 WebSocket，并自己管并发。

QUIC 是最有意思的部分。courierust 提供 RFC 9000/9001 线缆编解码（包头、帧、varint、包保护）和 TLS 1.3 加密原语，但没有 QUIC 连接运行时。为了不交出一个连不上真服务器的栈，Corduit 在 `protocol::quic` 里补上缺失的一层：一个真实的客户端 QUIC v1 传输——TLS 1.3-over-QUIC 握手（ClientHello → ServerHello → EncryptedExtensions/Certificate/CertificateVerify/Finished）、三个包号空间、ACK/丢包恢复 + PTO、NewReno 拥塞控制、流与连接级流控、RFC 9221 数据报——全部基于 courierust 的公开原语。每条连接一条专用驱动线程持有 UDP socket；流是同步 `Read`/`Write` 句柄，底层是互斥锁保护的缓冲区加 condvar 唤醒。

之上是 QPACK/HPACK 头编解码（`protocol::qpack`），以及由 `quic` feature 门控的 TUIC v5（`tuic`）与 Hysteria2（`hysteria2`）出站。Hysteria2 按官方协议规范实现：HTTP/3 `POST /auth` 认证、`0x401` TCP 请求、带分片的会话/UDP 数据报帧、可选 Salamander 包混淆（BLAKE2b-256）。

明确不支持——配置里出现会显式告警，绝不静默假装：0-RTT（early data）、BBR / TCP-Brutal 拥塞控制（只有 NewReno）、源端口跳动、TLS 指纹伪装。

## 安全

这是控制网络流量的本地工具，边界很重要：

- **FFI**：任何 panic 都不会穿过 `extern "C"`；所有参数都做类型检查；二进制通道有界（`rustbinary`，64 MiB 上限）。
- **RPC 服务器**：只绑 `127.0.0.1`，要求 Bearer token 常数时间比较，请求体 16 MiB 封顶，空闲连接会被回收。
- **其他**：DNS 压缩指针封顶、MMDB 读取越界检查、HTTP 响应体封顶、`skip-cert-verify` 默认关。

更多：[Security](https://github.com/blueokanna/Corduit/wiki/Security)。

## License

[PolyForm Strict License 1.0.0](LICENSE)，外加附加许可人条款。

- **允许**：个人用途（研究、实验、测试、个人学习、业余项目）与非商业目的，包括非商业组织使用。
- **不允许**：以任何形式分发本软件（无论免费或收费），以及基于本软件修改或创作衍生作品。
- **前提条件——合法使用**：不授予任何绕过网络管控的权利，且必须在你所在辖区的法律允许范围内使用。

Required Notice: Copyright 2026 blueokanna (https://github.com/blueokanna/Corduit)
