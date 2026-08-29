# Corduit

用 Rust 写的统一网络代理引擎。配置、规则路由、DNS、用户态网络栈和所有线缆协议都在同一个 crate 里，不靠拼第三方代理内核。

[![Crates.io](https://img.shields.io/crates/v/corduit)](https://crates.io/crates/corduit)
[![docs.rs](https://img.shields.io/docsrs/corduit)](https://docs.rs/corduit)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue)](Cargo.toml)

- **English** → [README.md](README.md)
- **完整文档** → [Wiki](https://github.com/blueokanna/Corduit/wiki)（FFI / RPC / 全部方法参考都在里面）

---

## 这是什么

传统代理都是"拼"出来的：Clash、sing-box、V2Ray 把配置加载、规则引擎、DNS 解析和一堆协议实现从不同上游粘到一起，每个部件各有各的版本、各有各的坑。

Corduit 反过来：**一个 crate 里装下全部**——配置模型、规则路由、DNS、用户态网络栈、各协议实现一起开发、一起测试、一起发版。

开箱即有的东西：

- **协议**：Shadowsocks、VMess、VLESS、Trojan、WireGuard、SOCKS5、HTTP(S)，加上代理组（选择、测速、回退、负载均衡、中继）。
- **HTTP/TLS 全部自包含**：HTTP/1.1、HTTP/2、HTTP/3、TLS 1.2/1.3、WebSocket 全走 [courierust](https://crates.io/crates/courierust)（零依赖编解码栈），外加仓库内手写的 RFC 6455 帧。不再有 hyper、rustls、tokio-tungstenite。
- **抗污染 DNS**：UDP/TCP/DoH/DoT 服务端与客户端、TTL 缓存、fake-IP、hosts、Bogon 过滤、国内外分流。
- **TUN 支持**：仓库内用户态 TCP/IP 栈（SolidTCP）加 NAT，Windows / Linux / macOS / Android 都能做透明代理。
- **热重载**：`Corduit::reload()` 原子换配置。
- **流量统计**：逐连接上下行、速度、活动列表。
- **三种调用方式**（见下），背后是同一张分发表。

## 怎么调用

不管前端是什么，最终都走同一个 `rpc::dispatch`。三种传输：

| 前端 | 传输 | 文档 |
|---|---|---|
| Flutter / Kotlin / Swift / C++ | 手写 C ABI（`corduit_call` / `corduit_call_binary`） | [FFI-API](https://github.com/blueokanna/Corduit/wiki/FFI-API) |
| 网页仪表盘 / 任意语言 | 本地 HTTP + WebSocket JSON-RPC | [RPC-API](https://github.com/blueokanna/Corduit/wiki/RPC-API) |
| Rust 应用 | 类型化异步 `api::*` | [Rust-API](https://github.com/blueokanna/Corduit/wiki/Rust-API) |

## 快速开始

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

给网页开个口子，两行：

```rust,no_run
use corduit::api;
api::start_rpc_server(8765, Some("my-token".into())).await?; // 只绑 127.0.0.1
```

```bash
curl -X POST http://127.0.0.1:8765/rpc \
  -H "Authorization: Bearer my-token" \
  -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'
# {"code":0,"data":"Corduit v0.1.0"}
```

## 配置

一份校验过的 JSON 模型：`general` / `dns` / `inbounds` / `outbounds` / `rules`。枚举值都是字符串，不合法的在入口就被拒绝，引擎内部只处理已验证的数据。逐字段参考：
[Configuration](https://github.com/blueokanna/Corduit/wiki/Configuration)。

## 目录结构

```
src/
├── lib.rs          # 模块装配、全局变量、平台入口
├── api.rs          # 类型化异步 API
├── ffi.rs          # 手写 C ABI
├── rpc/            # 共享分发表 + 本地 HTTP/WebSocket JSON-RPC
├── types.rs        # 共享 DTO
├── common/         # URL 解析、courierust HTTP 客户端/服务端、阻塞-异步桥、根证书
├── engine/         # 配置、路由、入站/出站、统计
├── crypto/         # 仓库内加密原语
├── protocol/       # 线缆协议（TLS、WebSocket、WireGuard…）
├── dns/            # DNS 服务端/客户端、缓存、fake-IP
└── netstack/       # 用户态 TCP/IP、TUN、NAT、VPN 驱动
```

## 构建与测试

```bash
cargo check --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
```

最低 Rust 版本：1.95。整个 crate 不依赖任何第三方 HTTP/TLS/QUIC 库——网络层全是 courierust 加仓库内手写协议编解码。

## 为什么旧 HTTP/TLS/QUIC 栈没了

以前 Corduit 的网络层靠 hyper/h2/http、rustls + tokio-rustls、quinn 拼起来：每个都带自己的依赖树、自己的 TLS provider、自己的发版节奏和自己的安全公告。现在 HTTP/1.1、HTTP/2、HTTP/3、TLS 1.2/1.3、WebSocket 全走 courierust（零依赖），RFC 6455 帧是手写的，阻塞/异步之间的缝隙由仓库内一个单线程泵的适配器补上。基于 QUIC 的出站传输（TUIC、Hysteria2、VMess-over-QUIC）连同 quinn 一起移除了——courierust 的 QUIC 只有编解码器，为一个没法跟真实服务器互通的自研 QUIC 栈承担风险不值。

## 安全

这东西在本机管网络流量，边界得把严：

- **FFI**：panic 不会跨 `extern "C"` 边界；所有参数入口做类型校验；二进制通道有界（rustbinary，64MiB 上限）。
- **RPC 服务**：只绑 `127.0.0.1`，必须带 token（常数时间比较），请求体上限 16 MiB，空闲连接自动回收。
- **其它**：DNS 压缩指针限 128 跳、MMDB 全程边界检查、HTTP 响应体有上限、`skip-cert-verify` 默认关。

详见 [Security](https://github.com/blueokanna/Corduit/wiki/Security)。

## 协议

PolyForm Perimeter 1.0.1：可以自由使用、修改、分发；唯一限制是不能拿它做替代 Corduit 本身的产品。
