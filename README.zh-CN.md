# Corduit

同步执行的 Rust 代理引擎，核心可在 `no_std` 下编译。配置模型、规则路由、DNS 栈、用户态 TCP/IP 栈与全部线路协议都在同一个 crate 里，没有拼接任何第三方代理内核，**依赖树中也没有 async runtime**。

[![Crates.io](https://img.shields.io/crates/v/corduit)](https://crates.io/crates/corduit)
[![docs.rs](https://img.shields.io/docsrs/corduit)](https://docs.rs/corduit)
[![CI](https://github.com/blueokanna/Corduit/actions/workflows/ci.yml/badge.svg)](https://github.com/blueokanna/Corduit/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.95-blue)](Cargo.toml)

- English documentation → [README.md](README.md)
- 完整文档 → [Wiki](https://github.com/blueokanna/Corduit/wiki)（FFI / RPC / 方法参考）

---

## 法律声明（构建与运行前必读）

Corduit 是网络工程工具，涵盖代理协议、规则路由、DNS 与用户态 TCP/IP 协议栈，仅面向**合法用途**发布。

- **以你所在司法辖区的法律为准。** 本仓库、其许可证与文档不授予你任何当地法律未曾给予的许可，使用后果由你自行承担。
- **不得用于违法用途。** 在某些司法辖区（包括中国大陆），提供或使用代理、VPN、隧道类服务规避国家网络管控属于违法。Corduit 不授予此类权利，维护者既不授权也不支持。
- **TUIC、Hysteria v1 与 Hysteria2 默认关闭。** 三者均为可选 Cargo feature（`tuic`、`hysteria`、`hysteria2`），默认构建不包含，是否开启由你决定。
- **违法用途不提供支持。** 涉及违法用途的 issue、PR、讨论一律关闭。
- **无担保、无责任。** 软件按「现状」提供，见 [LICENSE](LICENSE)：其中的附加许可人条款把合法使用作为所有许可的前提条件。
- **本声明不是法律意见。** 若不确定用途是否合法，请先咨询你所在辖区的执业律师，再构建或运行。

---

## 目录

- [设计动机](#设计动机)
- [能力概览](#能力概览)
- [协议支持](#协议支持)
- [架构](#架构)
- [执行模型](#执行模型)
- [构建](#构建)
- [驱动引擎](#驱动引擎)
- [配置](#配置)
- [规则引擎](#规则引擎)
- [安全模型](#安全模型)
- [测试与持续集成](#测试与持续集成)
- [平台支持](#平台支持)
- [目录结构](#目录结构)
- [已知边界](#已知边界)
- [许可证](#许可证)

## 设计动机

多数代理都是拼装出来的：配置加载器、规则引擎、DNS 解析器与若干协议内核各来自不同上游，有各自的缺陷追踪与发版节奏。问题恰好出在这些部件的接缝处——同一条规则对路由器和解析器含义不同，同一个 profile 键被一个组件接受、被下一个组件静默丢弃。

Corduit 走的是相反的安排：一个 crate 拥有整条数据平面，因此一个配置键、一种规则类型、一个线路细节只有一份实现和一套测试。引擎是同步的：没有 async runtime、没有 reactor、数据路径里没有 `async` / `await`，线程拓扑、取消语义与失败模式都可被直接检视。

## 能力概览

| 领域 | 已实现 |
|---|---|
| **入站** | `http`、`socks5`、`mixed`（协议自动识别）；TUN 走仓库内的用户态协议栈 |
| **出站** | `direct`、`reject`、`socks5`、`socks4`/`socks4a`、`http`（明文或 TLS）、`shadowsocks`（2017 AEAD + SIP003 插件）、`shadowsocksr`、`snell` v4/v5、`vmess`、`vless`、`trojan`、`wireguard`、`naive`，以及需显式开启的 `shadowtls` v3、`tuic` v5、`hysteria` v1、`hysteria2` |
| **策略组** | `selector`、`url-test`（带防抖容差）、`fallback`、`load-balance`（轮询 / 一致性哈希 / 会话保持）、`relay` |
| **规则类型** | `domain`、`domain-suffix`、`domain-keyword`、`domain-regex`、`geosite`、`geoip`、`ip-cidr`、`src-ip-cidr`、`src-port`、`dst-port`、`in-port`/`in-type`/`in-name`/`in-user`、`process-name`、`process-path`、`network`、`rule-set`、`proxy-mode`、`and`/`or`/`not`、`match` |
| **规则集** | 文本 / YAML / JSON 载荷；`.srs`（版本 1–5，zlib）；`.mrs`（容器版本 1，zstd） |
| **Geo 数据** | `geosite.dat`（分类）、`geoip.dat` 与 `Country.mmdb`（地址归属） |
| **DNS** | [RecurseX](https://crates.io/crates/recurse-x) 解析器；profile 侧策略、上游 bootstrap、应答过滤、可选的监听式解析器 |
| **运行时** | 热重载、逐连接流量统计、JSON-RPC 控制面、C ABI、Android JNI |

支持与不支持遵循同一条标准：引擎兑现不了的能力，在**配置阶段**就以点名缺失项的错误拒绝，而不是接受后静默降级。详见 [已知边界](#已知边界)。

## 协议支持

### 入站

| 类型 | 说明 |
|---|---|
| `http` | CONNECT 与绝对 URI 转发，可选认证 |
| `socks5` | CONNECT、UDP ASSOCIATE、用户名/密码认证 |
| `mixed` | 同一监听器根据首字节识别 HTTP 或 SOCKS5，且不消费该字节 |
| TUN | 仓库内用户态 TCP/IP（`netstack`），带 fake-IP 池与 DNS 应答器 |
| `redir`、`tproxy`、`inbounds` 中的 `tun` | 可解析为类型，但**在校验阶段被拒绝**：三者都没有监听器实现，接受了它们的构建只会表面启动却什么都不应答 |

### 出站

| 类型 | 说明 |
|---|---|
| `direct`、`reject` | 直连；fail-closed 拒绝 |
| `socks5`、`socks4`/`socks4a`、`http` | 明文或 TLS 包裹的 HTTP 代理 |
| `shadowsocks` | 2017 AEAD 密码套件；SIP003 插件 `obfs`、`v2ray-plugin`、`shadow-tls` 全部以仓库内流实现 |
| `shadowsocksr` | 完整 protocol / obfs 组合 |
| `snell` | v4 与 v5，`obfs: http` / `obfs: tls` |
| `vmess`、`vless`、`trojan` | 完整客户端实现，含协议定义的复用 |
| `wireguard` | 用户态 WireGuard 客户端（feature `wireguard`） |
| `naive` | NaiveProxy 客户端 |
| `shadowtls` v3、`tuic` v5、`hysteria` v1、`hysteria2` | 由 feature 门控（`shadowtls`、`tuic`、`hysteria`、`hysteria2`） |

Shadowsocks 2022 套件以具名错误明确拒绝，不做半实现。

## 架构

```
        client ──▶ inbound ──▶ router ──▶ policy group ──▶ outbound ──▶ server
                     │           │
                     │           └── rule table · rule providers · geo databases
                     └── netstack (TUN) · DNS resolver · connection tracker
```

- **`engine/config`** —— 校验过的配置模型，以及把 profile 方言映射到该模型的编解码层。
- **`engine/routing`** —— 规则编译与匹配。规则只编译一次（正则、CIDR、端口区间、传输层），域名与后缀走索引，使有序规则表在每条连接上都不必线性扫描。
- **`engine/ruleset`** —— 二进制规则集解码器（`.srs`、`.mrs`）、两者共用的压缩域集，以及它们解码成的 headless 规则模型。
- **`engine/geo`** —— Geo 数据库：严格 protobuf 解码、分类与国家码首次使用即编译、地址区间合并。
- **`engine/outbound`** —— 每个协议一个模块，外加策略组。
- **`engine/inbound`** —— 监听器。
- **`dns`** —— 基于 RecurseX 的 profile → 解析器适配。
- **`netstack`** —— 用户态栈：TCP 状态机、UDP 会话、TUN 集成、平台路由。
- **`protocol`**、**`crypto`** —— 线路编解码与密码学原语，两者均兼容 `no_std`。
- **`common`** —— 同步原语、socket、带缓冲的流、定时器、取消机制，以及 provider 更新所用的 HTTP 客户端。

依赖方向是单向的：`protocol` 与 `crypto` 不认识 `engine`，`engine` 也不会伸手进 `netstack` 的内部。

## 执行模型

这里没有执行器，并发是显式的：

- 来自 [`courierust`](https://crates.io/crates/courierust) 的 work-stealing 池运行短小、有界任务——accept、握手、provider 刷新；
- 长连接中继各占一个线程，取消令牌触发时退出；
- 每一次阻塞等待要么带截止时间，要么可被该令牌打断，因此停机不依赖某个网络操作的完成。

这也是为什么引擎可以被 `main` 线程、Flutter worker、Android service 或 C 调用方直接驱动：没有需要「接入」的运行时。

## 构建

**要求**：Rust 1.95（edition 2024）与 C 工具链。C 工具链用于 `zstd`（`.mrs` 规则集的后端）；`mrs` 属于默认 feature 集，所以直接 `cargo build` 就会用到它。无 C 工具链的交叉编译同样支持——见 [已知边界](#已知边界)。

```bash
cargo build --release
cargo build --release --no-default-features --features std,tls,wireguard   # 无 C 依赖
```

### Feature 开关

| Feature | 默认 | 作用 |
|---|---|---|
| `std` | 开 | 线程化引擎层（隐含 `tls`） |
| `tls` | 开 | 依赖 TLS 的出站所用的客户端 / 服务端层 |
| `wireguard` | 开 | WireGuard 协议与出站 |
| `mrs` | 开 | `.mrs` 二进制规则集；引入自带 C 源码的 `zstd` 解码器 |
| `quic` | 关 | 仓库内 QUIC v1 传输（RFC 9000/9001/9002） |
| `tuic`、`hysteria`、`hysteria2` | 关 | 对应出站（隐含 `quic`） |
| `tls13` | 关 | 仓库内 TLS 1.3 客户端，可呈现浏览器形态 `ClientHello` 指纹 |
| `reality`、`shadowtls` | 关 | REALITY 与 ShadowTLS v3（隐含 `tls13`） |

`default-features = false` 时以 `no_std + alloc` 编译；纯线路编解码与密码学原语不依赖 OS。

## 驱动引擎

```rust
use corduit::engine::{Config, Corduit};

fn main() -> corduit::engine::Result<()> {
    let text = std::fs::read_to_string("config.yaml")?;
    let config = Config::from_str(&text)?;
    let engine = Corduit::new(config)?;
    engine.start()?;
    // ... 提供服务，直到停机 ...
    engine.stop()
}
```

JSON 门面（`api::start_proxy_from_yaml` 等）与 JSON-RPC 控制面（`rpc`）都建立在这同一个引擎之上；`ffi` 提供的 C ABI 与 Android JNI 桥接调用前者。可运行示例在 [`examples/`](examples)，并在 docs.rs 上有文档。

## 配置

profile 是 YAML（或 JSON）文档，形态贴近引擎所消费的方言，只有一条规矩：**每个键只有一个含义，未实现的键是错误而不是空操作**。

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

[`wiki/Configuration.md`](wiki/Configuration.md) 记录每个键；[`wiki/Rules.md`](wiki/Rules.md) 详细说明规则引擎、规则集格式与 Geo 数据库。

## 规则引擎

规则自上而下求值，第一条命中即生效。有三条性质值得明确写出，因为它们在别处很容易被做错：

1. **不存在静默丢弃。** payload 编译不了的规则、格式解不出的规则集、不存在的 Geo 分类——每一条都会在加载期报出并点名具体条目。一条永远不可能命中的规则，是后期极难定位的路由缺陷。
2. **索引不会改变规则顺序。** 域名与后缀规则会建索引以加速查找，但候选仍按配置顺序求值，因此被索引的规则不会越过前面出现的正则或进程规则。
3. **域名解析是显式选择。** 只有规则没有声明 `no-resolve` 时，`ip-cidr` 与 `geoip` 才能看到路由器解析出的地址；若全部 IP 规则都是 `no-resolve`，引擎在域名解析上不会付出任何一次开销。

规则集的格式**按内容判定，绝不看文件名**：载荷被识别为文本、`.srs`、`.mrs` 或 Geo 数据库依据的是字节本身，因为订阅 URL 的扩展名说明不了任何事。

## 安全模型

- **Fail closed。** 配置点名了本构建已关闭的协议，则拒绝加载，绝不退化为直连；global 模式若没有代理出站，则走拒绝而不是泄露。
- **输入有界。** 仓库内每个解码器都有明确上限：规则集载荷（解压后 256 MiB）、Geo 数据库（512 MiB）、HTTP 响应体、DNS 报文尺寸，以及逻辑规则与 protobuf 消息的嵌套深度。
- **不信任 profile 字符串。** 会进入线路格式的取值（主机名、路径、凭据）一律校验；控制字符直接拒绝，而不是转义后放行。
- **自实现密码学。** AEAD、哈希、KDF 与流密码都在 `crypto` 中实现并由已知答案测试覆盖；不存在 OpenSSL 或 ring 依赖。
- **默认不跳过证书校验。** `skip-cert-verify` 是每个出站的显式选择。

细节见 [`wiki/Security.md`](wiki/Security.md)。

## 测试与持续集成

```bash
cargo test --all-features      # 1097 项
cargo test                     # 默认 feature 下 1008 项
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

测试覆盖：纯编解码的已知答案与性质测试、规则引擎的顺序与优先级测试、二进制格式解码器的字节级夹具（含手工拼装的夹具，避免解码器只被自己的写入器验证）、以及环回环境下的引擎端到端测试。

CI 在三个桌面平台运行，检查声明的 MSRV，交叉检查 Android（aarch64 与 x86_64，通过 NDK）与 iOS，用裸机目标验证 `no_std` 核心，并且出现任何编译警告或 rustdoc 链接失效都会让构建失败。

## 平台支持

| 平台 | 状态 |
|---|---|
| Linux、macOS、Windows | 支持；桌面 CI |
| Android | 支持（`jni` 桥接，TUN 走 `VpnService`） |
| iOS | 支持（TUN；`sysinfo` 指标改由平台 API 提供） |
| HarmonyOS（`target_env = ohos`） | 引擎层支持 |
| `no_std + alloc` 目标 | 协议核心可编译；线程化引擎不可用 |

## 目录结构

```
src/
  engine/    config、routing、ruleset、geo、inbound、outbound、dns、providers
  netstack/  用户态 TCP/IP、TUN 集成、平台路由
  dns/       profile → RecurseX 适配、监听式解析器
  protocol/  线路编解码：TLS 1.3、QUIC、WebSocket、WireGuard、地址类型
  crypto/    AEAD、哈希、KDF、流密码、随机数
  common/    同步原语、socket、流、定时器、HTTP 客户端
  api.rs     类型化同步门面
  rpc/       JSON-RPC 控制面
  ffi.rs     C ABI
```

## 已知边界

以下都是有意为之，且每一条都会在**配置阶段**暴露，而不是留到运行时。

| 领域 | 现状 | 后果 |
|---|---|---|
| 流量嗅探（TLS ClientHello SNI / HTTP Host 回捞） | 未实现 | 域名来自 DNS 侧（fake-IP、redir-host）。客户端直接用 IP 连接时，域名规则无法命中；这类流量用 `ip-cidr` / `geoip` 兜底 |
| 子规则段（`sub-rules`） | 未实现 | 用「具名 rule-provider + `rule-set` 规则」表达等价语义 |
| `.srs` 中的客户端条件（`wifi_ssid`、`package_name` 等） | 识别并拒绝 | 整份规则集被拒绝并点名该条件；不含这些条件的规则集正常加载 |
| 无 C 工具链的目标上的 `.mrs` | 可用 feature 关闭 | 以 `--no-default-features --features std,tls,wireguard` 构建；此时 `.mrs` 载荷会以点名缺失 feature 的错误被拒绝 |
| `DOMAIN-KEYWORD` 匹配 | 与关键词数量线性相关 | 关键词集合保持精简，或用 `domain-regex` 表达 |

## 许可证

见 [LICENSE](LICENSE)。Corduit 仅面向合法用途发布：它是面向代理协议、路由、DNS 与用户态 TCP/IP 的网络工程工具。
