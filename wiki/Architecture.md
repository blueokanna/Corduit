# 架构（Architecture）

Corduit 是一个单一 crate，内部按内聚模块组织，每个文件夹对应一个 `mod.rs`。

## 模块结构

```mermaid
flowchart TB
    ROOT["corduit (单一 crate)<br/>crate 根 = src/lib.rs"]

    ROOT --> LIB["lib.rs<br/>模块装配 / 全局单例 / 平台入口"]
    ROOT --> API["api.rs<br/>类型化异步 API"]
    ROOT --> FFI["ffi.rs<br/>手写 C ABI"]
    ROOT --> RPC["rpc/<br/>分发表 + HTTP/WebSocket 服务"]
    ROOT --> TYPES["types.rs<br/>共享 DTO"]
    ROOT --> COMMON["common/<br/>URL 解析 + courierust HTTP 客户端/服务端<br/>+ 阻塞-异步桥 + 根证书"]
    ROOT --> ENGINE["engine/<br/>代理引擎核心"]
    ROOT --> CRYPTO["crypto/<br/>加密原语"]
    ROOT --> PROTOCOL["protocol/<br/>线缆协议（QUIC v1 客户端、TLS、QPACK/HPACK、WebSocket）"]
    ROOT --> DNS["dns/<br/>DNS 解析与服务器"]
    ROOT --> NETSTACK["netstack/<br/>用户态 TCP/IP + TUN"]

    ENGINE --> EC["config/<br/>校验过的配置模型"]
    ENGINE --> EI["inbound/<br/>HTTP / SOCKS5 / mixed 监听"]
    ENGINE --> EO["outbound/<br/>Direct/SS/VMess/VLESS/Trojan/WireGuard/TUIC/Hysteria2/HTTP(S)/SOCKS5<br/>+ proxy-provider 节点注册表"]
    ENGINE --> ER["routing.rs<br/>规则 → 出站匹配 + rule-provider 管理"]
    ENGINE --> EG["geoip.rs + mmdb.rs<br/>CountryMatcher + MMDB 读取"]
    ENGINE --> EP["proxy.rs<br/>ProxyManager 协调器"]
    ENGINE --> EU["provider_updater.rs<br/>后台：订阅/规则刷新 + 健康检查"]
    ENGINE --> EPP["proxy_provider.rs<br/>ProxyProviderManager（订阅节点）"]
    ENGINE --> ET["traffic_stats.rs<br/>流量统计"]
```

## 一个分发表，三种传输

```mermaid
flowchart LR
    subgraph Transport
        CA["corduit_call<br/>(C ABI, nextjson JSON)"]
        CB["corduit_call_binary<br/>(C ABI, rustbinary 二进制)"]
        HTTP["POST /rpc<br/>(Bearer token)"]
        WS["WebSocket /ws?token=..."]
        RUST["api::*<br/>(Rust 直接调用)"]
    end
    DISPATCH["rpc::dispatch(method, args)<br/>参数全部在边界校验"]
    ENGINE["引擎各模块"]
    CA --> DISPATCH
    CB --> DISPATCH
    HTTP --> DISPATCH
    WS --> DISPATCH
    RUST --> DISPATCH
    DISPATCH --> ENGINE
```

设计要点：**所有传输共享同一个分发表**，新增一个方法只需改 `rpc/mod.rs` 的 `dispatch` 一处，FFI/HTTP/WS/Rust 全部自动可用；`CORDUIT_METHODS` 常量让客户端可以动态发现支持的方法。

## 一次请求的生命周期

```mermaid
sequenceDiagram
    participant Client as 客户端（curl / JS / Dart / Rust）
    participant T as 传输层（FFI / HTTP / WS）
    participant D as rpc::dispatch
    participant A as api::*
    participant E as 引擎（Corduit / ProxyManager）

    Client->>T: {"method":"start_corduit","params":{"config_json":"..."}}
    T->>D: 反序列化 + 鉴权（FFI 走 rustbinary，HTTP/WS 走 JSON + token）
    D->>A: 校验参数类型（Args::string/u16/...）
    A->>E: 调用类型化 API
    E-->>A: Result<T>
    A-->>D: nextjson::to_value(result)
    D-->>T: Ok(Value) / Err(String)
    T-->>Client: {"code":0,"data":...} 或 {"code":1,"error":"..."}
```

## 配置热重载生命周期

```mermaid
sequenceDiagram
    participant C as 客户端
    participant PM as ProxyManager
    participant CFG as Config RwLock
    participant R as Router
    participant I as InboundManager
    participant O as OutboundManager

    C->>PM: reload(new_config)
    PM->>CFG: write(new_config) 后立即释放写锁
    PM->>R: reload()（内部读同一把锁）
    PM->>I: reload()
    PM->>O: reload()
    R-->>PM: ok
    I-->>PM: ok
    O-->>PM: ok
    PM-->>C: Ok(())
```

> 注意：`ProxyManager::reload` 先替换配置、释放写锁，再让各子管理器各自拿读锁重载。Tokio 的 `RwLock` 不可重入，持写锁等读锁会死锁——这是刻意设计。

重载时 provider 的同步（`Router::reload` + `OutboundManager::reload`）：

```mermaid
sequenceDiagram
    participant R as Router
    participant RPM as RuleProviderManager
    participant O as OutboundManager
    participant PPM as ProxyProviderManager

    R->>R: 重编译规则 + 默认出站
    R->>RPM: 删除消失的 provider；新增/替换配置变化的；未变的不动
    O->>O: 清空注册表 + 清空 provider
    O->>PPM: 按 runtime 配置重新加载订阅，节点重新注册
    PPM-->>O: 节点按 tag 进入共享注册表
    O-->>R: ok
```

ProviderUpdater 在 `Corduit::start` 时启动、`stop` 时停止，默认 60 秒 tick，按各自 `interval` 刷新订阅/规则并跑健康检查（见 [Rules](Rules#6-后台-providerupdater)）。

## 安全边界

```mermaid
flowchart LR
    subgraph 对外面
        FFI["C ABI（仅同进程）"]
        RPC["127.0.0.1 HTTP/WS（token 鉴权）"]
        INBOUND["入站代理监听（HTTP/SOCKS5）"]
    end
    subgraph 边界检查
        V1["catch_unwind（FFI 不跨边界展开）"]
        V2["ct_eq 常数时间 token 比较"]
        V3["请求体/消息 16MiB 上限"]
        V4["rustbinary 64MiB + 集合上限"]
        V5["DNS 压缩指针 ≤128 跳"]
    end
    FFI --> V1
    RPC --> V2
    RPC --> V3
    FFI --> V4
    INBOUND --> V5
```

详细说明见 [Security](Security)。

## no_std 边界

引擎整体**不能** no_std——它跑在 tokio 上，依赖 `std::net`、线程、TUN 驱动和文件系统。可以独立出来做 no_std 的部分：

| 模块 | 状态 |
|---|---|
| `crypto/`（哈希/MAC/流密码/AEAD/KDF/X25519/Base64/Hex/UUID） | ✅ 已 no_std：全模块零 `std::` 引用，只用 `core` + `alloc`，无任何外部依赖 |
| `protocol/address.rs`（SOCKS 地址编解码） | ⚠️ 接近：仅 `fmt` / `io::Cursor` / `net` 三处 std，可平移 |
| `dns/wire.rs`（DNS 报文编解码） | ⚠️ 接近：`fmt` / `net` / `HashMap` 可换 `core` / `alloc` |
| `engine` / `rpc` / `api` / `ffi` / `netstack` / `common` | ❌ 依赖 tokio + std + 平台 API，无法 no_std |

也就是说：**加密与线缆编解码核心可以无 std 复用（比如做固件/嵌入式端）**，但完整代理引擎需要 std + tokio，这是设计使然，不是遗漏。
