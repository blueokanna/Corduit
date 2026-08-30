# Rust API

`corduit::api` 是类型化**同步**接口，是所有传输（FFI / HTTP / WS）最终调用的那层。绝大多数函数返回 `Result<T, String>`，失败信息是人类可读字符串；没有 panic 路径。

引擎是同步的：不需要 async runtime、不需要 `.await`、不需要 `#[tokio::main]`。阻塞操作由 socket 超时约束，长连接由专用线程承载。

> 需要先 `api::init_app()`（幂等）初始化日志与 TLS provider；`start_proxy_*` / `initialize_corduit` 内部会自动处理。

## 生命周期

```rust,no_run
use corduit::api;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    api::init_app();

    // 启动（JSON 字符串）
    api::start_proxy_from_yaml(config_json.to_string())?;

    // 启动（从文件）
    api::start_proxy_from_file("/path/config.json".to_string())?;

    // 是否运行
    let running = api::is_proxy_running()?;

    // 热重载
    api::reload_config_from_yaml(new_config_json.to_string())?;

    // 停止
    api::stop_proxy()?;
    Ok(())
}
```

## 现代引擎 API（推荐）

```rust,no_run
// 初始化引擎（不启动）
api::initialize_corduit(config_json.to_string())?;

// 启动 / 停止 / 重载
api::start_corduit()?;
api::reload_corduit(new_config_json.to_string())?;
api::stop_corduit()?;

// 状态
let status = api::get_corduit_status()?;   // ProxyStatus
println!("running={} inbounds={}", status.running, status.inbound_count);

// 校验配置（不启动）
let ok = api::test_config(config_json.to_string())?;

// 系统信息
let info = api::get_system_info()?;
let version = api::get_version();
```

## 流量与连接

```rust,no_run
// 流量统计
let stats = api::get_traffic_stats()?;          // TrafficStats
let dto = api::get_traffic_stats_dto()?;        // TrafficStatsDto

// 连接列表
let conns = api::get_connections()?;            // Vec<ConnectionInfo>
let active = api::get_active_connections()?;    // Vec<ActiveConnection>

// 关闭连接
api::close_connection(id.clone())?;
let closed = api::close_active_connection(id)?; // bool
api::close_all_connections()?;

// 连接统计 (upload, download, upload_speed, download_speed)
let (up, down, ups, downs) = api::get_connection_stats()?;
```

## 代理与分组

```rust,no_run
// 代理列表
let proxies = api::get_proxies()?;              // Vec<ProxyInfoDto>

// 分组
let groups = api::get_proxy_groups()?;          // Vec<ProxyGroupDto>
api::select_proxy("auto".to_string(), "ss-jp".to_string())?;

// 组内选择
let ok = api::select_proxy_in_group("auto".to_string(), "DIRECT".to_string())?;
let selected = api::get_selected_proxy_in_group("auto".to_string())?; // Option<String>
```

## 测速

```rust,no_run
// 单点 TCP / 代理测速
let r = api::test_proxy_latency("1.2.3.4".into(), 8388, 3000)?;
println!("latency={:?} ok={}", r.latency_ms, r.success);

let r = api::test_outbound_latency("ss-jp".into(), 3000)?;
let r = api::test_tcp_connectivity("example.com".into(), 443, 3000)?;
let r = api::test_shadowsocks_latency("1.2.3.4".into(), 8388, "pass".into(), "aes-256-gcm".into(), 3000)?;

// 批量（走 DTO 版本更省事）
let all = api::test_all_proxies_latency("http://www.gstatic.com/generate_204".into(), 3000)?;
let batch = api::test_proxies_latency(vec![("a.com".into(), 443), ("b.com".into(), 80)], 3000)?;
```

## 规则与 DNS 查询

```rust,no_run
let rules = api::get_rules()?;                  // Vec<RuleDto>
let dns = api::get_dns_config()?;               // DnsConfigDto

api::set_proxy_mode(3)?;                        // 1=global 2=direct 3=rule
let mode = api::get_proxy_mode()?;
```

## 日志

```rust,no_run
// 查询 / 清空日志
let logs = api::get_logs(100)?;                 // Vec<LogEntry>
api::clear_logs()?;
```

## 直接使用引擎（不经过 api 层）

```rust,no_run
use corduit::engine::{Config, Corduit};

fn main() -> corduit::engine::Result<()> {
    let config: Config = /* 从 YAML/JSON 解析或手写 */ Config::default();
    let engine = Corduit::new(config)?;
    engine.start()?;
    engine.reload(new_config)?;
    engine.stop()?;
    Ok(())
}
```

`Corduit::new` 同步构造（校验配置 + 建 ProxyManager/Router/OutboundManager），`start` 启动全部监听与后台 provider 刷新，`stop` 优雅关停并 join 所有线程。

## 并发注意

- api 层是同步的，可安全地从任意线程调用；内部锁全部短临界区。
- 不要在池 worker 上调用会阻塞很久的 api（如测速），长操作应委托到独立线程。
- `get_corduit_instance()`（lib.rs）返回 `Arc<parking_lot::RwLock<Option<Corduit>>>`，多线程共享引擎实例时用该锁。
