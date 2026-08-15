# Rust API

`corduit::api` 是类型化异步接口，是所有传输（FFI / HTTP / WS）最终调用的那层。绝大多数函数返回 `Result<T, String>`，失败信息是人类可读字符串；没有 panic 路径。

> 需要先 `api::init_app()`（幂等）初始化日志与 TLS provider；`start_proxy_*` / `initialize_corduit` 内部会自动处理。

## 生命周期

```rust,no_run
use corduit::api;

api::init_app();

// 启动（JSON 字符串）
api::start_proxy_from_yaml(config_json.to_string()).await?;

// 启动（从文件）
api::start_proxy_from_file("/path/config.json".to_string()).await?;

// 是否运行
let running = api::is_proxy_running().await?;

// 热重载
api::reload_config_from_yaml(new_config_json.to_string()).await?;

// 停止
api::stop_proxy().await?;
```

## 现代引擎 API（推荐）

```rust,no_run
// 初始化引擎（不启动）
api::initialize_corduit(config_json.to_string()).await?;

// 启动 / 停止 / 重载
api::start_corduit().await?;
api::reload_corduit(new_config_json.to_string()).await?;
api::stop_corduit().await?;

// 状态
let status = api::get_corduit_status().await?;   // ProxyStatus
println!("running={} inbounds={}", status.running, status.inbound_count);

// 校验配置（不启动）
let ok = api::test_config(config_json.to_string()).await?;

// 系统信息
let info = api::get_system_info().await?;
let version = api::get_version();                 // 同步
```

## 流量与连接

```rust,no_run
// 流量统计
let stats = api::get_traffic_stats().await?;          // TrafficStats
let dto = api::get_traffic_stats_dto().await?;        // TrafficStatsDto

// 连接列表
let conns = api::get_connections().await?;            // Vec<ConnectionInfo>
let active = api::get_active_connections().await?;    // Vec<ActiveConnection>

// 关闭连接
api::close_connection(id.clone()).await?;
let closed = api::close_active_connection(id).await?; // bool
api::close_all_connections().await?;

// 连接统计 (upload, download, upload_speed, download_speed)
let (up, down, ups, downs) = api::get_connection_stats().await?;
```

## 代理与分组

```rust,no_run
// 代理列表
let proxies = api::get_proxies().await?;              // Vec<ProxyInfoDto>

// 分组
let groups = api::get_proxy_groups().await?;          // Vec<ProxyGroupDto>
api::select_proxy("auto".to_string(), "ss-jp".to_string()).await?;

// 组内选择
let ok = api::select_proxy_in_group("auto".to_string(), "DIRECT".to_string()).await?;
let selected = api::get_selected_proxy_in_group("auto".to_string()).await?; // Option<String>
```

## 测速

```rust,no_run
// 单点 TCP / 代理测速
let r = api::test_proxy_latency("1.2.3.4".into(), 8388, 3000).await?;
println!("latency={:?} ok={}", r.latency_ms, r.success);

let r = api::test_outbound_latency("ss-jp".into(), 3000).await?;
let r = api::test_tcp_connectivity("example.com".into(), 443, 3000).await?;
let r = api::test_shadowsocks_latency("1.2.3.4".into(), 8388, "pass".into(), "aes-256-gcm".into(), 3000).await?;

// 批量（走 DTO 版本更省事）
let all = api::test_all_proxies_latency("http://www.gstatic.com/generate_204".into(), 3000).await?;
let batch = api::test_proxies_latency(vec![("a.com".into(), 443), ("b.com".into(), 80)], 3000).await?;
```

## 规则与 DNS 查询

```rust,no_run
let rules = api::get_rules().await?;                  // Vec<RuleDto>
let dns = api::get_dns_config().await?;               // DnsConfigDto

api::set_proxy_mode(3).await?;                        // 1=global 2=direct 3=rule
let mode = api::get_proxy_mode().await?;
```

## 日志

```rust,no_run
let lines = api::get_logs(Some(200)).await?;          // Vec<String>，None=全部
api::set_log_level("debug".to_string()).await?;
```

## TUN / Windows 平台（平台相关函数在错误平台上安全返回错误）

```rust,no_run
#[cfg(windows)]
{
    let available = api::is_wintun_available();
    api::enable_tun_mode().await?;
    api::enable_tun_mode_with_mode("global".into()).await?;
    let tun = api::get_tun_status().await?;           // TunStatus
    api::disable_tun_mode().await?;
    api::set_windows_proxy_mode("system".into()).await?;
}
```

## 本地 JSON-RPC 服务（给网页前端）

```rust,no_run
// 起服务（只绑 127.0.0.1）。token 缺省自动生成。
api::start_rpc_server(8765, Some("my-token".into())).await?;
let st = api::get_rpc_server_status()?;   // RpcServerStatus { running, addr, token_set }
api::stop_rpc_server()?;
```

## 错误处理

所有异步方法返回 `Result<T, String>`。没有 `unwrap()`，没有 panic；在 FFI 场景内部还被 `catch_unwind` 兜底。解析配置失败、端口占用、代理不存在等全部变成 `Err` 字符串。

```rust,no_run
match api::start_proxy_from_yaml(bad_json.into()).await {
    Ok(()) => {}
    Err(e) => eprintln!("配置无效: {e}"),
}
```
