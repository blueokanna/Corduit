# 方法参考（Methods Reference）

这张表就是 `rpc::dispatch` 的全部方法——FFI、HTTP、WebSocket 三端共享。参数一律是**命名参数对象**；下面用 `curl` 展示，但同样的 `{method, params}` 在三种前端都一样。

约定：
- 返回 `data` 一栏写的是成功时的值类型；
- `params` 省略 = `{}`；
- 错误统一返回 `{"code":1,"error":"..."}`。

## 生命周期

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `init_app` | — | `null` | 初始化日志/TLS（幂等） |
| `start_proxy_from_yaml` | `yaml_config: string` | `null` | 从 JSON 字符串启动代理 |
| `start_proxy_from_file` | `config_path: string` | `null` | 从文件启动 |
| `stop_proxy` | — | `null` | 停止代理 |
| `is_proxy_running` | — | `bool` | 是否运行中 |
| `reload_config_from_yaml` | `yaml_config: string` | `null` | 热重载 |
| `reload_config_from_file` | `config_path: string` | `null` | 热重载（文件） |

```bash
curl -s -X POST http://127.0.0.1:8765/rpc -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"method":"start_proxy_from_yaml","params":{"yaml_config":"{\"general\":{},\"inbounds\":[],\"outbounds\":[],\"rules\":[]}"}}'
```

## 现代引擎 API

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `initialize_corduit` | `config_json: string` | `null` | 创建引擎（不启动） |
| `start_corduit` | — | `null` | 启动引擎 |
| `stop_corduit` | — | `null` | 停止引擎 |
| `reload_corduit` | `config_json: string` | `null` | 原子热重载 |
| `get_corduit_status` | — | `ProxyStatus` | `{running,inbound_count,outbound_count,connection_count,memory_usage,uptime}` |
| `get_traffic_stats` | — | `TrafficStats` | `{upload,download,upload_speed,download_speed}` |
| `test_config` | `config_json: string` | `bool` | 只校验不启动 |
| `get_system_info` | — | `SystemInfo` | 平台/CPU/内存 |
| `get_version` | — | `string` | 版本号 |
| `get_build_info` | — | `string` | 构建信息 |

## 流量 / 连接

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `get_traffic_stats_dto` | — | `TrafficStatsDto` | `{upload,download,total_upload,total_download,connection_count,uptime_secs}` |
| `get_connections_dto` | — | `[ConnectionDto]` | 连接列表 |
| `close_connection_by_id` | `id: string` | `null` | 按 id 关闭 |
| `close_all_connections_dto` | — | `null` | 关闭全部 |
| `get_connections` | — | `[ConnectionInfo]` | 连接详情 |
| `close_connection` | `connection_id: string` | `null` | 关闭单个 |
| `get_active_connections` | — | `[ActiveConnection]` | 活动连接 |
| `close_active_connection` | `connection_id: string` | `bool` | 是否关闭成功 |
| `close_all_connections` | — | `null` | 关闭全部 |
| `get_connection_stats` | — | `[u64×4]` | `[upload,download,upload_speed,download_speed]` |

## 代理 / 分组

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `get_proxies` | — | `[ProxyInfoDto]` | `{tag,protocol_type,server,port,latency_ms,alive}` |
| `get_proxy_groups` | — | `[ProxyGroupDto]` | `{tag,group_type,proxies,selected}` |
| `select_proxy` | `group_tag, proxy_tag: string` | `null` | 选择代理 |
| `select_proxy_in_group` | `group_name, proxy_name: string` | `bool` | 组内选择 |
| `get_selected_proxy_in_group` | `group_name: string` | `string?` | 当前选中 |

## 测速

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `test_proxy_latency` | `server: string, port: u16, timeout_ms: u32` | `LatencyTestResult` | `{proxy_name,latency_ms,success,error}` |
| `test_outbound_latency` | `outbound_name: string, timeout_ms: u32` | `LatencyTestResult` | 按 tag 测 |
| `test_tcp_connectivity` | `server: string, port: u16, timeout_ms: u32` | `LatencyTestResult` | 纯 TCP 连通 |
| `test_shadowsocks_latency` | `server,port,password,cipher,timeout_ms` | `LatencyTestResult` | SS 握手延迟 |
| `test_proxies_latency` | `proxies: [{server,port}], timeout_ms: u32` | `[LatencyTestResult]` | 批量 |
| `test_proxy_latency_dto` | `tag, test_url, timeout_ms: u64` | `u64` | 毫秒延迟 |
| `test_all_proxies_latency` | `test_url, timeout_ms: u64` | `[ProxyLatencyDto]` | 全部节点 |

```bash
curl -s -X POST http://127.0.0.1:8765/rpc -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"method":"test_outbound_latency","params":{"outbound_name":"ss-jp","timeout_ms":3000}}'
```

## 规则 / DNS / 模式

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `get_rules` | — | `[RuleDto]` | `{rule_type,payload,outbound,matched_count}` |
| `get_dns_config` | — | `DnsConfigDto` | `{enable,listen,enhanced_mode,nameservers,fallback}` |
| `set_proxy_mode` | `mode: i32` | `null` | `1=global 2=direct 3=rule` |
| `get_proxy_mode` | — | `i32` | 当前模式 |
| `get_logs` | `lines?: u32` | `[string]` | 最近日志 |
| `set_log_level` | `level: string` | `null` | `silent/error/warning/info/debug` |

## TUN / Windows

| method | params | 返回 data | 平台 |
|---|---|---|---|
| `start_tun_mode` | `tun_name,tun_address,tun_netmask` | `null` | Windows |
| `stop_tun_mode` | — | `null` | Windows |
| `is_wintun_available` | — | `bool` | Windows |
| `get_wintun_dll_path` | — | `string` | Windows |
| `ensure_wintun_dll` | — | `null` | Windows（自动下载） |
| `enable_tun_mode` | — | `null` | Windows |
| `enable_tun_mode_with_mode` | `mode: string` | `null` | Windows |
| `disable_tun_mode` | — | `null` | Windows |
| `get_tun_status` | — | `TunStatus` | Windows |
| `set_windows_proxy_mode` | `mode: string` | `null` | Windows（系统代理） |
| `get_windows_proxy_mode_str` | — | `string` | Windows |
| `get_windows_tun_stats` | — | 统计对象 | Windows |
| `enable_uwp_loopback` | — | `bool` | Windows UWP 回环 |
| `open_uwp_loopback_utility` | — | `bool` | Windows |

## Android / iOS / VPN fd

| method | params | 返回 data | 平台 |
|---|---|---|---|
| `set_android_vpn_fd` / `get_android_vpn_fd` / `clear_android_vpn_fd` | `fd: i32` | — | Android |
| `set_android_proxy_mode` / `get_android_proxy_mode` | `mode: string` | — | Android |
| `start_android_vpn` / `stop_android_vpn` | — | — | Android |
| `set_ios_vpn_fd` / `get_ios_vpn_fd` / `clear_ios_vpn_fd` | `fd: i32` | — | iOS |
| `set_vpn_fd` / `clear_vpn_fd` | `fd: i32` | — | Android/iOS |
| `set_protect_socket_callback_enabled` | `enabled: bool` | — | Android |

## 本地 RPC 服务控制

| method | params | 返回 data | 说明 |
|---|---|---|---|
| `start_rpc_server` | `port: u16, token?: string` | `null` | 起服务（token 缺省自动生成） |
| `stop_rpc_server` | — | `null` | 停服务 |
| `get_rpc_server_status` | — | `RpcServerStatus` | `{running,addr,token_set}`（**不含 token**） |

## 参数类型规则

- `u16` / `u32` / `u64`：JSON 里的整数，超出范围报错；
- `i32`：有符号整数；
- `string`：必须是字符串；
- `string?` / `u32?`：可省略或传 `null`；
- `proxies`：`[{ "server": "...", "port": 443 }, ...]`。

## 运行时发现

不想硬编码方法名？调 `corduit_methods()`（FFI）或在任意传输里请求后自行维护；`CORDUIT_METHODS` 常量在 Rust 侧 `corduit::rpc::CORDUIT_METHODS`。
