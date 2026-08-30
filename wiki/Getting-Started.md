# 快速开始（Getting Started）

从零开始，把 Corduit 跑起来，并用三种前端各调通一个方法。

## 1. 依赖

在 `Cargo.toml` 里加：

```toml
[dependencies]
corduit = "0.1"
```

**不需要任何 async runtime**。Corduit 是同步引擎：没有 tokio，不需要
`#[tokio::main]`，没有 `.await`。并发由 courierust 的 work-stealing 线程池
（短任务）+ 专用线程（长连接中继）承载。

## 2. 最小可运行示例

```rust,no_run
use corduit::engine::{Config, Corduit};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) 构造并校验配置（errors 都是类型化的，不 panic）
    let config = Config::default();

    // 2) 创建引擎
    let engine = Corduit::new(config)?;

    // 3) 启动（打开入站监听、出站连接池、后台 provider 刷新）
    engine.start()?;

    // 4) 停引擎
    engine.stop()?;
    Ok(())
}
```

## 3. 用 Rust API 直接调用

```rust,no_run
use corduit::api;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 启动代理（config_json 是 nextjson JSON 字符串，见 Configuration）
    let config_json = r#"{
      "general": { "mode": "rule", "mixed_port": 7890, "log_level": "info" },
      "dns": { "enable": true, "nameservers": ["https://dns.google/dns-query"] },
      "inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }],
      "outbounds": [{ "type": "direct", "tag": "DIRECT" }],
      "rules": []
    }"#;
    api::start_proxy_from_yaml(config_json.to_string())?;

    let status = api::get_corduit_status()?;
    println!("running = {}", status.running);

    let version = api::get_version();
    println!("{version}");

    api::stop_proxy()?;
    Ok(())
}
```

## 4. 开启网页/任意语言用的本地 JSON-RPC 服务

```rust,no_run
use corduit::api;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 绑定 127.0.0.1:8765。token 缺省时自动生成一个 256 位随机 token，
    // 可用 get_rpc_server_status() 查实际地址；token 本身不对外返回。
    api::start_rpc_server(8765, Some("my-secret-token".to_string()))?;

    let status = api::get_rpc_server_status()?;
    println!("RPC 服务: {}", status.addr.unwrap_or_default());

    // 保持进程存活（同步 sleep；真实应用用事件循环/线程等待）
    std::thread::sleep(Duration::from_secs(3600));
    api::stop_rpc_server()?;
    Ok(())
}
```

然后用 curl 验证：

```bash
curl -X POST http://127.0.0.1:8765/rpc \
  -H "Authorization: Bearer my-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'
# {"code":0,"data":"Corduit v0.1.3"}
```

WebSocket 版（浏览器友好，token 放查询串）：

```bash
# 用任意 WS 客户端连接 ws://127.0.0.1:8765/ws?token=my-secret-token
# 然后发送 {"method":"get_version"}，收到 {"code":0,"data":"Corduit v0.1.3"}
```
