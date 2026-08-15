# 快速开始（Getting Started）

从零开始，把 Corduit 跑起来，并用三种前端各调通一个方法。

## 1. 依赖

在 `Cargo.toml` 里加：

```toml
[dependencies]
corduit = "0.1"
tokio = { version = "1", features = ["full"] }
```

> Corduit 内部自带 Tokio 运行时管理；Rust 应用只需在自己的 `#[tokio::main]` 里调用 `api::*` 即可。

## 2. 最小可运行示例

```rust,no_run
use corduit::engine::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) 构造并校验配置（errors 都是类型化的，不 panic）
    let config = Config::default();

    // 2) 创建引擎
    let engine = corduit::engine::Corduit::new(config).await?;

    // 3) 启动（打开入站监听、出站连接池）
    engine.start().await?;

    // 4) 停引擎
    engine.stop().await?;
    Ok(())
}
```

## 3. 用 Rust API 直接调用

```rust,no_run
use corduit::api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 启动代理（config_json 是 nextjson JSON 字符串，见 Configuration）
    let config_json = r#"{
      "general": { "mode": "rule", "mixed_port": 7890, "log_level": "info" },
      "dns": { "enable": true, "nameservers": ["https://dns.google/dns-query"] },
      "inbounds": [{ "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 7890 }],
      "outbounds": [{ "type": "direct", "tag": "DIRECT" }],
      "rules": []
    }"#;
    api::start_proxy_from_yaml(config_json.to_string()).await?;

    let status = api::get_corduit_status().await?;
    println!("running = {}", status.running);

    let version = api::get_version();
    println!("{version}");

    api::stop_proxy().await?;
    Ok(())
}
```

## 4. 开启网页/任意语言用的本地 JSON-RPC 服务

```rust,no_run
use corduit::api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 绑定 127.0.0.1:8765。token 缺省时自动生成一个 256 位随机 token，
    // 可用 get_rpc_server_status() 查实际地址；token 本身不对外返回。
    api::start_rpc_server(8765, Some("my-secret-token".to_string())).await?;

    let status = api::get_rpc_server_status()?;
    println!("RPC 服务: {}", status.addr.unwrap_or_default());

    // 保持进程存活
    tokio::signal::ctrl_c().await?;
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
# {"code":0,"data":"Corduit v0.1.0"}
```

WebSocket 版（浏览器友好，token 放查询串）：

```bash
# 用 wscat 或浏览器
wscat -c "ws://127.0.0.1:8765/ws?token=my-secret-token"
> {"method":"get_proxies"}
< {"code":0,"data":[...]}
```

## 5. 用 FFI（Flutter / 原生）调用

C 接口不需要额外依赖，直接在原生侧链接：

```c
// 声明（头文件由你自己按这个签名写）
typedef struct { int code; char* data; } FfiResponse;
extern FfiResponse corduit_call(const char* method, const char* args_json);
extern void corduit_string_free(char* ptr);

FfiResponse r = corduit_call("get_version", NULL);
printf("%s\n", r.data);   // "Corduit v0.1.0"
corduit_string_free(r.data);
```

完整绑定示例（C / Dart）见 [FFI-API](FFI-API)。

## 下一步

- 想知道每个方法长什么样 → [Methods-Reference](Methods-Reference)
- 想配真实代理节点 → [Configuration](Configuration)
- 遇到问题 → [Troubleshooting](Troubleshooting)
