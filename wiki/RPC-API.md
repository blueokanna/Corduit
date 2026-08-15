# RPC API（网页 / 任意语言）

本地 JSON-RPC 服务，供网页仪表盘或任何带 HTTP 栈的语言使用。只绑定 `127.0.0.1`，必须带 token。

## 启动

```rust,no_run
use corduit::api;
api::start_rpc_server(8765, Some("my-secret-token".into())).await?;
// 不传 token 会自动生成 256 位随机 token；
// 端口传 0 会随机分配，用 api::get_rpc_server_status() 查实际地址。
```

## 端点

| 端点 | 鉴权 | 说明 |
|---|---|---|
| `GET /health` | 无 | 探活，返回 `{"ok":true}` |
| `POST /rpc` | `Authorization: Bearer <token>` | JSON-RPC 请求 |
| WebSocket（任意路径） | `?token=<token>` 查询参数 | JSON-RPC over WS |

> 为什么 WebSocket 用查询参数？浏览器 JS 无法给 WebSocket 设置 `Authorization` 头，这是标准做法。token 只在本地回环传输。

## 请求 / 响应格式

请求：

```json
{ "method": "get_proxies", "params": { } }
```

成功：

```json
{ "code": 0, "data": [ { "tag": "DIRECT", "protocol_type": "direct", "alive": true } ] }
```

失败：

```json
{ "code": 1, "error": "Proxy not initialized" }
```

`params` 可以省略（等价于 `{}`）。

## curl 示例

```bash
TOKEN="my-secret-token"
BASE="http://127.0.0.1:8765"

# 版本
curl -s -X POST "$BASE/rpc" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'

# 带参数：测一个出站延迟
curl -s -X POST "$BASE/rpc" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"method":"test_outbound_latency","params":{"outbound_name":"ss-jp","timeout_ms":3000}}'

# 启动代理
curl -s -X POST "$BASE/rpc" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"method":"start_corduit","params":{"config_json":"{...}"}}'

# 错误演示：不带 token
curl -s -X POST "$BASE/rpc" -H "Content-Type: application/json" \
  -d '{"method":"get_version"}'
# HTTP 401 {"code":1,"error":"unauthorized"}
```

## 浏览器 JS 示例

```js
const TOKEN = "my-secret-token";
const BASE = "http://127.0.0.1:8765";

async function rpc(method, params = {}) {
  const res = await fetch(`${BASE}/rpc`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({ method, params }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  if (body.code !== 0) throw new Error(body.error);
  return body.data;
}

// 用法
const version = await rpc("get_version");
const stats = await rpc("get_traffic_stats");
await rpc("start_corduit", { config_json: JSON.stringify(config) });
```

## WebSocket 示例（实时推送友好）

```js
const ws = new WebSocket(`ws://127.0.0.1:8765/ws?token=${TOKEN}`);

ws.onopen = () => {
  ws.send(JSON.stringify({ method: "get_traffic_stats" }));
  // 可周期性发送轮询，或后续扩展服务端主动推送
};
ws.onmessage = (e) => {
  const resp = JSON.parse(e.data);
  console.log(resp.code === 0 ? resp.data : resp.error);
};
ws.onerror = (e) => console.error("ws error", e);
```

Python 也能直接调：

```python
import json, urllib.request

req = urllib.request.Request(
    "http://127.0.0.1:8765/rpc",
    data=json.dumps({"method": "get_version"}).encode(),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer my-secret-token"},
)
print(json.load(urllib.request.urlopen(req)))
# {'code': 0, 'data': 'Corduit v0.1.0'}
```

## 限制与安全

- 只绑 `127.0.0.1`（`::1` 也支持，见 `bind` 参数），**不绑 `0.0.0.0`**；
- token 比较是常数时间（`ct_eq`），抗时序侧信道；
- 请求体 / WebSocket 消息上限 16 MiB，超出返回 `413`；
- 连接生命周期上限 600 秒，空闲连接自动回收；
- CORS 全放开（本地服务 + token 门控），允许 `Authorization` 头；
- 响应里的错误消息由 `nextjson` 转义，不会破坏 JSON。

完整方法见 [Methods-Reference](Methods-Reference)。
