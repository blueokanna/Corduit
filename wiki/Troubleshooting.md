# 排查（Troubleshooting）

## 编译 / 环境

**Q: `cargo build` 报 `error: the `no_std` attribute may only be used at the crate root`？**
不会——crypto 模块的 `no_std` 已在合并时移除。若遇到，确认你在 `main` 最新代码上。

**Q: Windows 下 wintun 相关报错？**
TUN 功能需要 `wintun.dll`。`ensure_wintun_dll` 会自动下载；离线环境请手动把 wintun.dll 放到可执行文件目录。非 TUN 场景不影响。

## 启动

**Q: `start_corduit` 返回 `Invalid config ...`？**
配置 JSON 不合法。先用 `test_config` 单独校验拿具体错误：

```bash
curl -s -X POST http://127.0.0.1:8765/rpc -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
  -d '{"method":"test_config","params":{"config_json":"{...}"}}'
```

**Q: 端口被占用 / `Address already in use`？**
换端口，或先确认旧进程已退出。Windows 上 `netstat -ano | findstr :7890` 查占用。

**Q: 报 `At least one inbound must be configured`？**
`inbounds` 数组不能为空；至少要一个监听（如 `{"type":"mixed","tag":"in","listen":"127.0.0.1","port":7890}`）。

## RPC 服务

**Q: curl 返回 `401 unauthorized`？**
token 不对或没带。HTTP 用 `Authorization: Bearer <token>`；WebSocket 用 `?token=<token>`。token 不记得了？重启服务并让服务端生成新的（或自己在代码里固定一个）。

**Q: `POST /rpc` 返回 404？**
确认路径是 `/rpc`，且方法是 `POST`。`GET /health` 只探活。

**Q: WebSocket 连不上？**
- 检查 URL 是否带 `?token=`；
- 浏览器控制台看握手是否 101；401 说明 token 错；
- 服务器只绑 127.0.0.1，跨机器连不上是**预期行为**。

**Q: 请求体太大返回 413？**
配置太大？单次 JSON 上限 16 MiB。超大订阅建议拆小或走文件加载。

## 代理行为

**Q: 流量不走代理（直连了）？**
检查规则：`match` 兜底规则有没有指向想要的出站；`mode` 是 `rule` 时规则优先，`global` 时全走选中节点，`direct` 全直连。

**Q: 某个节点 `alive=false` / 测速失败？**
- 服务器地址/端口/凭据是否正确；
- `skip-cert-verify` 是否必要（不要对不信任节点开）；
- 目标测速 URL 是否可达（`http://www.gstatic.com/generate_204`）。

**Q: DNS 走 fake-ip 后连不上？**
fake-ip 需要 TUN/透明代理配合映射回真实 IP；纯本地代理请用 `enhanced_mode: "normal"`。

## FFI

**Q: `corduit_call` 返回 `code != 0`？**
`data` 里是错误消息，先打印它。常见：方法名拼错、参数类型不对（比如端口传了字符串）、引擎未初始化。

**Q: 忘记释放返回的指针？**
`corduit_call` 的 `data` 必须 `corduit_string_free`；`corduit_call_binary` 的响应必须 `corduit_binary_free`。不释放会泄漏。

## 日志

**Q: 怎么开 debug 日志？**
`set_log_level("debug")`，或环境变量 `RUST_LOG=debug,corduit=debug`。日志缓冲区最大 5000 条，`get_logs` 可取。

**Q: 日志时间戳时区？**
日志时间戳是 UTC（`tzcraft`），不是本地时区——这是有意的，避免歧义。

## 还有问题？

带上这些信息开 issue：`get_version` / `get_build_info` 输出、`get_logs(Some(200))`、`test_config` 报错、复现步骤。
