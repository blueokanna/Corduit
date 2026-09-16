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

**Q: 日志出现 “fake-IP address has no domain mapping; resetting connection”？**
客户端在用**上一个会话缓存的 fake 地址**。映射表只在进程内，引擎重启（或显式 `reset_fake_ip_pool`）之后，此前发出去的地址就再也查不回域名了。处理策略是确定的：TCP 立刻回 RST，让应用快速失败并重新解析，而不是把 SYN 丢掉让它一直重试；UDP 直接丢弃——fake 地址不可路由，转发给代理节点没有任何意义。日志按地址合并，同一地址 10 秒内只打一条，`suppressed` 字段是被合并掉的次数。fake-ip 应答的 TTL 固定 10 秒，正常情况下一轮 DNS 就能拿到新地址。

**Q: VMess 节点“连上就断”：日志里只有一段卡顿和 `Proxy->App: EOF`，没有任何具体报错？**
这是 AEAD 握手被服务端拒绝的标准表现：v2ray/xray 不会立刻断开非法请求，而是按行为种子继续读数秒（drain）再关闭——客户端先卡住，随后看到裸 EOF。修复前的实现踩中了五条路径，0.1.6 起逐条修掉：

1. **请求头长度字段**写成了密文长度（明文 + 16）：服务端多读 16 字节、GCM 校验失败，所有 TCP 都连不通，UDP（DNS/QUIC）同样秒断。现在按规范写**明文长度**，回归测试 `a_reference_server_decodes_the_sealed_request` 按服务端解码路径逐字段校验封包头。
2. **响应头被提前消费导致死锁**：参考实现（xray 的 `transferResponse`）会把响应头缓冲到**第一条目标数据真正到达**才发送；客户端如果在转发前就阻塞等待响应头，双方互等直到超时。下行现在**惰性**消费响应头（分段状态机，可在短读/超时处恢复），不在连接建立阶段预读。
3. **ChaCha20-Poly1305 密钥派生错误**：曾是 key‖key；参考实现为 `MD5(key)‖MD5(MD5(key))`。已修并有已知答案测试 `chacha20_key_matches_the_reference_derivation`。
4. **WebSocket + TLS 的 ALPN**：默认同时宣告 `h2` 会被服务端协商成 HTTP/2，而 WS 升级报文是 HTTP/1.1 → 变成 HTTP/2 协议错误（实测参考 Xray 先回 h2 SETTINGS 帧再关闭）。WS 传输现在默认**只宣告 `http/1.1`**；TCP+TLS 保持 `h2` + `http/1.1`；显式 `alpn` 配置优先。顺带修掉了 `alpn` 只从 `quic-opts` 读取的问题——顶层 `alpn` 现在生效。
5. **流终止与 UDP 计数**：流关闭发 AEAD 终止块 `[0x00,0x10]` + tag（不再是裸 `[0x00,0x00]`，参考实现会把后者丢给 AEAD 校验并报错）；UDP 响应块使用独立的接收计数器（此前固定复用 nonce 0，第二个包起必然失败）；握手/响应头读取有真正生效的墙钟超时（`write_shutdown_emits_the_aead_end_chunk`、`response_chunks_consume_incrementing_nonces` 覆盖）。

另外：`network` 填了尚未实现的传输（`h2`/`grpc`/`kcp`/`quic`）现在会在创建出站时**显式报错**，不再静默按裸 TCP 连接（那样只会得到一个更难排查的 EOF）。现在这类失败会在 WARN 级别写明出站、目标与原因（如 `SOCKS5 relay via '<tag>' to <host>:<port> failed: ...`），不再变成无声的 EOF。

验证方式：39 个 VMess 单元测试 + 与参考 Xray 服务的端到端探针，六种形态全部实测通过——`cargo run --example vmess_probe -- tcp|chacha|ws|ws-tls|tcp-tls|udp` 分别覆盖 纯 TCP（AES-128-GCM）、ChaCha20-Poly1305、WebSocket、WebSocket+TLS 1.3、TCP+TLS 1.3、VMess UDP。

**Q: VMess（以及一切以域名配置的服务器）"秒连秒断"，日志里连一行错误都没有？**
这是**节点域名解析**走错通道的典型后果。很多订阅把节点域名放进 `nameserver-policy`，只允许用提供商自己的解析器（典型是 TCP DNS）解析：

```yaml
dns:
  nameserver-policy:
    +.v114514-1.qpon: tcp://<host>:8080
```

公开 DNS 对这些域名要么 NXDOMAIN（解析瞬间失败，连接还没建立就被放弃——表现为零点几秒的"静默断开"），要么返回诱饵地址（连过去必然黑洞）。0.1.6 起引擎解析**自己的出站服务器域名**时：先查 `nameserver-policy`（按最长后缀命中，`+.`/`*.`/裸域名写法都支持），命中就只问策略里的解析器；其余名字走 `nameservers`；系统解析器仅在引擎没有任何可用 DNS 配置时兜底。结果会做 5 分钟正向缓存。回归测试：`dns::engine_resolver` 的 5 个单测（Clash 风格后缀归一化、标签边界匹配、最长策略优先、环回 UDP 解析器实测 + 缓存命中）。

同批打磨：HTTP CONNECT 中继失败从 `debug` 提到 **WARN**（写明出站/目标/原因，与 SOCKS5 入站一致）；`Proxy->App: EOF` 这类"对端正常关闭"的通知从 INFO 降到 DEBUG——浏览网页时每个 `Connection: close` 都会触发，挂在 INFO 只会把正常关闭刷成"看起来像错误"。

**Q: 节点在 Clash / Clash Verge 里能用（延迟测试正常），在引擎里却"秒连秒断"，日志同样没有任何错误？**

这是 **legacy（pre-AEAD）VMess 服务器**的典型特征。订阅里的 `alterId > 0` 不是历史包袱——它意味着服务器（多为老版本 v2ray 或兼容配置）只接受**旧版握手**：客户端发送 `HMAC-MD5` 鉴权块 + AES-128-CFB 封装的请求头，服务器才认；而纯 AEAD 握手（现代客户端默认）会被服务器**直接关闭连接**，不回任何错误——表现就是零点几秒的静默断开，连参考实现 Xray 的最新版（同样只发 AEAD）打不通这类节点，只有 Clash 系客户端（对 `alterId>0` 走 legacy）能连。

引擎现在与 Clash 行为对齐：**`alterId > 0` 自动选择 legacy 握手**，`alterId = 0` 走 AEAD：

- 鉴权块 = `HMAC-MD5(选中的 alter UUID, u64be(时间戳))`；
- 请求头 = 版本/密钥/指令/目标/校验和整体用 **AES-128-CFB** 加密，key = `MD5(uuid ‖ "c48619fe-…")`（即 cmd_key），IV = `MD5(u64be(ts) × 4)`；
- alter 链 = `MD5(uuid ‖ "16167dc8-…")` 迭代 N 次、主 UUID 兜底，每个连接随机选一个（服务器按同样的链逐一验证）；
- 响应头 = 4 字节 CFB 解密块（key/IV 为请求密钥/IV 的 MD5），首字节回显请求、第三字节必须为 0；
- 数据帧两种模式共用（GCM 分块，nonce = 计数器 ‖ IV 切片），只有响应密钥派生由 SHA-256 改为 MD5。

日志里会看到 `alterId=N, using the pre-AEAD handshake (legacy mode)` 的启动提示。验证：NIST SP 800-38A 的 CFB 向量、独立钉死的 MD5 向量（时间戳 IV / alter 链首跳）、按服务端视角解码 legacy 头的回归测试、legacy 下行分帧测试，以及针对真实 legacy 订阅的端到端实测（curl 返回节点出口 IP）。

## FFI

**Q: `corduit_call` 返回 `code != 0`？**
`data` 里是错误消息，先打印它。常见：方法名拼错、参数类型不对（比如端口传了字符串）、引擎未初始化。

**Q: 忘记释放返回的指针？**
`corduit_call` 的 `data` 必须 `corduit_string_free`；`corduit_call_binary` 的响应必须 `corduit_binary_free`。不释放会泄漏。

## 日志

**Q: 怎么开 debug 日志？**
`set_log_level("debug")`，或环境变量 `RUST_LOG=debug,corduit=debug`。日志缓冲区最大 5000 条，`get_logs` 可取。

**Q: 日志时间戳时区？**
日志时间戳是 UTC（`common::clock`），不是本地时区——这是有意的，避免歧义。

## 还有问题？

带上这些信息开 issue：`get_version` / `get_build_info` 输出、`get_logs(Some(200))`、`test_config` 报错、复现步骤。
