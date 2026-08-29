# 安全（Security）

Corduit 同时做**依赖图审计**与**源码级加固**。

## 依赖面

- 整个依赖图零 serde（`Cargo.lock` 里没有 `serde*`），序列化只走 `nextjson` / `rustbinary`（两者都 `#![deny(unsafe_code)]`）；
- 时间用 `tzcraft`（`#![deny(unsafe_code)]`）替代 `chrono`；
- `cargo audit` 无已知漏洞。

## 远程控制面

| 面 | 边界 | 鉴权 |
|---|---|---|
| FFI（C ABI） | 仅同进程可调 | 进程身份 |
| HTTP JSON-RPC | `127.0.0.1` 独占 | `Authorization: Bearer <token>` |
| WebSocket JSON-RPC | `127.0.0.1` 独占 | `?token=<token>` |
| 入站代理（HTTP/SOCKS5） | 按配置绑定 | 可选 `authentication` |

要点：
- RPC 服务**从不绑 `0.0.0.0`**，其它机器无法触达；
- token 比较用常数时间 `ct_eq`，抗时序侧信道；
- token 256 位随机（`getrandom`），自动生成时不落盘、不写日志；
- `get_rpc_server_status` 只返回 `{running, addr, token_set}`，**永远不返回 token**。

## 边界加固（对照 CWE）

| 项 | 状态 |
|---|---|
| CWE-78 命令注入 | 接口名进 PowerShell/netsh 前经 `sanitize_interface_name` 校验 |
| CWE-190 整数截断 | SOCKS5 凭据按 RFC 1929 校验长度；WebSocket 帧长按 RFC 6455 校验且 ≤16 MiB |
| CWE-295 TLS 校验 | `skip_cert_verify` 默认关；只有显式配置才绕过；默认用系统根证书 |
| CWE-400 资源耗尽 | DNS 压缩指针 ≤128 跳；MMDB 读取全程边界检查；HTTP body ≤64 MiB；RPC body/WS 消息 ≤16 MiB；RPC 连接 600s 上限 |
| CWE-306 缺少鉴权 | RPC 必须 token |
| CWE-502 反序列化 | FFI 二进制走 rustbinary 有界 profile（64MiB + 集合上限 + 拒绝尾部字节） |
| 开放代理 | SOCKS5 UDP ASSOCIATE 只中继已认证客户端 IP 的数据报 |
| panic 安全 | FFI 全包 `catch_unwind`，panic 不跨 `extern "C"` 边界 |

## 加密实现

- AEAD 标签校验、GHASH、AES S-box、X25519 全部避免数据相关分支/索引；
- MAC 比较用常数时间；
- 所有 hash/加密原语仓库内实现，无外部加密依赖（熵源 `getrandom` 除外）；
- MD5/SHA-1 仅用于协议兼容（SS/VMess 派生），不用于抗碰撞场景。

## 给使用者的提醒

1. RPC token 属于敏感信息，别写进前端仓库/日志；
2. `allow_lan` 或把入站 `bind_address` 设成 `0.0.0.0` 会暴露代理给局域网——按需开启；
3. `skip-cert-verify` 只在你信任的节点上开；
4. 规则文件/订阅走 HTTPS 拉取（`HttpClient` 默认校验证书）。
