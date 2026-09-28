# 安全（Security）

Corduit 同时做**依赖图审计**与**源码级加固**。

## 依赖面

- 整个依赖图零 serde（`Cargo.lock` 里没有 `serde*`），序列化只走 `nextjson` / `rustbinary`（两者都 `#![deny(unsafe_code)]`）；
- 时间用仓库内的 UTC 时钟（`common/clock.rs`，Hinnant 历法算法）格式化；
- `cargo audit` 无已知漏洞。

## 远程控制面

| 面 | 边界 | 鉴权 |
|---|---|---|
| FFI（C ABI） | 仅同进程可调 | 进程身份 |
| HTTP JSON-RPC | `127.0.0.1` 独占 | `Authorization: Bearer <token>` |
| WebSocket JSON-RPC | `127.0.0.1` 独占 | `?token=<token>` |
| 入站代理（HTTP/SOCKS5） | 按配置绑定 | 可选 `authentication`（覆盖 HTTP 请求/CONNECT、SOCKS5 TCP/UDP，以及 TUN 栈自己的 SOCKS5 客户端） |

要点：
- RPC 服务**从不绑 `0.0.0.0`**，其它机器无法触达；
- token 比较用常数时间 `ct_eq`，抗时序侧信道；空 token 会被**拒绝**（视为未设置并生成随机 token），`?token=` 空串不可能通过校验；
- token 256 位随机（`getrandom`），自动生成时不落盘、不写日志；
- `get_rpc_server_status` 只返回 `{running, addr, token_set}`，**永远不返回 token**。

## 边界加固（对照 CWE）

| 项 | 状态 |
|---|---|
| CWE-78 命令注入 | 接口名进 PowerShell/netsh 前经 `sanitize_interface_name` 校验 |
| CWE-74 URL 注入 | `Url::parse` 统一拒绝全部原始控制字节（CR/LF/NUL 等）：`path()` 会被拼进多处探测请求行（`GET {path} HTTP/1.1`），此前任何一处都可能被 CRLF 注入头；现在一类问题在解析器一层关掉 |
| CWE-190 整数截断 | SOCKS5 凭据按 RFC 1929 校验长度；WebSocket 帧长与分片上限由 `courierust_ws` 会话强制（≤16 MiB） |
| CWE-345 伪装升级 | 出站 WebSocket 握手校验 `Sec-WebSocket-Accept`（`base64(SHA-1(key‖GUID))`），不匹配即硬失败，绝不“告警后继续” |
| CWE-93 头注入 | 出站 WS 握手头在写线之前校验（token 名称、值中不得含 CR/LF 或 NUL），保留头（Host/Upgrade/Connection/Sec-WebSocket-*）不允许被配置覆盖 |
| CWE-295 TLS 校验 | `skip_cert_verify` 默认关；只有显式配置才绕过；默认用系统根证书；QUIC 出站（TUIC/Hysteria/Hysteria2）在装 1-RTT 密钥前要求证书链**且**通过验证的 `CertificateVerify`，仓库内 TLS 1.3 客户端同样强制 |
| CWE-400 资源耗尽 | DNS 压缩指针 ≤128 跳（内置应答器同样）；MMDB 读取全程边界检查；HTTP body ≤64 MiB；RPC body/WS 消息 ≤16 MiB；RPC 连接 600s 上限；重定向 ≤8 跳；UDP 会话（direct/shadowsocks）并发上限 1024，QUIC 流表 1024、datagram 队列 64，hysteria2/tuic 分片重组 4 MiB/64 条 |
| CWE-306 缺少鉴权 | RPC 必须 token |
| CWE-502 反序列化 | FFI 二进制走 rustbinary 有界 profile（64MiB + 集合上限 + 拒绝尾部字节） |
| 开放代理 | SOCKS5 UDP ASSOCIATE 只中继关联客户端（IP + 端口：声明了就按声明的，否则钉扎首包源址）的数据报 |
| panic 安全 | FFI 全包 `catch_unwind`，panic 不跨 `extern "C"` 边界 |

## 加密实现

- AEAD 标签校验、GHASH、X25519 全部避免数据相关分支/索引；AES 轮函数在有 AES-NI（x86/x86_64）或 ARMv8 AES 指令（aarch64）的 CPU 上按运行时检测走硬件指令（不碰查表），软件回退是经典固定表实现（无数据相关分支；表按数据索引，属无可硬件支持的通用可移植 AES 的固有取舍）；GHASH 的域乘法同样按运行时检测走 PCLMULQDQ（x86/x86_64）/ PMULL（aarch64）（3 次 carry-less 乘法 + 移位约简），软件回退为无分支掩码实现，两条路径由逐位对拍的一致性测试钉死；
- MAC 比较用常数时间；
- 哈希/加密原语在仓库内实现（熵源 `getrandom` 除外）；文本编解码中的 base64 复用
  `courierust_crypto::base64`，全工作区只有一份实现，不做第二遍；
- MD5/SHA-1 仅用于协议兼容（SS/VMess 派生），不用于抗碰撞场景。

## 给使用者的提醒

1. RPC token 属于敏感信息，别写进前端仓库/日志；
2. `allow_lan` 或把入站 `bind_address` 设成 `0.0.0.0` 会暴露代理给局域网——按需开启；
3. `skip-cert-verify` 只在你信任的节点上开；
4. 规则文件/订阅走 HTTPS 拉取（`HttpClient` 默认校验证书）。
