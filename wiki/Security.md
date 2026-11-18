# 安全（Security）

Corduit 同时做**依赖图审计**与**源码级加固**。

## 依赖面

- 整个依赖图零 serde（`Cargo.lock` 里没有 `serde*`），序列化只走 `nextjson` / `rustbinary`（两者都 `#![deny(unsafe_code)]`）；
- 时间用仓库内的 UTC 时钟（`common/clock.rs`，Hinnant 历法算法）格式化；
- `cargo audit`：**0 个已知漏洞**（2026-09-29 实测，1277 条公告扫描 210 个依赖）；唯一告警是 `paste`（unmaintained），它由 Linux 目标的 `tun-rs → route_manager → netlink-packet-*` 链引入，是编译期 proc-macro，不在运行路径上。

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
| CWE-93 头注入 | 所有"把名字拼进文本行"的边界共用同一条判定（`common::text::has_line_breaking_byte`）：出站 WS 握手头（token 名称、值中不得含 CR/LF 或 NUL，保留头不允许被配置覆盖）、Snell obfs 与 SIP003 simple-obfs 的伪造请求（host/uri/method 校验，host 长度上限保证 `ClientHello` 的 16 位长度字段不溢出）、SSR 的 `obfs-host`、SOCKS5 入站的域名（CR/LF/NUL/空白直接拒绝并回失败应答） |
| CWE-295 TLS 校验 | `skip_cert_verify` 默认关；只有显式配置才绕过；默认用系统根证书；QUIC 出站（TUIC/Hysteria/Hysteria2）在装 1-RTT 密钥前要求证书链**且**通过验证的 `CertificateVerify`，仓库内 TLS 1.3 客户端同样强制 |
| CWE-345 DNS 应答（引擎自用回退解析器） | 只接受事务 ID 与问题（名字/类型/类）完全匹配的应答，截断（TC）按失败处理并换下一台——竞态或伪造的应答不会被当成地址（`dns::trusted`） |
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

---

## 规则集投毒：能做什么、不能做什么

规则集是**数据**，不是代码：没有解释器、没有插件、没有可执行字段。因此它无法执行任意代码，它能触及的只有三样东西——内存、CPU，以及路由决策本身。

| 攻击面 | 现在被什么挡住 |
|---|---|
| 解压炸弹（几 KB 索取几百 MB） | 规则集解压后硬上限 **64 MiB**；zstd 解码器另加**放大比例上限**（输入长度 × 128，外加 1 MiB 的底），所以小文件拿不到与自身体量不符的输出 |
| 海量条目耗尽内存或索引时间 | 单份规则集条目上限 **2,097,152**；二进制解码器读到 `count` 就核对，不等分配；Geo 分类同受此限 |
| 正则表达式耗尽编译资源 | 单份规则集最多 **4096** 条表达式，每条编译后大小上限 **1 MiB**（`size_limit` 显式设定，不用默认值）；Geo 分类里的表达式同样受约束 |
| 关键词拖慢每条连接 | `DOMAIN-KEYWORD` 是逐条子串扫描，因此上限 **65,536** 条关键词，超出直接拒绝 |
| 结构不一致（截断、计数与剩余字节矛盾、位流未精确耗尽、FSE/Huffman 表不完整） | 一律硬错误；不存在「解出一半」的规则集，因为半份规则集比一份坏规则集更难发现 |
| 路由投毒（把流量导向错误出口或 REJECT） | 这本来就是规则集的职责，格式校验无法区分「恶意」与「正常」；边界因此在**信任**上，见下 |

**信任边界**：只从你信任的 URL 或文件加载规则集；优先用固定版本 URL 或内容指纹；`type: file` 的 `path` 应当指向你自己的目录。`type: http` 的 HTTPS 强制与来源校验属于配置装配层的策略（`api.rs` 在装配配置时执行），引擎本身只按给定 URL 取回内容——跨信任边界部署时，请把规则集来源当作代码来源对待。

**一句话的结论**：投毒能让你的分流出错（这是数据本身的性质），但不能让进程崩溃、不能被用来执行代码、也不允许用一份小文件换走你几百 MB 内存或每条连接的 CPU 时间。
