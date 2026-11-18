# 规则引擎（Rules）

规则引擎解决一个问题：**一条连接该走哪个出站**。它由三部分组成：

1. **模式（mode）**：global / direct / rule，决定整体策略；
2. **规则表（rules）**：从上到下第一条命中生效，先匹配先赢；
3. **规则集与代理订阅（rule-provider / proxy-provider）**：把外部维护的规则和节点列表拉进来，不必全部手写。

这篇文章按「先模式、再规则、再 provider、最后第三方规则集对照」的顺序讲清楚，每个行为都对应真实代码，不含示例性虚构。

---

## 1. 三种模式

模式有两个来源，**运行时模式优先**：

| 优先级 | 来源 | 取值 |
|---|---|---|
| 高 | 运行时模式（RPC `set_proxy_mode` / FFI 同名字段） | `0`=跟随配置，`1`=global，`2`=direct，`3`=rule |
| 低 | 配置文件 `general.mode` | `rule` / `global` / `direct` |

运行时模式为 `0`（跟随配置）时，才去看 `general.mode`。RPC 把模式切成 `1/2/3` 会立刻生效，直到切回 `0` 或重载配置。

三种模式的实际行为（`routing.rs::match_outbound`）：

| 模式 | 行为 |
|---|---|
| `global` | 全部流量走**代理组**：第一个 `selector` / `url-test` / `fallback` / `load-balance` 组；若一个组都没有，走第一个非 `direct`/`reject` 的普通出站；再没有就 `DIRECT` |
| `direct` | 全部流量走直连出站（配置里第一个 `direct` 出站的 tag；没有则 `DIRECT`） |
| `rule` | 按规则表顺序匹配；第一条命中即返回其 `outbound`；全部不命中走默认出站 |

**默认出站**（`resolve_default_outbounds`，每次配置解析时算好，请求时不扫描）：
- `default`：配置里第一个出站；
- `direct`：第一个 `direct` 类型出站，否则字符串 `DIRECT`；
- `global`：如上（代理组 → 非直连非拒绝出站）。

> 一个容易踩的坑：`rule` 模式下，如果**规则表为空**，引擎会启用「大陆自动直连」兜底（见 2.4 节）。一旦你配置了任何规则，就严格按顺序匹配，不再有内置捷径——兜底只在「一条规则都没有」这一种情况下存在，这是刻意的设计。

---

## 2. 规则表（rules）

配置里的 `rules` 是数组，每条规则：`{ "type", "payload", "outbound" }`。匹配**从上到下**，第一条命中立即生效，后面的不再看。`outbound` 必须能解析到已定义出站（校验器在加载时报错，而不是运行时静默直连）。

### 2.1 规则类型与精确语义

| `type` | payload 含义 | 匹配语义（对照实现） |
|---|---|---|
| `domain` | 完整域名 | 大小写不敏感**精确**相等 |
| `domain-suffix` | 域名后缀 | 匹配**自身 + 所有子域**，且带点边界：`example.com` 命中 `example.com` 和 `a.example.com`，但**不**命中 `notexample.com` |
| `domain-keyword` | 域名子串 | 域名包含该子串即命中（大小写不敏感） |
| `domain-regex` | 正则 | 对整个域名跑正则；**大小写不敏感**（DNS 名字本就不区分大小写，RFC 1035 §2.3.3）——需要区分时用内联 `(?-i)`。编译期校验，非法正则直接报配置错误 |
| `geoip` | 国家/地区码，或定制库里的提供商标签 | 目标 IP 属于该国家/地区即命中（GeoIP 库）；大小写不敏感，`A-Z{2,16}` |
| `ip-cidr` | 目标 IP 段 | 目标 IP 在 CIDR 内（支持 IPv4/IPv6） |
| `src-ip-cidr` | 源 IP 段 | 连接发起方 IP 在 CIDR 内 |
| `src-port` | 源端口 | 端口或端口范围，见下 |
| `dst-port` | 目标端口 | 同上 |
| `process-name` | 进程名 | 匹配进程的**全路径**、**文件名**或**去掉 `.exe` 的名字**（大小写不敏感） |
| `rule-set` | 规则集名 | 交给同名 `rule-provider` 判断（见 4.1 / 4.4） |
| `geosite` | 分类名，如 `netflix`、`category-ads-all` | 域名属于该 geosite 分类即命中（Geo 数据库，见 2.3 节）。与 `rule-set` **不是同一个命名空间** |
| `process-path` | 进程全路径 | 全路径（大小写不敏感）精确相等；`process-name` 只认文件名，这个是钉死可执行文件本身 |
| `network` | `tcp` / `udp` | 连接使用的传输层 |
| `in-port` | 入站监听端口 | 端口语法同 `src-port` |
| `in-type` | `HTTP` / `SOCKS5` | 客户端与之对话的入站协议 |
| `in-name` | 入站 tag | 连接落在哪个入站上 |
| `in-user` | 入站认证用户名 | 该入站认证通过的用户名 |
| `proxy-mode` | `rule` / `global` / `direct` | 命中当前生效模式。注意 `global` / `direct` 模式下规则表根本不参与匹配（模式短路），所以真正可达的只有 `rule`：有些 profile 方言用它表达模式，本引擎的模式是原生的，两者殊途同归 |
| `and` / `or` / `not` | 子规则数组 | 逻辑组合，见下 |
| `match` | 忽略 | 永远命中，一般放最后做兜底 |

逻辑组合规则把条件写在 `rules` 数组里（`payload` 留空）：`and` 要求**全部**子规则命中，`or` 要求**任一**命中，`not` 取反且**恰好**一个子规则。没有子规则的 `and`/`or`、子规则数不为 1 的 `not`、嵌套超过 **8 层**，都在加载时报配置错误——这几种组合要么恒真要么恒假，没有一种能猜出作者本意。

> `geosite` 和 `rule-set` 也容易混淆：前者查的是 `geosite.dat` 里的分类，后者查的是你在 `rule_providers` 里定义并命名的规则集。名字撞车不会互相兜底——引擎在 `Router::new` 时就检查每个 `rule-set` 引用的名字必须存在。

端口规则 payload 支持：单个端口 `53`、范围 `80-90`（含两端）、逗号分隔 `53,80-90,443`。

### 2.2 域名规则的 DNS 行为（重要）

`geoip` 和 `ip-cidr` 需要 IP，但代理流量常常只知道域名。引擎的处理是：

1. 先用已有 IP 试一次；
2. 只有域名时，解析出全部 IP，**逐个**拿去做 geoip/ip-cidr 匹配，任一命中即命中。

解析有明确的上限与缓存，不会因为 DNS 拖慢请求：

- 解析超时 **3 秒**（超时按「未命中」处理，继续走域名规则）；
- 结果缓存 **300 秒**、容量 4096 条；
- 解析失败的负缓存 **30 秒**，避免把坏域名反复打爆上游。
- 解析走的是**当前 profile 的引擎 DNS**（`nameservers` / `nameserver-policy` / `default-nameserver`），只有引擎没有可用解析器时才退回系统解析器。规则看到的地址必须就是连接将要使用的地址：否则 `geoip` / `ip-cidr` 可能按一个答案判定、而拨号用的是另一个，两者恰好会在「profile 特意配了 DNS」时不一致。IPv4 与 IPv6 **都会**被问到——一条 IP 规则可能匹配到任一族的地址。

### 2.3 Geo 数据库：`geosite` / `geoip` / `mmdb`

`geosite` 和 `geoip` 读的不是规则集，而是**数据库**。引擎认三种文件，**按内容判定，从不看文件名**：

| 文件 | 格式 | 提供什么 | 实现 |
|---|---|---|---|
| `Country.mmdb` | MaxMind DB v2 | 按 IP 查国家/地区/提供商 | `engine/mmdb.rs`（自解析，不依赖 libmaxminddb） |
| `geoip.dat` | v2ray `GeoIPList` protobuf | 国家码 → CIDR | `engine/geo/geoip.rs` |
| `geosite.dat` | v2ray `GeoSiteList` protobuf | 分类名 → 域名 | `engine/geo/geosite.rs` |

判定顺序：以 `\xab\xcd\xefMaxMind.com` 结尾 → mmdb；外层「字段 1 = 消息」且内层「字段 1 = 字符串、字段 2 = 消息」→ geosite / geoip；两者都不是 → 拒绝加载并说明。一个叫 `geosite.dat` 的 mmdb 会按 mmdb 加载，反过来也一样：社区分发的文件名从来不可靠。

**去哪找**（每个候选独立加载，装哪个算哪个）：

1. 代码注册的路径 —— `set_default_database_path()`、`set_default_geosite_path()`；
2. 环境变量 —— `CORDUIT_GEOIP_DB`、`CORDUIT_GEOSITE_DB`；
3. 可执行文件同目录 —— `Country.mmdb`、`geoip.dat`、`geosite.dat`。

运行期也能换：`Router::load_geoip_database(path)` 接受任意三种格式（按内容分派），`Router::load_geosite_database(path)` 只接受 geosite。文件**缺失**是正常状态（`GEOIP`/`GEOSITE` 规则顺延到下一条），文件**存在但读不动**会记警告并点名文件——后者是配置错误，值得看见。

`GEOIP` 的判定顺序（`GeoIpDatabase::matches_country`）：

1. `LAN` / `PRIVATE` —— 查 IANA 特殊用途表（与 DNS 反污染闸门共用一张表），任何数据库都不参与；
2. `Country.mmdb` 里**有**该地址的记录 —— 以它为准；
3. 否则查 `geoip.dat` 的对应国家码。

只装 `geoip.dat` 的社区系 profile 因此不需要 mmdb；只装 mmdb 的 sing-box 系 profile 也照旧工作。

`GEOSITE` 的语义与 v2ray / Mihomo 一致：

| `Domain.Type` | 语义 |
|---|---|
| `Plain`(0) / `RootDomain`(2) | 后缀：`example.com` 命中自身与所有子域，**不**命中 `notexample.com` |
| `Full`(3) | 精确 |
| `Regex`(1) | 整域名正则，大小写不敏感 |

**为什么它不会「加载即卡顿」**：社区 `geosite.dat` 通常有一千多个分类、上百万条域名，全量编译要几秒和几百 MB，而一个 profile 往往只点十几个分类。所以引擎加载时**只建索引**（每个分类一条「名字 + 字节区间」，零拷贝保留原文件），**第一次被规则用到时才解码那一个分类**并缓存：无用分类常驻开销是名字加十六字节，热分类只编译一次（`RwLock<HashMap<.., Arc<..>>>`，并发首次访问也只会编译一次）。

分类内部用**压缩前缀树**（`ruleset/succinct.rs`）：域名按字符倒序插入，同 TLD 共享路径；查询是一次遍历、每字节两次 O(1) 位图运算（rank/select），内存约为 `HashSet<String>` 的十分之一。这套结构就是 sing-box `.srs` 里那份，geosite 与二进制规则集共用同一实现，语义不可能漂移。

地址侧用**合并后的区间数组**二分（`geo/ipset.rs`）：`geoip:cn` 的几千条 CIDR 合并成区间，一次查询 log(n) 次比较、无分配。指针式 32 层 trie 是插入型工作负载的教科书答案；只建一次、读几百万次的集合，排序区间数组在内存和缓存上都更合适——这是权衡，不是偏好，代码注释里写的是同一句话。

分类名或国家码写错（`geosite:netflex`、`GEOIP:CNX`）**不会静默**：第一次查不到就在日志里点名「该分类不在数据库里，规则永远不会命中」，且只报一次。

### 2.4 大陆自动直连兜底

`rule` 模式下规则表为空时，以下两种情况直接走 `direct`：

- 域名以 `.cn` 结尾（含裸 `cn`，大小写不敏感，忽略末尾点）；
- 解析出的目标 IP **不可全球路由**，或 GeoIP 判定为 CN。「不可全球路由」用的是 DNS 反污染闸门那张 [IANA 特殊用途表](Configuration)（含多播、保留段、benchmark、`::ffff:0:0/96`、Teredo/6to4/ORCHID 等）——与 GEOIP 的 `LAN`/`PRIVATE` 伪国家码共用同一份判定，全仓库只有一张表。

**只要规则表非空，这段兜底就被跳过**，一切由你的规则说了算。想要「国内直连、其余走代理」的效果，参考第 5 节把 `cncidr` 等规则集挂进来即可，不必依赖兜底。

---

## 3. 模式怎么切（运行时）

RPC / FFI 提供 `set_proxy_mode(mode)`，参数是整数：`0`=CONFIG、`1`=GLOBAL、`2`=DIRECT、`3`=RULE。非法值会被归一化回 `0`（跟随配置），不会进入未定义状态。查询用 `get_proxy_mode()`，返回当前生效的运行时模式。

---

## 4. Provider：把外部规则和节点拉进来

### 4.1 rule-provider（规则集）

配置 JSON 顶层的 `rule_providers` 数组（与 `rules`/`outbounds` 平级，引擎启动或重载时读取）：

```json
{
  "rule_providers": [
    {
      "name": "proxy",
      "type": "http",
      "behavior": "domain",
      "url": "https://cdn.jsdelivr.net/gh/example/rulesets@release/proxy.txt",
      "interval": 86400
    }
  ]
}
```

字段与约束（`api.rs::configure_rule_providers` 一次性校验，不合格直接拒绝加载）：

| 字段 | 说明 |
|---|---|
| `name` | 规则集名，`rule-set` 规则用它引用；必须唯一 |
| `type` | `http` 或 `file`；`http` 必须配 `url` 且 **必须 https**（明文 http 拒绝），`file` 必须配 `path` |
| `behavior` | `domain` / `ip-cidr` / `classical`，决定怎么解析文件内容，见下 |
| `interval` | 自动更新间隔（秒），**最小 60**，小于 60 拒绝 |
| `url` / `path` | 数据来源 |

`behavior` 决定内容解释方式（`rule_provider.rs::parse_rules`）：

| behavior | 内容格式 | 典型文件 |
|---|---|---|
| `domain` | `payload:` 列表或逐行纯域名；支持 `keyword:` 前缀、`regexp:`/`regex:` 前缀、`full:` 精确前缀、`+`/`.` 前缀；默认按**后缀**处理 | 常见的 `proxy.txt`、`direct.txt`、`apple.txt`、`google.txt` 等域名列表 |
| `ip-cidr` | `payload:` 列表或逐行 CIDR | `telegramcidr.txt`、`cncidr.txt`、`lancidr.txt` |
| `classical` | 完整的规则行：`DOMAIN,xxx`、`DOMAIN-SUFFIX,xxx`、`DOMAIN-KEYWORD,xxx`、`DOMAIN-REGEX,xxx`、`IP-CIDR,xxx`、`IP-CIDR6,xxx`、`SRC-IP-CIDR,xxx`、`PROCESS-NAME,xxx` | 混合规则文件 |

加载细节：

- 内容为空 → 报错（宁可不加载，也不留一个空集让流量漏过）；
- `http` 拉取失败时自动回退到本地缓存（`%TEMP%/corduit/rule-providers/<name>.rules`），缓存也没有才报错；
- 规则在启动时加载，之后由后台 **ProviderUpdater** 按 `interval` 自动刷新（见第 6 节）。

规则里引用：`{ "type": "rule-set", "payload": "proxy", "outbound": "PROXY" }`。**启动时校验**：所有 `rule-set` 规则引用的名字必须存在于 `rule_providers`，否则报「Rule references missing provider」。

### 4.2 proxy-provider（代理订阅）

配置 JSON 顶层的 `proxy_providers` 数组：

```json
{
  "proxy_providers": [
    {
      "name": "subscription",
      "type": "http",
      "url": "https://example.com/sub?token=...",
      "interval": 3600,
      "health_check": { "enable": true, "url": "http://www.gstatic.com/generate_204", "interval": 300, "timeout": 5000 }
    }
  ]
}
```

字段与约束（`api.rs::configure_proxy_providers` 校验，规则和 rule-provider 一致）：

- `type` `http`/`file`；`http` 必须 https，`file` 必须配 `path`；
- `interval` ≥ 60 秒；
- `health_check`：可选，`enable`/`url`/`interval`/`timeout`（毫秒）/`lazy`。

订阅内容两种格式都认（`proxy_provider.rs::parse_proxies`）：

```json
{ "proxies": [ { "type": "ss", "tag": "jp-01", "server": "...", "port": 8388, "password": "...", "cipher": "aes-256-gcm" } ] }
```

或直接是裸数组 `[ { ... }, ... ]`。条目创建是**宽容的**：单条坏节点只记警告跳过，不会让整个订阅加载失败；但整个内容解析失败会报错。

加载出的节点会注册进**共享出站注册表**（按 tag），所以：

- 代理组可以直接在 `outbounds` 里引用订阅节点的 tag；
- 也可以更省事，用 `use` 把整个 provider 的节点全部展开进组：

```json
{
  "type": "selector",
  "tag": "PROXY",
  "outbounds": ["DIRECT"],
  "use": ["subscription"]
}
```

`use` 里的名字必须在 `proxy_providers` 里声明过，否则校验器报「references unknown proxy provider」。

### 4.3 两者的热重载语义

重载配置（`reload`）时：

- **规则集**：删除已消失的、新增新出现的、替换「配置有变化」的；配置没变的规则集保持已加载内容不动（由后台 updater 按自己的 interval 刷新）；
- **代理订阅**：出站注册表清空后整体重建（`OutboundManager::reload`），旧节点不再残留。

### 4.4 二进制与数据库载荷（`.srs` / `.mrs` / `.dat` / `.mmdb`）

rule-provider 的载荷**按内容判格式**（`ruleset::detect`）：扩展名和 `Content-Type` 都可伪造或配错，magic 不会。

| 载荷内容 | 结果 |
|---|---|
| 文本 / `payload:` YAML / JSON 数组 | 按 `behavior` 解析（4.1 节，行为不变） |
| sing-box 二进制规则集（文件以 `SRS` 开头） | **完整解码**，见下 |
| 另一族二进制规则集（文件是 zstd 帧，帧内 `MRS` + 版本） | **完整解码**，见下 |
| `geosite.dat` / `geoip.dat` | 拒绝：那是数据库不是规则集，报错指路到 `GEOSITE,<分类>` / `GEOIP,<国家>` |
| `Country.mmdb` | 同上，指路到 Geo 数据库 |

#### `.srs`（版本 1–5）

解码后变成与文本规则集同一套可执行规则（`ruleset::HeadlessRule`），因此不需要 `behavior`：

- 支持：`network`、`domain`（精确 / 后缀 / 正则混在一个压缩域集里）、`domain_keyword`、`domain_regex`、`source_ip_cidr`、`ip_cidr`、`port`、`port_range`、`source_port`、`source_port_range`、`process_name`、`process_path`、`process_path_regex`、`and` / `or` 逻辑组合、`invert` 取反。
- 语义：同一条规则内的多个条件是 **AND**，同一规则集里的多条规则是 **OR**——与 sing-box 一致。
- **解不了的条件拒绝整份规则集**，绝不静默丢条件：`query_type`、`package_name`、`package_name_regex`、`wifi_ssid`、`wifi_bssid`、`adguard_domain`、`network_type`、`network_is_expensive`、`network_is_constrained`、`network_interface_address`、`default_interface_address`。把「只对 Wi-Fi 生效」降级成「永远生效」，是替操作员做决定；错误的路由比加载失败难发现得多。报错会点名条件，方便你换一份导出。
- 容错与上限：zlib 解压 256 MiB 上限（防解压炸弹）；每个 count / 长度字段先与剩余字节比对再分配；逻辑嵌套上限 100 层；截断的文件是**错误**，不是「短一点但能用」。

#### `.mrs`（容器版本 1）

整个文件是**一个 zstd 帧**，容器 magic 在压缩流**内部**——所以识别这个格式只能靠帧头的 zstd magic（`28 B5 2F FD`），解压之后才是：

```text
"MRS" 0x01      4 字节：magic + 容器版本
behavior        1 字节：0 = 域集，1 = 地址集
count           i64 大端：载荷条目数
extra length    i64 大端：保留字段长度，随后跳过该字节数
payload         域集 / 地址集
```

两种载荷的布局（均以大端定长整数，不是变长整数）：

- **域集**：`0x01` + `i64`(leaves 个数) + `u64`×N + `i64`(labelBitmap 个数) + `u64`×N + `i64`(labels 字节数) + 原始字节。这就是本引擎与 sing-box 共用的那棵压缩树的另一种序列化，读取时复用同一套 rank/select 索引；
- **地址集**：`0x01` + `i64`(区间数) + 每区间 `(16 字节起, 16 字节止)`，IPv4 以映射形态存放，读取时反映射回 IPv4 再与目标比较。

域集的键用的是另一套标记：`+` 表示「该域名之下任意深度」（后缀），`*` 表示「任意一个标签」（并带回溯）。因此 `.mrs` 的域集走 `SuccinctSet::has_wildcards`，单标签通配、后缀通配与精确匹配都在同一次遍历里判定，语义与写它的工具一致（包括它的回溯栈）。

边界与拒绝：容器版本不是 1、behavior 不是 0/1、inner magic 缺失、count 为 0、计数与实际字节矛盾、zstd 解压超过 256 MiB —— 一律报错并点名，不会退化成「空规则集」。behavior 的 `classical` 在该格式里没有二进制编码，报错会直接说「behavior 2」。

> 有两点刻意的差异：`behavior` 只描述**文本**怎么读，二进制载荷自带类型，两者不一致时以载荷为准（并记一条 debug），不会像上游那样直接拒绝整份文件；`.srs` 与 `.mrs` 的域集都按文件里的编码原样求值，不互相改写。

---

## 5. 对照第三方规则集

公开的规则集大多以「一行一条（可带 `payload:` 前缀）」的形式分发。Corduit 的 rule-provider 三种 behavior 正好一一对应：

| 文件内容 | Corduit `behavior` |
|---|---|
| 域名后缀 / 关键词 / 正则（`proxy.txt`、`direct.txt`、`apple.txt`、`google.txt`、`gfw.txt` 等） | `domain` |
| CIDR 列表（`telegramcidr.txt`、`cncidr.txt`、`lancidr.txt`、`private.txt` 等） | `ip-cidr` |
| 逐行写全类型的混合文件（`DOMAIN,...`） | `classical` |

**典型配置**（rules 顺序即优先级：直连 → 广告/私网 → 需要代理的 → 兜底）：

```json
{
  "rule_providers": [
    { "name": "direct", "type": "http", "behavior": "domain",
      "url": "https://cdn.jsdelivr.net/gh/example/rulesets@release/direct.txt", "interval": 86400 },
    { "name": "private", "type": "http", "behavior": "ip-cidr",
      "url": "https://cdn.jsdelivr.net/gh/example/rulesets@release/private.txt", "interval": 86400 },
    { "name": "cncidr", "type": "http", "behavior": "ip-cidr",
      "url": "https://cdn.jsdelivr.net/gh/example/rulesets@release/cncidr.txt", "interval": 86400 },
    { "name": "proxy", "type": "http", "behavior": "domain",
      "url": "https://cdn.jsdelivr.net/gh/example/rulesets@release/proxy.txt", "interval": 86400 }
  ],
  "rules": [
    { "type": "rule-set", "payload": "direct", "outbound": "DIRECT" },
    { "type": "rule-set", "payload": "private", "outbound": "DIRECT" },
    { "type": "rule-set", "payload": "cncidr", "outbound": "DIRECT" },
    { "type": "rule-set", "payload": "proxy", "outbound": "PROXY" },
    { "type": "match", "payload": "", "outbound": "PROXY" }
  ]
}
```

两个注意点：

- 这类文件的域名条目是「后缀」语义（`example.com` 匹配自身与子域），正好是 Corduit `domain` behavior 的默认处理，**不需要改文件**；
- 想彻底复刻「国内直连、其余走代理」的顺序，就按上面这样把 `cncidr`/`private` 挂在最前面（直连）、`proxy` 挂在代理组前面（走代理）、最后 `MATCH` 兜底。规则表非空后，内置的「大陆直连」兜底自动让位。

> 上面的 URL 是占位地址。任何按这三种格式之一分发、且能通过 **HTTPS** 拉取的规则集都可以直接换进去（明文 http 会被拒绝加载）。

---

## 6. 后台 ProviderUpdater

引擎启动（`Corduit::start`）时启动一条专用线程（`provider-updater`），默认每 **60 秒** tick 一次，做三件事：

1. 代理订阅：按各自的 `interval` 刷新（`update_if_needed`）；
2. 规则集：按各自的 `interval` 刷新；
3. 健康检查：对启用了 `health_check` 的代理订阅跑延迟探测。

tick 由 `mpsc::Receiver::recv_timeout` 兼任间隔睡眠与停机信号（二者同一个等待，不空转）；`stop` 时发送停机信号，线程走完当前轮即退出。代理订阅/规则集由引擎组件持有共享 `Arc`，所以刷新直接作用于正在用的节点和规则，不用重载配置。

---

## 7. 策略组：选择、健康检查与防抖

`selector` / `url-test` / `fallback` / `load-balance` / `relay` 五种组（`engine/outbound/group.rs`）共用一套健康表，但选择策略完全不同：

| 组类型 | 每次选谁 | 关键选项 |
|---|---|---|
| `selector` | 用户手选的那个（没有则第一个成员）；健康状态只上报不干预 | — |
| `url-test` | 实测延迟最低的可用成员，带 **tolerance 防抖** | `url`（默认 `http://www.gstatic.com/generate_204`）、`interval`（秒）、`timeout`（毫秒）、`tolerance`（毫秒，默认 **50**） |
| `fallback` | 按配置顺序第一个可用成员 | `url`、`interval`、`timeout` |
| `load-balance` | 按 `strategy` 轮询或按目标地址哈希 | `strategy`：`round-robin`（默认）/ `consistent-hashing` / `sticky-sessions` |
| `relay` | 第一个成员（链式转发未实现，启动时明确告警） | — |

**为什么 `tolerance` 是默认 50 ms 而不是 0**：两条线路差 1 ms 就换，等于每一轮探测都换一次，而每次切换都要让客户端重新握手。低于容差不动，只有「明显更好」才切；要贴地跟随就把 `tolerance` 显式设成 `0`。

**`load-balance` 的三种策略**：

- `round-robin`：连接数轮转，不关心目标；
- `consistent-hashing`：按目标主机名做 FNV-1a 哈希取模，**同一目标永远落在同一个成员**——需要同一站点的多条连接走同一出口时才用（一次登录、一次流媒体的分片下载）；
- `sticky-sessions`：哈希键加上目标端口，把「同一目标 + 同一端口」的服务流钉在一起。

没有目标可哈希的调用（健康探测、API 查询）会自动退回轮转，不会把这类调用全压在第一个成员上。写错的 `strategy` 值会记一条警告并退回轮转，而不是让整组不可用。

**健康检查的细节**：

- 探测在本组内**并发**进行，并发度上限 8（`MAX_PROBE_CONCURRENCY`）：两百个节点既不会同时开两百个 socket，也不会排队等两百个超时；
- **连续 2 次**失败才把成员下线（`FAILURES_BEFORE_DEAD`），一次抖动不会踢掉节点；探测成功立刻恢复；
- 所有成员都被判定下线时，**退回完整成员列表**按策略选：全组看起来都死，更可能是探测链路出问题而不是真的全挂，此时拒绝路由等于把监测故障放大成断网；
- `selector` 不启动探测线程：用户的选择就是答案，测了也没人读。

---

## 8. 已知边界（写清楚，不掩饰）

这一节列的都是**故意没做**或**只做了一半**的东西，以及每一条的确切后果和可行替代。功能清单里没有的，就是真没有。

| 能力 | 现状 | 后果 | 替代 |
|---|---|---|---|
| sing-box `.srs` 里的客户端条件 | 识别并**拒绝整份规则集**（见 4.4） | 带 `wifi_ssid`、`package_name` 等的 `.srs` 不能加载 | 换一份不含这些条件的导出 |
| Mihomo `SUB-RULE` | **未实现**，`type` 会被当成未知规则类型拒绝 | 依赖 `sub-rules:` 段的 profile 不能直接搬 | 把子规则展开成独立的 `rule-provider` + `rule-set` 规则（语义等价，只是不共享命名空间） |
| 流量嗅探（TLS ClientHello SNI / HTTP Host 回捞） | **未实现** | 域名来源只有 DNS 侧（redir-host 应答、TUN 的 fake-IP 映射）。客户端**直接用 IP 连接**时，域名规则（含 `geosite`、`domain-*`、后缀型 `rule-set`）一律无法命中，只能落到 IP 规则或 `match` | 打开 `dns.enable` 走 fake-IP / redir-host，让域名在 DNS 阶段被记住；对 IP 字面量连接，用 `ip-cidr` / `geoip` 兜底 |
| `DOMAIN-KEYWORD` 规模 | 逐条子串扫描，O(关键词数) | 上千条关键词的集合会拖慢每条连接 | 先用精确/后缀表达，关键词只留少量；或用 `domain-regex` 合成一条（正则内部是自动机） |
| `relay` 组 | 只走第一个成员，启动时告警 | 链式转发不可用 | 用 `selector` / `url-test` 组 |
| `IP-ASN` / `IP-SUFFIX` / `UID` / `DSCP` / `REMATCH-NAME` | 未实现（Mihomo 的规则类型） | 这些 `type` 会被拒绝 | 无等价物；不要把它们写进 profile |
