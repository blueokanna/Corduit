# 规则引擎（Rules）

规则引擎解决一个问题：**一条连接该走哪个出站**。它由三部分组成：

1. **模式（mode）**：global / direct / rule，决定整体策略；
2. **规则表（rules）**：从上到下第一条命中生效，和 Clash 的规则语义一致；
3. **规则集与代理订阅（rule-provider / proxy-provider）**：把外部维护的规则和节点列表拉进来，不必全部手写。

这篇文章按「先模式、再规则、再 provider、最后 clash-rules 对照」的顺序讲清楚，每个行为都对应真实代码，不含示例性虚构。

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

> 一个容易踩的坑：`rule` 模式下，如果**规则表为空**，引擎会启用「大陆自动直连」兜底（见第 3 节）。一旦你配置了任何规则，就严格按顺序匹配，不再有内置捷径——这是刻意对齐 Clash 语义的行为。

---

## 2. 规则表（rules）

配置里的 `rules` 是数组，每条规则：`{ "type", "payload", "outbound" }`。匹配**从上到下**，第一条命中立即生效，后面的不再看。`outbound` 必须能解析到已定义出站（校验器在加载时报错，而不是运行时静默直连）。

### 2.1 规则类型与精确语义

| `type` | payload 含义 | 匹配语义（对照实现） |
|---|---|---|
| `domain` | 完整域名 | 大小写不敏感**精确**相等 |
| `domain-suffix` | 域名后缀 | 匹配**自身 + 所有子域**，且带点边界：`example.com` 命中 `example.com` 和 `a.example.com`，但**不**命中 `notexample.com` |
| `domain-keyword` | 域名子串 | 域名包含该子串即命中（大小写不敏感） |
| `domain-regex` | 正则 | 对整个域名跑正则；编译期校验，非法正则直接报配置错误 |
| `geoip` | 国家/地区码 | 目标 IP 属于该国家/地区即命中（GeoIP 库） |
| `ip-cidr` | 目标 IP 段 | 目标 IP 在 CIDR 内（支持 IPv4/IPv6） |
| `src-ip-cidr` | 源 IP 段 | 连接发起方 IP 在 CIDR 内 |
| `src-port` | 源端口 | 端口或端口范围，见下 |
| `dst-port` | 目标端口 | 同上 |
| `process-name` | 进程名 | 匹配进程的**全路径**、**文件名**或**去掉 `.exe` 的名字**（大小写不敏感） |
| `rule-set` | 规则集名 | 交给同名 `rule-provider` 判断（见第 4 节） |
| `match` | 忽略 | 永远命中，一般放最后做兜底 |

端口规则 payload 支持：单个端口 `53`、范围 `80-90`（含两端）、逗号分隔 `53,80-90,443`。

### 2.2 域名规则的 DNS 行为（重要）

`geoip` 和 `ip-cidr` 需要 IP，但代理流量常常只知道域名。引擎的处理是：

1. 先用已有 IP 试一次；
2. 只有域名时，解析出全部 IP，**逐个**拿去做 geoip/ip-cidr 匹配，任一命中即命中。

解析有明确的上限与缓存，不会因为 DNS 拖慢请求：

- 解析超时 **3 秒**（超时按「未命中」处理，继续走域名规则）；
- 结果缓存 **300 秒**、容量 4096 条；
- 解析失败的负缓存 **30 秒**，避免把坏域名反复打爆上游。

### 2.3 大陆自动直连兜底

`rule` 模式下规则表为空时，以下两种情况直接走 `direct`：

- 域名以 `.cn` 结尾（含裸 `cn`，大小写不敏感，忽略末尾点）；
- 解析出的目标 IP 是内网/保留地址，或 GeoIP 判定为 CN。

**只要规则表非空，这段兜底就被跳过**，一切由你的规则说了算。想复刻 Clash「国内直连」的效果，直接参考第 5 节把 `cncidr.txt` 等规则集挂进来即可，不必依赖兜底。

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
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
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
| `domain` | `payload:` 列表或逐行纯域名；支持 `keyword:` 前缀、`regexp:`/`regex:` 前缀、`full:` 精确前缀、`+`/`.` 前缀；默认按**后缀**处理 | clash-rules 的 `proxy.txt`、`direct.txt`、`apple.txt`、`google.txt` 等 |
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
- 也可以更省事，用 `use` 把整个 provider 的节点全部展开进组（Clash 语义）：

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

---

## 5. 对照 Loyalsoldier/clash-rules

[Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) 的 `release` 分支提供现成规则文件，它们大多是 YAML 的 `payload:` 列表。Corduit 的 rule-provider 三种 behavior 正好一一对应：

| clash-rules 文件 | 内容 | Corduit `behavior` |
|---|---|---|
| `proxy.txt` `direct.txt` `apple.txt` `google.txt` `gfw.txt` `greatfire.txt` 等 | 域名后缀/关键词/正则 | `domain` |
| `telegramcidr.txt` `cncidr.txt` `lancidr.txt` `private.txt` | CIDR | `ip-cidr` |
| 需要逐条指定类型的混合文件 | `DOMAIN,...` 等完整行 | `classical` |

**典型配置**（rules 顺序即优先级：直连 → 广告/私网 → 需要代理的 → 兜底）：

```json
{
  "rule_providers": [
    { "name": "direct", "type": "http", "behavior": "domain",
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt", "interval": 86400 },
    { "name": "private", "type": "http", "behavior": "ip-cidr",
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt", "interval": 86400 },
    { "name": "cncidr", "type": "http", "behavior": "ip-cidr",
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt", "interval": 86400 },
    { "name": "proxy", "type": "http", "behavior": "domain",
      "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt", "interval": 86400 }
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

- clash-rules 的 `direct.txt` 等是「域名后缀」语义（`example.com` 匹配自身与子域），正好是 Corduit `domain` behavior 的默认处理，**不需要改文件**；
- 想在 `rule` 模式下彻底对齐 Clash 行为，就按上面这样把 `cncidr`/`private` 挂在最前面（直连）、`proxy` 挂在代理组前面（走代理）、最后 `MATCH` 兜底。规则表非空后，内置的「大陆直连」兜底自动让位。

---

## 6. 后台 ProviderUpdater

引擎启动（`Corduit::start`）时启动一个后台任务，默认每 **60 秒** tick 一次，做三件事：

1. 代理订阅：按各自的 `interval` 刷新（`update_if_needed`）；
2. 规则集：按各自的 `interval` 刷新；
3. 健康检查：对启用了 `health_check` 的代理订阅跑延迟探测。

tick 用 `MissedTickBehavior::Skip`（追不上就跳过，不堆积）；停引擎（`stop`）时通过 oneshot 信号优雅退出。代理订阅/规则集由引擎组件持有共享 `Arc`，所以刷新直接作用于正在用的节点和规则，不用重载配置。
