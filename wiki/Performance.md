# 性能与空闲开销

代理客户端绝大多数时间没有数据要传。一个空闲连接的成本因此不是细节，而是决定设备功耗与整机响应速度的主项：手机上几十个静默的 keep-alive 连接，如果每一个都在做无用功，用户体验会直接从“能省电”变成“手机烫、其他应用卡”。

本页说明 Corduit 在这方面的约束、已经修掉的缺陷类型，以及一套不需要 root 的实测方法。所有判据都以可观测的数据为准，不以“应该没问题”为准。

## 一条连接的空闲成本应当是多少

目标很明确：**静默方向必须 parked，而不是 ticking**。

- 传输层支持并发使用时（例如普通 socket、或自带内部锁的 TUN 侧连接），中继读取**不设超时**，两个方向互不阻塞，空闲连接的代价是一次阻塞的系统调用。
- 传输层不支持并发使用时（TLS、AEAD 记录层这类读写共享可变状态的实现），读取由 `RELAY_READ_POLL`（25 ms）界定，中继轮询间隔 `RELAY_POLL_YIELD`（2 ms）。这条路是回退路径，代价被显式接受并有数值上界。

在这两条路之外，不允许存在第三条“不阻塞也不让出”的路径。这是本节后面所有修复的出发点。

## 缺陷类型一：闩锁唤醒被当作普通唤醒

引擎的空闲等待建立在 `common::sync::Notify` 上。它是一个**闩锁**：`notify_*` 置位，`wait` 观察并消费。

问题在于 `wait` 的返回值只回答“是否观察到通知”，而这件事同时覆盖两种情况：

| 情况 | 是否阻塞 | 含义 |
|---|---|---|
| 闩锁唤醒（`latched`） | **没有阻塞** | 进入 `wait` 时闩锁已置位，立即返回 |
| 等待后超时 | 阻塞了 `timeout` | 时钟走完，期间没有通知 |

对条件变量式的调用者（“缓冲非空就返回，否则等待”）来说，这两者必须区分：前者如果不携带数据，直接重入就是**用户态忙等**——`Notify` 内部只有一把 `parking_lot` 互斥锁和一个原子标志，无竞争时不产生任何系统调用，于是线程满核运行而 `strace` 上什么都看不到。

修复方式是把这个区别显式化：

```rust
// common/sync.rs
pub fn wait_latched(&self, timeout: Duration) -> (bool, bool)
//                  (observed a notification, the call never blocked)
```

调用侧 `netstack::tcp::read_blocking` 只在「闩锁唤醒 **且** 接收缓冲仍为空」时退避 `NOTIFY_NO_PROGRESS_BACKOFF`（1 ms）：

- 携带数据的唤醒在上面的判断里已经取到数据并返回，**不受影响**；
- 超时路径不进入这个分支，**不受影响**；
- 只有“被叫醒却没有数据”这一种情况付出 1 ms。

## 缺陷类型二：没有数据却占用唤醒

唤醒是一种稀缺资源，只有“可读状态发生变化”才值得消耗一次。`push_recv_data` 原先在两种情况下一并置位闩锁：

```rust
if inner.recv_buffer.len() + data.len() > MAX_RECV_BUFFER { return; }  // 缓冲满：什么都没存
inner.recv_buffer.extend_from_slice(data);                            // 载荷为空：缓冲长度不变
self.inner.lock().notify.notify_waiters();                            // 却仍然通知
```

纯 ACK、零窗口探测这类无载荷段在用户态网络栈里出现得非常频繁。读者被叫醒、发现无数据可读、重入等待，而下一段又把它叫醒——这就是上面那条“不阻塞也不让出”的第三条路径，也正是需要被消除的东西。

现在两个分支都提前返回，不再置位闩锁：

```rust
if inner.recv_buffer.len() + data.len() > MAX_RECV_BUFFER { return; }
if data.is_empty() { return; }
```

`close` 同理，只在 `open → closed` 的翻转上通知一次；重复关闭不再为已经收到 EOF 的读者置位。

## 缺陷类型三：中继线程的所有权不完整

`common::stream::relay_with` 会为每个方向启动一个线程。它必须满足一条不变量：**返回之后，函数不再持有任何活动线程**。

两个曾经违反这条不变量、并因此在设备上表现为线程数单调增长的出口路径：

1. 两个 `spawn` 之间、两次 `join` 之间的 `?` 提前返回——第一个线程已经启动，却没有任何人再拥有它；
2. 某一个方向 panic 时直接向上返回——另一个方向仍 parked 在永远不会再有数据的读上。

现在的形状是：spawn 失败时先 `release()` 两侧再 `join` 已启动的线程；两次 `join` 都执行完才做错误传播；`up.join()` 报错时先释放两侧再 join 下行，避免 `join` 永久阻塞。

回归测试 `a_panicking_direction_does_not_strand_its_partner` 用「一个方向 panic、另一个方向 parked」复现原缺陷，并以“两个传输最终都被 drop”作为线程已被 join 的判据——线程若仍在运行，其 `Arc<Side>` 依旧持有传输。

## 缺陷类型四：可重试的错误码把失败变成死循环

第四种缺陷的起因不在等待，也不在“工作太贵”，而在于**给一次失败贴了一个会触发重试的错误码**。

`std::io::Write::write_all` 的约定是：`ErrorKind::Interrupted` 表示调用被信号打断、内容没有问题，因此**无限重试**：

```rust
while !buf.is_empty() {
    match self.write(buf) {
        Ok(n) => buf = &buf[n..],
        Err(e) if e.kind() == ErrorKind::Interrupted => continue,   // 无上界
        Err(e) => return Err(e),
    }
}
```

而 `protocol::ws::session_error` 把「会话已被取消」映射成了 `Interrupted`：

```rust
CourierKind::Canceled => io::ErrorKind::Interrupted,   // 语义错误
```

两者叠加的后果是一个**没有任何系统调用可以阻塞在其中的死循环**：`WebSocket::write` 失败 → `session_error` 分配一个错误字符串 → 返回 `Interrupted` → `write_all` 立即重试 → 再次失败。每轮迭代包含一次 `String` 分配、一次 `Vec` 扩容和一次释放。

实测特征与前三类明显不同，这是它容易被误判的原因：

| 观测量 | 值 | 误判方向 |
|---|---|---|
| 线程 `wchan` | 空 | 看起来像“纯用户态空转” |
| `voluntary_ctxt_switches` | **0** | 看起来像“从不阻塞” |
| 线程存活时间 | **分钟级** | 看起来像“长命线程内部死循环” |
| 线程数与 TID 创建速率 | **完全稳定、无新建** | 看起来“没有 churn，所以不是反复建连” |
| `utime` / `stime` | 各约 1 核 / 近 0 | — |

以上四条同时成立时，正确的结论是：**线程确实在循环，而且循环体是纯计算式的重试**，不是等待用错、不是反复建连。用 `perf` 抓调用图即可一眼确认——分配器占样本三分之二，且调用链终点落在 `write_all` 之下：

```text
copy_direction
  └─ Side::shutdown            ← 或 write_all 路径
       └─ VmessStream as SyncStream::shutdown
            └─ std::io::Write::write_all
                 └─ WebSocket::write
                      └─ ws::session_error
                           └─ Error as fmt::Display::fmt
                                └─ core::fmt::write
                                     └─ String::write_str
                                          └─ RawVec::reserve → finish_grow → realloc
```

修复是两件事，缺一不可：

1. **修正错误码语义**：取消映射到 `ConnectionAborted`（终态），而不是 `Interrupted`（可重试）。这切断了 `write_all` 的无限重试。
2. **错误路径不分配**：热点类别使用静态消息，只有真正承载可操作信息的类别才格式化底层文本。

回归测试 `a_cancelled_session_is_not_retried_by_write_all` 把**映射与重试行为作为同一个不变量**断言，并用「64 次尝试后才返回」这一事实钉住原因，避免后人把映射改回 `Interrupted`。

### 从这条链得到的通用规则

- **错误码是契约，不是描述。** `Interrupted` 在 `std` 里意味着“重试我”；任何非信号原因（取消、对端关闭、状态不合法）都不该用它。选错一个 `ErrorKind` 的代价可能是一个满核死循环。
- **错误路径也在热路径上。** 只要一段代码可能被高频执行，它就不能分配；失败循环里的 `format!`、`to_string()`、日志拼接都会以百万次/秒的量级出现。
- **判定分配问题要看分配器火焰，不要看业务函数。** 当 `malloc`/`free`/`realloc` 占据样本前列时，问题通常不在算得多的函数里，而在每次调用都分配的那个“无害”的辅助函数里。
- **线程数稳定不等于没有循环。** 稳态线程数只能排除“反复建连”，无法排除“长命线程内部死循环”；后者的判据是 `voluntary_ctxt_switches` 与线程 `TIME+`。

## 空转的可观测特征

判断是否存在空转，不要看瞬时 `%CPU`，看这三个量的组合：

| 观测量 | 空转时 | 正常空闲时 |
|---|---|---|
| 进程 `utime` 增量 | 高（可达每线程一个核） | 接近 0 |
| 进程 `stime` 增量 | 接近 0（无系统调用可阻塞） | 与轮询频率成正比且极小 |
| `rchar` / `wchar` 增量 | 与 CPU 增长不成比例（近乎不增长） | 与业务流量一致 |
| 运行中线程的 `wchan` | **空**（未阻塞在任何内核路径） | 内核睡眠符号 |

一个实际测量到的样例（手机，隧道开启、应用在前台，15 s 窗口）：

```text
user = 104.94 s   sys = 0.74 s        => 7.00 核 / 0.05 核
rchar +31 KB      wchar +833 KB       => 约 57 KB/s
线程状态: 113 R / 334 S
wchan 分布: 117 线程 wchan=0, 49 wait_woken, 6 hrtimer_nanosleep, 4 futex_wait
线程名: corduit-relay-u 136, corduit-relay-d 41
```

「7 个核的用户态时间 + 57 KB/s 的 I/O + 117 个线程停留在用户态」三者同时成立，就已经排除了“真流量”和“锁竞争”两种解释：前者会让 I/O 与 CPU 同比例增长，后者会让线程进入内核等待并抬高 `stime`。

## 实测方法（不需要 root）

```bash
P=$(pidof <your.app.id>)

# 1) 进程级用户态/内核态时间，两次采样求差（单位：100 Hz 计时脉冲）
awk '{print $14, $15}' /proc/$P/stat; sleep 15; awk '{print $14, $15}' /proc/$P/stat

# 2) I/O 增量：与 (1) 对照，CPU 增长而字节数不增长即为空转
cat /proc/$P/io

# 3) 线程状态直方图
for t in /proc/$P/task/*; do awk '{print $3}' $t/stat; done | sort | uniq -c

# 4) 线程级定位：wchan 为空表示停留在用户态
for t in /proc/$P/task/*; do echo "$(cat $t/comm) $(cat $t/wchan)"; done | sort | uniq -c | sort -rn
```

系统级视角用 Pressure Stall Information（内核 5.10+ 提供）：

```bash
cat /proc/pressure/cpu      # some avg10 持续偏高 => 有进程在抢 CPU
grep procs_running /proc/stat   # 就绪队列长度，用户感受到的“卡”
```

在同一台设备上，上面那个样例对应的系统级读数为 `PSI cpu some avg10 = 78.58%`、`procs_running = 118`；进程退出后分别为 `3.85%` 与 `1`。**系统级读数与该进程的相关性，是定位“到底谁在吃性能”最快的路径**，不需要采样器或火焰图。

## 修改自旋问题时不要做的事

- **不要用 `std::thread::yield_now()` 代替 `sleep`。** `sched_yield` 不是睡眠：它把线程放回就绪队列，循环依旧满核。仓库内所有重试路径统一使用真实的短睡眠。
- **不要在持锁期间做有界阻塞读取。** 它会把反方向挡在锁外，制造不必要的唤醒风暴；序列化路径的读取上界（25 ms）本身已经是一个需要权衡的数值，不应叠加。
- **不要给“由有界读超时或 `poll()` 保护”的循环添加无条件 sleep。** 那些循环本来就是 20–50 Hz 的轮询，加睡眠只会增加延迟而不会降低任何 CPU。
- **不要把 `%CPU` 的瞬时读数当作证据。** 它受采样窗口、CPU 频率调节和调度影响极大；增量式的 `utime`/`stime` 组合才是可复现的判据。
