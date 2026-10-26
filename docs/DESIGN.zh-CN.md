# 设计与格式

目标：在没有可用 Apple 用户态、不能接 UART、也不能依赖正常关机的情况下，拿到 XNU 早期
控制台的真实文本，并且在重启后由普通电脑只读取回。

非目标：完整启动日志、panic 即时落盘、通用块设备服务、防伪。

## 1. 数据路径

```text
console_write              (osfmk/console/serial_console.c)
console_printbuf_putc      (osfmk/console/serial_general.c)
serial_putc_crlf           (pexpert/arm/pe_kprintf.c)
        │ 每个字符
        ▼
nabu_capture_append  → 4 MiB 静态 BSS 环（无分配、无 I/O、无 console 重入）
        │ 快照 + 拷贝
        ▼
nabuLogThread（普通内核线程）
        │ GPT/FAT/token/窗口校验
        ▼
inactive 槽 payload → FUA 写 → SYNCHRONIZE CACHE → header(CRC) 写 → SYNCHRONIZE CACHE
        │
        ▼
Android/Recovery：ADB 只读 dd ESP → 主机 FAT 解析 → CRC 校验 → TXT/JSON
```

钩子注入发生在编译前，因此从第一次 `console_*` 调用起就能捕获；它不覆盖此前的
UEFI／DarwinBoot 输出，也不覆盖不经过 console 的 os_log。

## 2. RAM 环

- 容量 4 MiB，静态 BSS，页对齐；不依赖动态分配，可在早期启动使用。
- 每次追加最多 256 字节；`__atomic_compare_exchange_n` 做 try-lock，竞争失败立即放弃
  并累加 `lost`，绝不等待可能已停住的另一个 CPU。
- 快照只记录 `end/length/first/lost`，拷贝按 1 KiB 分块并在同一 try-lock 下完成；
  读取过程中若有覆盖，拷贝会因范围检查失败而被拒绝，writer 重试而不是发布半成品。
- 计数器为 64 位；超过容量后 `first` 前移，`ring_overwritten` 记录被覆盖字节数。

## 3. 卷归属证明

写入前必须证明目标区确实属于 ESP 里的那个普通文件，而不是“看起来空闲的块”：

1. GPT：主/备表 LBA、可用范围、表项数量与大小、两份 CRC32。
2. ESP 分区：类型 GUID 与分区名。
3. FAT32 BPB：块大小、簇大小、保留区、FAT 数量与大小、总簇数、根目录簇。
4. 两份 FAT 逐块比较，必须完全一致。
5. 从根目录沿目录链查找唯一的 `XNU2LOG BIN`；文件链必须连续、大小精确、无别名，
   且没有其他 FAT 引用进入该区间。
6. 首块配置结构 `NABUCFG2`：几何、容量、token、CRC，且保留区必须为零。
7. 日志窗口不得与 OS／SystemOS 启动窗口重叠。

任何一步失败都记录具名原因并停止，不退回任意分区写。token 只是分配身份，不是密钥；
CRC32 只检测损坏，不防伪造。

## 4. 双槽提交

文件布局固定为 8,400,896 字节：

| 区域 | 大小 |
| --- | --- |
| 配置块 | 4 KiB |
| 槽 0 | 4 KiB header + 4 MiB payload |
| 槽 1 | 4 KiB header + 4 MiB payload |

提交顺序：把快照写进**非当前**槽的 payload（WRITE(10) + FUA）→ SYNCHRONIZE CACHE →
写 header → 再次 SYNCHRONIZE CACHE。任一步失败，旧槽保持 CRC 有效，读回时按
`sequence` 选最新且校验通过的那个。

header 关键字段（小端）：

| 偏移 | 字段 |
| --- | --- |
| 0 | `NABULOG2` |
| 8 / 12 / 16 / 20 | version=2、header 字节、committed=1、ring 容量 |
| 24 | sequence（单调递增，非零） |
| 32 | boot ID 16 字节（由启动时刻与序列号派生） |
| 48 / 56 | 已提交流的 end、竞争丢失字节数 |
| 64 / 72 | payload first、payload 长度 |
| 76 | payload CRC32 |
| 80 | header CRC32（覆盖 0..79 与 84..4095，偏移 80 置零） |
| 88 | ring 覆盖计数（`first` 副本） |
| 96 | 分配 token 16 字节 |
| 112 | build identity 32 字节 |

`end - first == length` 且 `length == min(end, 容量)` 是结构校验的一部分，
因此“全零 header”不等于“空日志”，它只表示该槽从未提交。

## 5. 为什么不用 IOSleep 等待

writer 在 UFS 早期 bring-up 之后启动，此时定时器中断尚未被证明可用。`IOSleep` 依赖
超时唤醒；若唤醒不到，线程会停在第一次等待上，槽保持全零且没有任何后续输出。
同一项目的根路径早已因此把早期 `IOSleep` 改成主动让出。

现在的做法：

- 等待用 `clock_interval_to_deadline` 计算期限，同时设置自旋预算，循环里调用
  `thread_yield_internal(0)`；两个上界都满足就返回。
- 线程进入后立即尝试卷校验，不再先睡 1 秒。
- 读重试只由期限约束，避免“1000 次尝试在微秒内耗尽”而 50 ms 期限还没到。
- writer 在创建线程、首次提交尝试和提交失败时打印阶段、IOReturn 与 SCSI 状态。

## 6. 启动参数与 token 解析

```text
nabu-log=1 nabu-log-token=<32 位十六进制>
```

token 必须从 `PE_boot_args()` 的原始字符串按文本匹配。`PE_parse_boot_argn()` 对不以
`_` 开头的参数名会把右侧当数字解析，32 位十六进制会被截成整数，随后十六进制解码失败，
表现为“参数明明传了、writer 却拒绝”。

## 7. 失败分类

writer 的停止原因都会写进 console（因此也可能被自身捕获进下一份快照）：

| 现象 | 含义 |
| --- | --- |
| `token-gate detail=nabu-log-absent-or-not-1` | 启动项没有 `nabu-log=1` |
| `token-gate detail=nabu-log-token-absent` | 缺少 token 文本 |
| `token-gate detail=nabu-log-token-not-32-hex` | token 不是 32 位十六进制 |
| `boot-windows detail=missing-*` | 缺少 OS／SystemOS 窗口参数 |
| `boot-windows detail=esp-overlap` | 日志窗口与启动窗口重叠 |
| `volume open failed ... reason=<NBV_*>` | GPT／FAT／配置证明失败，原因具名 |
| `refusing to overwrite two non-zero invalid slots` | 两个非零但无效的旧槽，拒绝覆盖 |
| `commit failed ... phase=payload/sync/header` | 写入、同步或 header 提交失败 |
| `writer stopped reason=...` | 终态，附原因 |

心跳（若同时启用 `nabu-heartbeat=1`）输出 `NABU LOG state=... commits=... failures=...`：
state 0 未启动、1 建立/校验中、2 已进入提交循环、3 已停止。
`commits>0` 只是运行提示，最终仍以介质回读的 CRC 为准。

## 8. 主机侧读取

`nabu_esp_log.py pull`：

1. 校验设备确为 nabu，解析 ESP 的 by-name 与 GPT 几何。
2. 拒绝 ESP 正被可写挂载的情况，避免与文件系统写入竞争。
3. 只读读取 ESP 扇区，在主机端用同样的 FAT 规则定位并校验日志文件。
4. 只在两个槽都无效时拒绝生成 TXT；坏 CRC 会保留原始 BIN 和错误 JSON。

解码器独立实现同一格式（`nabu_log_volume.py`），不复用设备端代码，避免同一错误
在两端互相印证。

## 9. 边界

- 只能取回**最后一次成功提交**；之后的尾部可能丢失。
- 捕获开始之前的固件输出、以及不经过三个 console 出口的日志不在环里。
- 4 MiB 环只保留最近窗口；覆盖字节数会记录，但被覆盖内容不可恢复。
- panic 路径不做磁盘 I/O；完全停摆时不会再有新快照。
- USB CDC 是另一条通路，需要设备侧独立实现与枚举证据，不能由本仓库的 ESP 结果外推。