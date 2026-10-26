# nabu XNU console log readback

在小米平板 5（nabu，SM8150）上抓取原始 XNU 控制台文字，持久化到 ESP 中预分配的普通文件，
再在 Android／Recovery 里通过 ADB **只读**导出、校验并解码为文本。

这条链路不依赖可用的 iPadOS 用户态，也不在 panic 路径做磁盘 I/O。

## 状态

2026-10-26 在一台实测设备上完成端到端验证：内核启动后写入两个 CRC 有效槽，
重启进入 Recovery 后只读取得 15,303 字节真实 XNU 文本，`build_id` 与所安装候选的
logging 源标识一致。验证的是**本仓库这套格式与读取路径**；不同设备、不同内核仍需各自绑定证据。

## 目录

| 路径 | 作用 |
| --- | --- |
| `mac_build/unixnu-source-ci/nabu-device/ufs/NabuLogCore.h` | 4 MiB 静态 RAM 环，try-lock 追加与快照 |
| `.../ufs/NabuLogFormat.h` | 介质格式常量、CRC、槽与配置校验 |
| `.../ufs/NabuLogVolume.h` | GPT／FAT 归属证明与只读打开 |
| `.../ufs/NabuLogUfs.h` | 普通内核线程 writer、双槽提交 |
| `.../scripts/nabu_capture_source.py` | 编译前给 console 源注入捕获钩子 |
| `tools/nabu_log_volume.py` | 主机侧独立实现的格式与分配校验 |
| `tools/nabu_esp_log.py` | ADB 只读提取／离线镜像解码 |
| `tools/nabu_log_export.py` | 容器解码与 BIN/TXT/JSON 输出 |
| `tools/nabu_cdc_log.py` | 原始 CDC 串口单向接收（可选，另一条通路） |
| `docs/DESIGN.zh-CN.md` | 机制、格式、失败分类与边界 |

各文件保持与验证时相同的相对路径，主机测试无需改动。

## 读取

设备先启动一个包含 writer 的候选并产生提交，然后进入 Android 或 Recovery：

```powershell
py -3 -B tools/nabu_esp_log.py pull --root --serial <序列号>
```

工具自动解析 ESP、GPT 与 FAT，只读 `dd` 已分配的日志文件，不扫描其他裸块。
没有唯一在线设备时用 `--serial`；Recovery 的 adbd 已是 root 时 `--root` 自动降级为普通读取，
否则复用它已有的 `su` 授权。

输出目录包含：

- `boot-log.bin`：原始容器；
- `boot-log.txt`：仅在 CRC 与结构校验通过后生成；
- `boot-log-info.json`：槽、序列号、`boot_id`、`build_id`、丢失计数与校验结果。

验收看 `result = text_exported_crc_verified`、`stored_checksum_valid = true`，
并核对本次启动的 `boot_id` 与候选的 `build_id`。

离线已有完整 ESP 镜像时：

```powershell
py -3 -B tools/nabu_esp_log.py decode-esp <esp.img> --out <新目录>
```

## 抓取侧前提

- 内核需由 `NabuLogCore.h`／`NabuLogUfs.h` 编入，并用 `nabu_capture_source.py`
  给 `console_write`、`console_printbuf_putc`、`serial_putc_crlf` 挂钩子。
- 启动参数 `nabu-log=1` 与 16 字节 token（32 位十六进制文本）。
- ESP 内必须已有预分配、连续、无交叉引用的日志文件，且配置块里的 token 与启动参数一致。
- writer 由 UFS 根路径创建；任何一项校验失败都停止写入，不退回任意分区。

镜像准备与刷写工具是设备相关的部署步骤，不在本仓库发布。

## 测试

```powershell
py -3 -B -m unittest tools.test_nabu_log_writer tools.test_nabu_cdc_log -v
```

writer 测试直接编译真实的 `NabuLog*.h`，用脚本化硬件覆盖正常提交、并发竞争、
门禁拒绝，以及 payload／sync／header 三个断点的旧槽保留。

## 边界

只保存**最后一次成功提交**的 console 快照：未提交尾部、钩子之前的 UEFI 输出、
不经过 console 的 os_log 与用户态文件日志都不在其中。CRC32 用于检测损坏，不是防伪。
`nabu_cdc_log.py` 面向已枚举的 CDC 端口，不代表 USB 通路已在 nabu 上跑通。

## 许可

`mac_build/` 下的源码来自 UniXNU 项目，BSD-2-Clause-Patent，见
`mac_build/unixnu-source-ci/nabu-device/LICENSE`。`tools/` 为同一项目的主机侧实现。