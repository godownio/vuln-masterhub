---
id: defense-forensics-volatility3-secondary-dump-process-memmap-dll-dumpfiles
title: Volatility3 二次转储：导出进程内存、地址映射、DLL、缓存文件与注入段
type: scenario
domain: defense
path: defense/forensics
technique: volatility3-secondary-dump-process-memmap-dll-dumpfiles
tags:
- windows
- forensics
- memory
- volatility3
- dump
- dll
- malfind
- incident-response
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T16:56:51+08:00'
  notes: 已对照原文与截图核对转储命令族与 PID 3520 示例；对照 volatility3 2.7.0 官方包源码，将 dumpfiles 参数 --physical 更正为 --physaddr（--pid/--virtaddr/--physaddr 均存在），pslist/memmap/dlllist/malfind 的 --pid+--dump 均确认存在；命令未实际执行。原文无受影响版本。
url: /docs/defense/forensics/defense-forensics-volatility3-secondary-dump-process-memmap-dll-dumpfiles/
draft: false
kb_aliases:
- Volatility3 进程内存转储
- windows.pslist --dump
- windows.memmap --dump
- windows.dlllist --dump
- windows.dumpfiles 缓存文件
- malfind dump 注入段
---

## 一句话结论

在 Volatility3 中用 `-o <输出目录>` 配合插件的 `--dump`，可以把数 GB 的整机内存镜像“二次转储”成便于离线分析的小文件：`windows.pslist --pid <PID> --dump` 导出进程内存、`windows.memmap --pid <PID> --dump` 导出完整地址映射、`windows.dlllist --pid <PID> --dump` 导出进程加载的 DLL、`windows.malfind --pid <PID> --dump` 导出 RWX 注入段（文件名含 VAD 起止地址）；`windows.dumpfiles` 则按进程/虚拟地址还原内存中的缓存文件（该插件没有 `--dump` 参数）。

## 原理

- 整机镜像体积大、噪声多，直接 `strings` 或反汇编等于大海捞针；二次转储按插件已知的结构信息把目标进程/模块的字节范围切成独立文件，保留原始内存布局，后续可以放进 IDA/Ghidra/strings 反复分析而不必每次重新解析大镜像。
- `windows.pslist --dump`：按进程页表把该进程的用户态地址空间整体读出，得到一个“进程内存快照”，适合分析单体恶意进程、提取堆里的配置与 C2。
- `windows.memmap --dump`：导出该进程完整的虚拟地址映射（各 VAD 对应的页面），能按地址定位特定模块、栈或堆区域；与 pslist 的整体转储互为补充。
- `windows.dlllist --dump`：从内存中按模块基址与大小转储已加载 DLL；对内存加载、侧加载、已从磁盘删除的 DLL 尤其关键——磁盘上的同名文件可能已被替换或不存在，内存副本才是运行态证据。
- `windows.malfind --dump`：专门转储 `PAGE_EXECUTE_READWRITE` 且无文件映射的可疑 VAD，产物形如 `pid.<PID>.vad.<起始>-<结束>.dmp`。若段首是 `MZ` 说明是反射加载/注入的 PE，可直接做 PE 修复后反汇编；纯 shellcode 段则按架构反汇编。示例中 `svchost.exe`（PID 3520）的 RWX 段以 `MZ` 开头、尾部是 `0f 05`（syscall）与函数序言，是典型的注入模块形态。
- `windows.dumpfiles`：根据进程句柄/文件对象中的缓存信息，把内存中仍驻留的文件内容按虚拟或物理地址还原出来，用于恢复被删除、从未落盘或已加密的临时文件；参数形态是 `--pid`/`--virtaddr`/`--physaddr`，没有 `--dump`。
- 为什么要“二次”：转储产物可哈希、可归档、可分发给不同分析人员，避免反复加载大镜像与污染原始证据。

## 触发条件

- 已有 Windows 内存镜像，Volatility3 与匹配内核符号可正常解析。
- 已通过 pslist/psscan/netscan/malfind 锁定可疑 PID 或地址范围。
- 需要离线分析进程内存中的模块/配置/C2，或恢复内存缓存文件。

## 利用步骤

1. `windows.info` 确认版本与符号；`windows.pslist`/`windows.psscan` 确定目标 PID。
2. 建输出目录，所有命令加 `-o out`，避免产物散落。
3. 按目标选择转储方式：整体进程内存用 pslist `--dump`；按地址定位用 memmap `--dump`；模块级对比用 dlllist `--dump`；注入检测用 malfind `--dump`；缓存文件用 `windows.dumpfiles`。
4. 记录每个产物的文件名、大小与哈希，核对 VAD 起止地址是否与 malfind/vadinfo 输出一致。
5. 对 DLL 转储计算哈希并与磁盘同名文件对比，识别内存 patch、侧加载与代理 DLL；对 MZ 段做 PE 头修复后进 IDA。
6. 对 dumpfiles 产物按文件头识别类型（PE、脚本、配置、日志），再决定后续分析。
7. 原始镜像与转储产物按敏感数据加密保管，命令与工具版本写入取证记录。

## PoC

```bash
# 目标进程 PID 3520
python vol.py -o out -f image.raw windows.pslist  --pid 3520 --dump
python vol.py -o out -f image.raw windows.memmap  --pid 3520 --dump
python vol.py -o out -f image.raw windows.dlllist --pid 3520 --dump
python vol.py -o out -f image.raw windows.malfind --pid 3520 --dump
python vol.py -o out -f image.raw windows.dumpfiles --pid 3520

# 检查注入段
file out/pid.3520.vad.*.dmp
xxd out/pid.3520.vad.*.dmp | head
```

说明：不同 Volatility3 版本插件名/参数可能略有差异（缓存文件插件在插件清单中写作 `windows.dumpfiles.DumpFiles`，部分写法省略复数），以 `vol.py <plugin> -h` 为准。

## 变体与关联

- Volatility2 对应 `procdump`（进程内存）、`memdump`（地址空间）、`dlldump`（DLL）、`dumpfiles`（缓存文件）、`malfind --dump-dir`；命令名不同、思路一致。
- 纯 shellcode 段可用 scdbg/speakeasy 模拟；反射 DLL 可用 pe_unmapper/malduck 重建导入表后再分析。
- 关联：[[defense-forensics-memory-netscan-malfind-dump-injected-process]]（netscan 定位 PID 后 malfind dump 并用 IDA 还原 C2）、[[code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve]]（转储后的 PE 雕刻与重建）、[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]（Volatility2 快速排查）。

## 检测与防御

- 取证侧：先锁定 PID 再转储，避免无差别 dump 造成产物爆炸；对产物做哈希与来源记录；注意 `windows.dumpfiles` 依赖句柄/文件对象信息，进程已退出时可能无法还原。
- 防守侧：限制 `SeDebugPrivilege` 与跨进程内存读取，启用 Credential Guard/受保护进程；监控大规模进程内存读取与 minidump 写入行为。
- 内存镜像与转储段包含凭据、密钥等敏感数据，传输与留存必须加密并限制访问。
