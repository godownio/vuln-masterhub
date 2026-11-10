---
id: defense-forensics-memprocfs-mount-findevil-timeline
title: MemProcFS 挂载内存镜像为虚拟文件系统：pid/sys 浏览、forensic 时间线与 findevil 异常定位
type: scenario
domain: defense
path: defense/forensics
technique: memprocfs-mount-findevil-timeline
aliases:
- MemProcFS 取证
- 内存镜像挂载为文件系统
- Dokany 内存分析
- findevil 异常目录
- MemProcFS-Analyzer
tags:
- windows
- forensics
- memory
- memprocfs
- findevil
- timeline
- incident-response
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T16:56:49+08:00'
  notes: 已对照原文与截图核对：MemProcFS 5.9.12、-forensic 1、Mount M:\、Windows 10.0.19041、M:\forensic 与 findevil 的 PE_INJECT/PEB_BAD_LDR/SYSTEM_IMPERSONATION/PROC_DEBUG/DRIVER_PATH 均有截图；MemProcFS 本身未实测，findevil 中 3520 的 PEB_BAD_LDR 行为截图截断处推得。原文无受影响版本。
---

## 一句话结论

用 MemProcFS（需先装 Dokany 2 用户态文件系统驱动）以 `-forensic 1` 把 Windows 内存镜像挂载成虚拟盘（如 `M:\`），即可像浏览普通文件一样查看每个进程的 `pid\<PID>` 目录与 `sys` 系统信息；`forensic` 目录给出 NTFS/网络/网页/进程等时间线，`findevil` 目录直接汇总 PE_INJECT 注入模块、PEB_BAD_LDR、SYSTEM_IMPERSONATION 线程、PROC_DEBUG、DRIVER_PATH 等异常，适合快速把内存里的可疑进程与注入定位出来。

## 原理

- MemProcFS 自行解析镜像里的内核结构与页表，在用户态重建进程/模块/句柄/网络等对象，再通过 Dokany 文件系统驱动把结果映射成一个只读虚拟盘；打开资源管理器就能浏览，不需要逐条记忆 Volatility 插件参数。
- `pid` 目录按进程 PID 组织，每个进程目录里能看到内存、模块列表、句柄、环境变量等；`sys` 目录汇总系统级信息（网络、用户、操作系统版本等）；`name` 按进程名索引，`registry` 暴露注册表视图。
- `-forensic 1` 在挂载时额外生成取证时间线文件，把 NTFS、网络、网页、进程等事件按时间排序，便于和磁盘/日志证据拼接。
- `findevil` 是内置异常聚合视图：它把注入模块（PE_INJECT，显示模块基址与模块名/描述）、PEB 中异常的模块加载链（PEB_BAD_LDR）、线程令牌冒充（SYSTEM_IMPERSONATION）、调试端口（PROC_DEBUG）、驱动路径/驱动对象（DRIVER_PATH）等按进程列出。示例镜像中 `svchost.exe`（PID 3520）被标出多个 PE_INJECT 模块（如 `0x180000.dll`、`server.dll`、`extension.dll`）与 PEB_BAD_LDR，正好对应 Volatility malfind 在同一 PID 看到的 RWX+MZ 注入段。
- 为什么成立：注入模块通常没有磁盘文件或磁盘文件与内存不一致，模块链又可能被手工构造；findevil 把“模块基址不在正常加载链、PEB 异常、线程冒充”等信号聚合，比人工逐进程跑插件更快暴露异常，但仍需人工排除 JIT、.NET、安全软件注入等误报。

## 触发条件

- 已获取 Windows 内存镜像（raw/dmp），版本在 MemProcFS 支持范围内（示例为 Windows 10.0.19041）。
- 主机已安装 Dokany 2 文件系统驱动，分析进程有管理员权限（挂载盘符）。
- 需要快速浏览进程/系统对象、生成内存侧时间线，或先做异常筛选再决定深挖哪些 PID。

## 利用步骤

1. 安装 Dokany 2 并确认驱动工作正常；记录 MemProcFS 版本。
2. 执行 `MemProcFS.exe -device image.raw -forensic 1`，记录挂载点（示例 `M:\`）、识别出的系统版本与 forensic 模式初始化结果。
3. 在 `M:\pid` 按进程名/PID 浏览目标进程目录；在 `M:\sys` 查看网络、用户、OS 信息；必要时看 `M:\name`、`M:\registry`。
4. 打开 `M:\forensic` 下的时间线文件，按时间筛选可疑进程创建、网络连接与文件事件。
5. 打开 `M:\forensic\findevil`，逐条核对 PE_INJECT、PEB_BAD_LDR、SYSTEM_IMPERSONATION、PROC_DEBUG、DRIVER_PATH；对命中的 PID 回到 `M:\pid\<PID>` 导出模块/内存段，用 strings、IDA/Ghidra 分析。
6. 用 Volatility3 的 `windows.netscan`、`windows.malfind`、`windows.cmdline`、`windows.registry.*` 对同一镜像交叉验证，避免单一工具的误报。
7. 固化挂载参数、版本、导出文件与哈希；镜像属敏感数据，加密保管。

## PoC

```bash
# 前置：安装 Dokany 2
MemProcFS.exe -device image.raw -forensic 1
# 初始化输出示例：Mount Point: M:\  Operating System: Windows 10.0.19041 (X64)
```

```text
M:\
├─ pid\<PID>\         # 进程视图（内存、模块、句柄、环境变量等）
├─ sys\               # 网络、用户、系统信息
├─ registry\          # 注册表视图
├─ forensic\          # NTFS/网络/网页/进程时间线
│   └─ findevil\      # PE_INJECT / PEB_BAD_LDR / SYSTEM_IMPERSONATION 等异常汇总
└─ memory.dmp / memory.pmem
```

`findevil` 命中的典型行（示例，已脱敏）：

```text
PID   ProcessName  Type                  Address       Description
3520  svchost.exe  PE_INJECT             0x180000      Module:[0x180000.dll]
3520  svchost.exe  PE_INJECT             0x1c0000      Module:[server.dll]
3520  svchost.exe  PEB_BAD_LDR           0x...         ...
  8   svchost.exe  THREAD                0x...         TID:1888 SYSTEM_IMPERSONATION
```

## 变体与关联

- MemProcFS-Analyzer 对 MemProcFS 的取证输出做自动化汇总，适合批量/标准化流程。
- 图形化前端（如基于 MemProcFS+Volatility 的可视化工具）把同一份挂载结果做成表格视图，底层数据源一致。
- 关联：[[defense-forensics-memory-netscan-malfind-dump-injected-process]]（Volatility3 按外联 IP 定位 PID 后 malfind dump，可与 findevil 的 PE_INJECT 互相印证）、[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]（Volatility2 快速排查流程）、[[defense-forensics-cobaltstrike-memory-beacon-session-key-collision]]（内存中的 C2 会话密钥取证）。

## 检测与防御

- 取证侧：挂载前校验镜像哈希；`findevil` 只作线索聚合，PE_INJECT/PEB_BAD_LDR 会命中 JIT、.NET、部分安全软件，需结合模块签名、路径与行为确认。
- 防守侧：启用驱动签名强制与 HVCI，限制未签名驱动加载；监控跨进程写入/远程线程创建；对系统进程出现外部连接与无文件模块的组合告警。
- 内存镜像与挂载产物含凭据、令牌等敏感数据，访问与留存需授权、加密并限制范围。
