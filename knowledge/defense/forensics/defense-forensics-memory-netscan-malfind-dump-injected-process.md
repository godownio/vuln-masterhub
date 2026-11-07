---
id: defense-forensics-memory-netscan-malfind-dump-injected-process
title: 内存镜像按外联 IP 定位注入进程：Volatility3 netscan → malfind dump → IDA 还原
type: scenario
domain: defense
path: defense/forensics
technique: memory-netscan-malfind-injected-process-dump
aliases:
- Volatility3 内存取证
- windows.netscan 定位进程
- windows.malfind dump
- DumpIt 内存镜像
- hiberfil.sys 取证
- 系统进程外联排查
- 注入进程内存 dump
tags:
- windows
- forensics
- memory
- volatility3
- malfind
- netscan
- dumpit
- process-injection
- incident-response
- silverfox
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:52:19+08:00'
  notes: 已对照原文与截图象核对：DumpIt、hiberfil 5.47GB/pagefile 17GB、windows.info 15.19041、netscan 定位 PID4552 sihost.exe→192.238.192.11:22、malfind --pid 4552 --dump、dump 字符串含 DisplaySessionContainers.log/键盘标记/安全软件名均一致；未验证点：未复跑 Volatility3。
---

## 一句话结论

对常驻内存、落地文件可能自删或难以定位的木马，先拍完整内存镜像；用 Volatility3 `windows.netscan` 按恶意 IP 找到 ESTABLISHED 连接及所属 PID，再用 `windows.malfind --pid <PID> --dump` 导出 `PAGE_EXECUTE_READWRITE` 的可疑 VAD，最后在 IDA/strings 中还原注入模块的 C2、日志路径与配置。

## 原理

- **为什么先拍内存**：银狐这类木马常驻内存，落地文件可能已自删除，或只以白进程注入形式存在；磁盘上可能只剩加载器和加密载荷。内存镜像保存了进程虚拟内存、模块、句柄、网络连接与配置字符串，是恢复运行态证据的首选。
- **内存来源**：`DumpIt` 可直接生成 `.dmp`/`.raw` 全内存镜像；`hiberfil.sys` 是系统休眠时保存的完整内存快照（本例 5.47GB），`pagefile.sys` 是虚拟内存页文件（本例 17GB），页面以 4KB 为单位乱序存放，可能只有恶意代码的片段，需要按页拼接，不能当作完整连续镜像。
- **windows.info 定版本与符号**：Volatility3 先读内核 `KdVersionBlock`，输出 `NT BuildLab`/`Major/Minor` 等；本例 `15.19041` 对应 Windows 10 Version 2004（20H1）。版本决定内核结构与符号，需安装匹配的 PDB 符号，否则很多插件无法解析。
- **windows.netscan 找连接**：该插件从内存中的网络结构枚举 TCP/UDP 端点、状态、PID 与进程名，速度比逐个进程分析快。重点看 `ESTABLISHED`，同时保留 `CLOSE_WAIT`/`TIME_WAIT`，因为木马可能使用短连接。系统进程（`sihost.exe`、`svchost.exe`、`notepad.exe` 等）连接外部陌生 IP 是高价值线索；本例 `PID 4552 sihost.exe` 连接 `192.238.192.11:22`。
- **windows.malfind 找注入**：`malfind` 枚举进程 VAD，筛选 `PAGE_EXECUTE_READWRITE` 且无文件映射（或映射与磁盘文件不一致）的内存区，这些通常是反射加载的 PE、shellcode 或注入模块。`--dump` 把命中区域导出为 `pid.<PID>.vad.<起始>-<结束>.dmp`，可直接拖入 IDA。
- **为什么不用 pstree/psscan 起步**：`windows.pstree`、`windows.psscan` 输出进程树和隐藏进程，信息量大、噪声高，适合在已有目标后交叉验证；先用 netscan 从“异常外联”反查 PID 更高效。`windows.cmdline` 可补全每个进程的命令行，识别 `cmd /c *.bat`、`powershell -enc` 等。
- **dump 段分析**：导出的 VAD 可能是位置无关 shellcode 或 PEM 头不完整的反射模块。在 IDA 中按 16 位/32 位/64 位反汇编，结合 `strings` 找 C2 IP/域名、日志路径、互斥体、配置文件名；本例字符串中出现 `C:\ProgramData\<GUID>DisplaySessionContainers.log`、`[enter]`/`[lshift]` 等键盘标记、`192.238.192.11`、`QQPCtray.exe`/`HipsDaemon.exe` 等安全软件名。
- **与磁盘/实时证据交叉**：内存中的日志路径、GUID 目录、`config.ini` 需要在磁盘上核对；`Process Hacker` 的 TCP/IP 页、`Procmon` 的进程/线程退出与 DLL 加载事件可补足注入时间线。内存镜像只能证明“当时在内存里”，落盘与持久化仍需磁盘取证。

## 触发条件

- 能获取目标主机内存：物理机可用 `DumpIt`/WinPmem，虚拟机可挂起后取快照，离线可用 `hiberfil.sys`/`pagefile.sys`。
- 有与目标内核版本匹配的 Volatility3 符号（联网或离线 symbols 包）；镜像完整、未被加密/压缩。
- 已知或怀疑恶意 IP/域名，或至少有一批可疑外联；否则需要先做全量 netscan 再人工筛选。
- 有 IDA/Ghidra/strings 等分析工具，能把 dump 段还原为可读代码或字符串。
- 取证前尽量挂起被注入进程，避免其检测到分析行为后自删/转移；但挂起会改变运行态，需先记录进程列表与连接。

## 利用步骤

1. **留证与挂起**：记录 `tasklist /v`、`netstat -ano`、`Get-CimInstance Win32_Process` 的命令行；对被注入进程可先挂起（如 Process Hacker Suspend），防止其自毁；不要急着重启。
2. **拍内存**：运行 `DumpIt` 生成 `.dmp`/`.raw`，记录文件哈希、采集时间、主机名与工具版本；若无法在线采集，保留 `hiberfil.sys`、`pagefile.sys` 并记录其原始路径/大小。
3. **识别内核版本**：`python vol.py -f <image> windows.info`，确认 `NT BuildLab`/`Major/Minor` 与符号版本；本例 19041。
4. **按外联定位进程**：`windows.netscan` 输出中筛选 `ESTABLISHED`/`CLOSE_WAIT`/`TIME_WAIT`，重点看系统进程连接外部 IP 的记录；记录 PID、进程名、五元组与时间。本例定位到 `sihost.exe` PID 4552 → `192.238.192.11:22`。
5. **导出注入内存**：`windows.malfind --pid 4552 --dump`，记录命中的 VAD 起止、保护属性（`PAGE_EXECUTE_READWRITE`）与导出文件名；对多个可疑 PID 分别 dump。
6. **分析 dump**：用 IDA 按架构反汇编，`strings` 提取 IP/域名/路径/配置键；结合导入表/字符串判断模块能力（网络、键盘记录、进程操作、注册表）。本例字符串还原出日志路径、键盘标记、C2 IP 与安全软件检测列表。
7. **交叉验证**：`windows.cmdline` 查可疑命令行，`windows.pstree`/`psscan` 核对父子关系与隐藏进程；在磁盘上核对 `C:\ProgramData\<GUID>\`、`config.ini`、`DisplaySessionContainers.log` 与隐藏属性；用 Process Hacker/Procmon 复核实时行为。
8. **固化证据**：对镜像与导出段计算哈希，记录 Volatility 命令与符号版本，写入时间线；镜像按敏感数据保管。

## PoC

以下为取证命令骨架（只读分析，不执行样本）：

```bash
python vol.py -f image.dmp windows.info
python vol.py -f image.dmp windows.netscan
python vol.py -f image.dmp windows.malfind --pid 4552 --dump
python vol.py -f image.dmp windows.cmdline
python vol.py -f image.dmp windows.pstree
python vol.py -f image.dmp windows.psscan
```

```text
strings pid.4552.vad.0x...-0x....dmp | grep -E "https?://|[0-9]{1,3}(\.[0-9]{1,3}){3}|ProgramData|\.log"
```

## 变体与关联

- 变体：用 `hiberfil.sys` 直接分析（Volatility 支持 hibernation 转换）；用 `pagefile.sys` 按 4KB 页扫描 PE/shellcode 特征；用 WinPmem/LiME（Linux）采集；用 MemProcFS 挂载镜像后按文件/进程浏览。
- 变体：先做 `windows.malfind` 全进程扫描再按 PID 回溯 netscan；对反射 DLL 用 `pe_unmapper`/`malduck` 重建 PE；对纯 shellcode 用 `scdbg`/speakeasy 模拟。
- 关联：[[defense-detection-linux-process-injection]]（Linux 侧同类注入检测与 LiME/Volatility3）、[[code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump]]（dump 后 PE 修复）、[[pentest-c2-silverfox-inno-dlclr-vmprotect-png-zlib-chain]]（本样本加载链）、[[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]（取证后的清除顺序）。

## 检测与防御

- **采集侧**：在主机上预置内存采集能力与符号包；事件响应时先拍内存再杀进程/重启；对 `hiberfil.sys`、`pagefile.sys` 做保全，避免被清理工具删除。
- **分析侧**：优先筛选系统进程的外部 ESTABLISHED 连接；对 `PAGE_EXECUTE_READWRITE` 且无文件映射的 VAD 告警；核对进程命令行、父进程、启动时间是否自洽；对 dump 段做字符串与导入表画像。
- **检测规则**：`sihost.exe`、`uhssvc.exe`、`taskhostw.exe` 等系统进程出现外部 22/443/自定义端口连接；系统进程加载无签名/路径异常的模块；进程内存出现 RWX 区域；`cmd.exe /c *.bat` 与 `sc start` 高频组合。
- **防御**：启用 Credential Guard/受保护进程、限制 `SeDebugPrivilege`、监控跨进程写入与线程创建；对系统进程做完整性保护；封禁已知 C2；定期演练内存取证流程，确保符号与工具可用。
- **注意事项**：内存镜像含密码、令牌、剪贴板等敏感数据，传输与留存需加密并限制访问；`pagefile.sys` 页乱序，不能按文件偏移直接当连续内存；`malfind` 有误报（JIT、.NET、部分安全软件），需结合签名、路径与行为确认。
