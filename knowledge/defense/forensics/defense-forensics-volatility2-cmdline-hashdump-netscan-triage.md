---
id: defense-forensics-volatility2-cmdline-hashdump-netscan-triage
title: Volatility2 Windows 内存四查：cmdline 识破 Temp 伪装 svchost、printkey 取主机名、hashdump 取 NTLM、netscan 定位外联
type: scenario
domain: defense
path: defense/forensics
technique: volatility2-memory-triage-cmdline-hashdump-netscan
aliases:
- Volatility2 内存取证
- Win7SP1x64 内存镜像
- cmdline 识别伪装进程
- hashdump NTLM
- netscan 外联排查
- 内存取证四件套
tags:
- windows
- forensics
- memory
- volatility2
- cmdline
- hashdump
- netscan
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:29+08:00'
  notes: 已对照原文与全部61张图核对；未复跑PoC
---

## 一句话结论

拿到 Windows 内存镜像后，用 Volatility2 按 `Win7SP1x64` profile 依次跑 `cmdline`、`printkey`、`hashdump`、`netscan`，可以在几分钟内定位“路径/参数异常的系统进程”、提取主机名与本地账户 NTLM 哈希、并把恶意进程与外部 C2 连接对应起来，形成一条最小可用的入侵时间线。

## 原理

- **内存镜像的价值**：进程命令行、注册表 hive、SAM 账户哈希、TCP/UDP 端点都驻留在内存结构里；磁盘上的可执行文件可能已自删或只留下加载器，内存镜像仍保留运行态证据。
- **cmdline 识别伪装进程**：正常 `svchost.exe` 位于 `C:\Windows\System32`，且命令行带 `-k <服务组>`；若出现 `C:\Windows\Temp\svchost.exe` 或缺少 `-k` 参数，基本可判定为伪装/替换。`vol2 -f image --profile=Win7SP1x64 cmdline` 会列出 PID、进程名与完整命令行，适合第一轮扫异常路径。
- **printkey 取主机名**：`ControlSet001\Control\ComputerName\ComputerName` 的 `ComputerName` 值可直接读出主机名；内存中的注册表 hive 不需要挂载磁盘。主机名用于关联日志、资产清单与样本回连标识。
- **hashdump 取 NTLM**：Volatility2 的 `hashdump` 从内存中的 SAM/LSA 结构解析本地账户，输出 `user:RID:LM:NT:::`, 其中 NT 哈希可用于离线破解或撞库。`aad3b435b51404eeaad3b435b51404ee` 是空 LM，`31d6cfe0d16ae931b73c59d7e0c089c0` 是空 NT（空口令）。
- **netscan 定位外联**：`netscan` 枚举内存中的网络端点，输出本地/远端地址、状态、PID 与进程名；筛选 `ESTABLISHED` 并关注系统进程连接陌生外部 IP/端口，即可把“可疑进程”与“C2 连接”绑定。短连接木马也可能处于 `CLOSE_WAIT`/`TIME_WAIT`，不要只看了 `ESTABLISHED`。
- **为什么按这个顺序**：cmdline 先缩小进程范围；printkey/hashdump 补全主机与凭据；netscan 用外联反查 PID，三者交叉验证。相比一上来跑全量 `psscan`/`malfind`，这条路径噪声更低、速度快。

## 触发条件

- 已获取 Windows 内存镜像（`.raw`/`.dmp`，DumpIt、WinPmem、VM 快照或休眠文件）。
- 镜像内核版本与 Volatility2 profile 匹配（本例 `Win7SP1x64`；可用 `imageinfo` 自动识别）。
- 镜像完整、未加密/压缩；Volatility2 可读取内核结构与符号。
- 已知或怀疑主机失陷，需要快速定位恶意进程、账户口令与外联地址。
- 有离线哈希破解能力（字典/在线库）可把 NTLM 还原为明文。

## 利用步骤

1. **识别 profile**：`vol2 -f hellohacker.raw imageinfo`，确认 `Suggested Profile(s)`（本例 `Win7SP1x64`）。
2. **看命令行**：`vol2 -f hellohacker.raw --profile=Win7SP1x64 cmdline`；重点看系统进程名但路径不在 `System32`、缺少 `-k` 参数、从 `Temp`/`ProgramData`/用户目录启动的条目。
3. **取主机名**：`vol2 -f hellohacker.raw --profile=Win7SP1x64 printkey -K "ControlSet001\Control\ComputerName\ComputerName"`；记录 `ComputerName`。
4. **导账户哈希**：`vol2 -f hellohacker.raw --profile=Win7SP1x64 hashdump`；过滤空 LM/NT，保留有值的 NT 哈希；用字典/在线库破解，注意 NTLM 不是 MD5。
5. **查网络连接**：`vol2 -f hellohacker.raw --profile=Win7SP1x64 netscan`；筛 `ESTABLISHED`/`CLOSE_WAIT`，把可疑 IP:PORT 与 PID/进程名对应。
6. **交叉验证**：对可疑 PID 跑 `dlllist`、`malfind`、`handles`；对可疑路径在磁盘/注册表/日志中核对；把 cmdline 启动时间、连接时间与文件 mtime 串成时间线。
7. **固化证据**：记录命令、输出、镜像哈希、采集时间、主机名与账号；导出可疑进程内存段备份。

## PoC

```bash
# 1) 识别 profile
vol2 -f hellohacker.raw imageinfo

# 2) 进程命令行（找 Temp 下的 svchost / 缺 -k 参数）
vol2 -f hellohacker.raw --profile=Win7SP1x64 cmdline

# 3) 主机名
vol2 -f hellohacker.raw --profile=Win7SP1x64 \
  printkey -K "ControlSet001\Control\ComputerName\ComputerName"

# 4) 本地账户 NTLM
vol2 -f hellohacker.raw --profile=Win7SP1x64 hashdump

# 5) 网络端点与外联 PID
vol2 -f hellohacker.raw --profile=Win7SP1x64 netscan
```

输出判读示例：

```text
svchost.exe  pid 2500  C:\Windows\Temp\svchost.exe
svchost.exe  pid 2864  C:\Windows\Temp\svchost.exe
# 正常应为 C:\Windows\System32\svchost.exe -k <组名>

JustAGuestA! 1000 aad3b435b51404eeaad3b435b51404ee:3008c87294511142799dca1191e69a0f:::
# NT 哈希可离线破解；空 LM 不影响

TCPv4  125.216.248.74:11451  192.168.20.131:49158  ESTABLISHED  2864  svchost.exe
# PID 2864 即 Temp 下的伪装进程，外联地址/端口即 C2
```

## 变体与关联

- **Volatility3**：`windows.info`、`windows.cmdline`、`windows.registry.printkey`、`windows.hashdump`、`windows.netscan`；插件名与参数不同，思路一致。
- **隐藏进程**：`psscan` 与 `pslist` 对比，找 DKOM 隐藏/已退出进程；`malfind` 找 RWX 注入段并 dump。
- **注册表深度**：`printkey -K "ControlSet001\Services\<name>"` 看服务 ImagePath；`userassist`/`shellbags` 补用户行为。
- **凭据**：除 SAM 外，`lsadump`、`cachedump`、`hashdump` 可提取域缓存/明文凭据；结合 mimikatz 在线的 `lsadump::sam`。
- **关联卡片**：[[defense-forensics-memory-netscan-malfind-dump-injected-process]]（Volatility3 按外联 IP 定位注入进程并 dump）；[[ctf-forensics-windows-sam-system-offline-ntlm-mask-crack]]（离线 SAM 提取与 NTLM 爆破）。

## 检测与防御

- **基线**：记录正常 `svchost.exe` 的路径与 `-k` 参数；对 Temp/ProgramData/用户目录启动的系统进程名告警。
- **执行限制**：禁止从 `%TEMP%`、`%APPDATA%` 执行可执行文件（AppLocker/WDAC/软件限制策略）；限制服务账户权限。
- **凭据卫生**：本地管理员使用强口令、LAPS 轮换；禁用空口令账户；监控 SAM 读取与 hashdump 类行为。
- **网络检测**：对系统进程的异常外联（非 80/443、陌生 IP、长连接）告警；结合 DNS/代理日志做时间线。
- **取证规范**：先内存后磁盘；采集前记录系统时间与哈希；不要在受害机直接运行未知工具。
