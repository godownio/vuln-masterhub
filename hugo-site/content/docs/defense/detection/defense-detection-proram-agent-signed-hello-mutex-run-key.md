---
id: defense-detection-proram-agent-signed-hello-mutex-run-key
title: ProRAM C2 Agent 样本行为与检测：Ed25519 signed hello、公钥指纹互斥量与 HKCU Run 持久化
type: scenario
domain: defense
path: defense/detection
technique: proram-agent-behavior-detection
tags:
- malware-analysis
- c2
- detection
- ioc
- ed25519
- mutex
- registry-run
- windows
- proram
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V83
  verified_at: '2026-11-05T17:52:28+08:00'
  notes: 已对照原文与图02/03核对：图02 agent_main 的 0x800 命令行/0xC00 cfg、load_embedded_config、--print-capabilities/--once/--insecure-tls/--server、PRORAM_SERVER_URL 回退、create_instance_mutex、agent_connect_loop 与卡一致；图03 build_signed_hello(PRORAM_INSTANCE_LOCK_NONCE)、Global\ProRAM-Agent- 前缀、CreateMutexA 与 GetLastError==0xB7 duplicate_instance 一致。未验证点：HELLO +0x00/+0x60/+0x90/+0xD8/+0x120 字段表来自正文文字，截图未逐字段展示；Run 键与 identity.bin 路径来自正文；YARA/命令未实机验证；无版本。
url: /docs/defense/detection/defense-detection-proram-agent-signed-hello-mutex-run-key/
draft: false
kb_aliases:
- ProRAM Agent
- PRORAM_ 环境变量
- SomPlugin
- .prcfg
- Global\ProRAM-Agent
- identity.bin
- signed_hello
---

## 一句话结论

该样本是一个以白加黑方式加载的 C NoCRT C2 Agent（PRO_RAM C NoCRT Agent/0.2）：它在 `identity.bin` 中保存 32 字节身份种子，派生 Ed25519 密钥并生成带签名的 HELLO，经 WSS/DNS failover + msgpack 上线；用公钥指纹派生 `Global\ProRAM-Agent-*` 互斥量保证单实例，并通过 `HKCU\...\Run\ProRAMAgent` 持久化。检测可围绕导出表、`.prcfg` 节、互斥量、环境变量、身份目录与 Run 键展开。

## 原理

- **白加黑加载**：黑 DLL `somkernl.dll`（内部名 `proram_c_nocrt_agent_failover_dll.dll`，构建标记 `clash-silent-speedld-dll`）与 `360speedld.exe` 同目录或作为插件被调用；导出对齐 `msimg32.dll` 并转发系统调用，额外导出 `SomPlugin` 承载 Agent。
- **身份与 HELLO**：`build_signed_hello` 生成 0x180 字节 HELLO：`agent_id`（`agent_c_` + 公钥 SHA256 前 16 hex）、Ed25519 公钥、`fingerprint`（`sha256:` + 公钥哈希）、`host_fingerprint`（MachineGuid/计算机名/USERDOMAIN/卷序列号）、`signature`（对 `PRO_RAM_AGENT_HELLO_V1:<nonce>` 的 Ed25519 签名，Base64）。种子来自 `PRORAM_AGENT_SEED_HEX`/`PRORAM_AGENT_IDENTITY_SEED_HEX`，否则读取/创建 `identity.bin`（`CryptGenRandom` 后落盘）。
- **单实例互斥量**：取 HELLO 中 `fingerprint` 冒号后的前 16 个 hex，拼成 `Global\ProRAM-Agent-<16hex>` 并 `CreateMutexA`；`ERROR_ALREADY_EXISTS` 时判定重复实例并退出。互斥量由公钥指纹派生，因此同一 `identity.bin` 只能跑一个 Agent，换机器/换身份会得到不同互斥量。
- **通信与能力**：WSS 主通道 + DNS failover，协议 msgpack，心跳 ping/pong；能力表包含 shell.exec、file_manager.*、persistence.*、system_info.get、diagnostics.get 等；导入中还有远程线程/写内存/反向 SOCKS/截屏相关痕迹。
- **持久化与落地**：`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ProRAMAgent`；身份目录 `%LOCALAPPDATA%\ProRAM\instances\portable-<16hex>\identity.bin` 或 `%ProgramData%\ProRAM\instances`；环境变量前缀 `PRORAM_`（`PRORAM_SERVER_URL`、`PRORAM_SL_KEEP`、`PRORAM_AGENT_ID`、`PRORAM_C_AGENT_LOG` 等）。
- **配置节**：内嵌配置位于 `.prcfg` 节，内容以 `PRORAMCFGv2` 开头；命令行支持 `--print-capabilities`、`--once`、`--insecure-tls`、`--server URL`，无 `--server` 时优先 `PRORAM_SERVER_URL`，最后才用内嵌 C2。
- 这些特征组合比单一字符串更可靠：导出表异常 + `.prcfg` 节 + `Global\ProRAM-Agent-*` 互斥量 + `identity.bin` + Run 键，基本可以唯一指向该 Agent。

## 触发条件

- 主机上出现 `360speedld.exe` 加载非官方目录的 `msimg32.dll`/`somkernl.dll`，或出现带 `SomPlugin` 导出的 DLL。
- 进程/内存/文件中出现 `ProRAM`、`PRORAM_`、`PRO_RAM_AGENT_HELLO_V1:`、`PRORAMCFGv2` 等字符串。
- 存在 `Global\ProRAM-Agent-*` 互斥量、`identity.bin` 或 `ProRAMAgent` Run 值。
- 网络侧出现 WSS/DNS failover、msgpack 流量或异常 C2 域名。

## 利用步骤

1. **进程与模块**：用 Sysmon Event 7/Process Explorer 查看 `360speedld.exe` 的模块列表，记录 `msimg32.dll`/`somkernl.dll` 的路径、签名与哈希。
2. **导出表**：`dumpbin /exports <dll>`，检查是否同时存在 `AlphaBlend`、`GradientFill`、`TransparentBlt`、`vSetDdrawflag` 与 `SomPlugin`。
3. **节区与字符串**：`strings -a <dll> | grep -E 'PRORAM|ProRAM|PRO_RAM_AGENT_HELLO_V1|PRORAMCFGv2'`；用 PE 工具查看 `.prcfg` 节。
4. **文件与注册表**：检查 `%LOCALAPPDATA%\ProRAM\instances\`、`%ProgramData%\ProRAM\instances\` 下的 `identity.bin`；`reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ProRAMAgent`。
5. **互斥量**：`WinObj`/Process Explorer 查找 `Global\ProRAM-Agent-*`；用 `handle`/`Process Hacker` 定位持有进程。
6. **环境变量**：检查进程环境块或注册表中的 `PRORAM_*`（尤其 `PRORAM_SERVER_URL`、`PRORAM_SL_KEEP`）。
7. **网络**：抓取 WSS/DNS 流量，查找 `PRO_RAM_AGENT_HELLO_V1:`、msgpack 结构与心跳；提取 C2 域名/IP。
8. **处置**：隔离主机、终止白进程与 Agent、删除 Run 键/身份目录、封禁 C2；保留样本、内存与日志做进一步分析。

## PoC

```powershell
# 1) 查看白进程加载的模块
Get-Process 360speedld -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty Modules |
  Where-Object { $_.FileName -match 'msimg32|somkernl' } |
  Select-Object FileName, FileVersionInfo

# 2) 导出表
dumpbin /exports .\somkernl.dll | Select-String 'AlphaBlend|SomPlugin|GradientFill'

# 3) 字符串与配置节
strings -a .\somkernl.dll | Select-String 'PRORAM|ProRAM|PRORAMCFGv2|HELLO_V1'

# 4) 注册表 Run 键
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ProRAMAgent

# 5) 身份目录
Get-ChildItem "$env:LOCALAPPDATA\ProRAM\instances","$env:ProgramData\ProRAM\instances" -Recurse -ErrorAction SilentlyContinue
```

```yara
rule ProRAM_Agent_DLL {
  strings:
    $a = "PRO_RAM_AGENT_HELLO_V1:" ascii
    $b = "PRORAMCFGv2" ascii
    $c = "Global\\ProRAM-Agent-" wide ascii
    $d = "PRORAM_SL_KEEP" ascii
  condition:
    uint16(0) == 0x5A4D and 3 of them
}
```

## 变体与关联

- 变体：同一 Agent 可能换白进程/插件名、换 C2 域名或 WSS 路径；但 `PRO_RAM_AGENT_HELLO_V1:`、`PRORAMCFGv2`、`Global\ProRAM-Agent-` 等构建标记通常保留。
- 变体：身份种子可通过环境变量注入，`identity.bin` 可能不存在；此时重点看互斥量与 HELLO 字符串。
- 变体：持久化可能从 HKCU Run 扩展到计划任务/服务；检测时应同时检查自启动项与计划任务。
- 关联：[[pentest-c2-dll-sideload-export-forwarding-host-whitelist]]（本样本的白加黑加载方式）、[[pentest-c2-signed-luajit-loader-shellcode-edr-evasion]]（其他白进程加载器）、[[pentest-persistence-control-panel-cpl-dll-registry]]（注册表持久化检测）、[[defense-forensics-java-memshell-heapdump-bytecode]]（内存取证方法参考）。
- 边界：样本可能被重新编译/改字符串，静态标记会失效；仅凭单个字符串可能误报，需结合导出表、互斥量、文件与网络多源确认。

## 检测与防御

- **主机检测**：Sysmon 7（非标准路径 DLL 加载）、8/10（远程线程/进程访问）、11（`identity.bin` 创建）、13（Run 键写入）；EDR 对“签名白进程加载未签名 DLL”告警；YARA 扫描上述字符串与 `.prcfg` 节。
- **网络检测**：WSS/DNS failover 模式、msgpack 心跳、`PRO_RAM_AGENT_HELLO_V1:` 明文（若未加密）、异常长连接与 DNS 查询；对 C2 域名/IP 做封禁与回溯。
- **加固**：白进程安装目录 ACL 收紧、DLL 签名校验、WDAC/AppLocker；禁用不必要的插件加载；限制 HKCU Run 与计划任务创建；对主机做定期 IOC 扫描。
- **应急**：隔离主机、终止 Agent、删除持久化与身份文件、封禁 C2、重置该主机上使用过的凭据；保留样本与内存镜像供溯源。

