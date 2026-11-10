---
id: defense-detection-cobaltstrike-memory-hunting-toolkit
title: Cobalt Strike 4.9.1 Beacon 内存狩猎工具链：EvilEye 配置提取、Hunt-Sleeping-Beacons、Hollows_Hunter 与 Elastic YARA
type: scenario
domain: defense
path: defense/detection
technique: cobaltstrike-memory-hunting-toolkit
tags:
- cobaltstrike
- c2
- threat-hunting
- memory-scan
- yara
- beaconeye
- hollows-hunter
- detection
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Cobalt Strike 4.9.1（文中测试 Beacon 版本）
verification:
  verified_by: verifier-V341
  verified_at: '2026-11-08T21:29:17+08:00'
  notes: 已对照原文核对：EvilEye 3040 配置字段、HSB DelayExecution 栈与 x86 限制、Hollows_Hunter 检出 3040、Elastic YARA 6 条规则及最终四工具未检出但自写 Test.yar 仍命中 7f8da98a，全部与截图一致；防守方工具链卡无攻击原语错误
url: /docs/defense/detection/defense-detection-cobaltstrike-memory-hunting-toolkit/
draft: false
kb_aliases:
- BeaconEye
- EvilEye
- Hunt-Sleeping-Beacons
- Hollows_Hunter
- Windows_Trojan_CobaltStrike.yar
- CS Beacon 内存检测
- 威胁狩猎
---

## 一句话结论

对默认配置的 Cobalt Strike 4.9.1 Beacon，内存狩猎可用四类互补工具：EvilEye/BeaconEye 扫描内存中的 Beacon 特征并解析出完整配置（C2、URI、User-Agent、Sleep、SpawnTo 等）；Hunt-Sleeping-Beacons 按 `DelayExecution` 线程与异常调用栈发现睡眠中的 Beacon；Hollows_Hunter 扫描全进程的植入 PE/shellcode/hook/内存补丁；Elastic `Windows_Trojan_CobaltStrike.yar` 以字符串/代码字节规则命中多条特征。四者组合可作为评估 CS 免杀配置（strrep/magic/cleanup/obfuscate/sleepmask/Artifact Kit）的基线。

## 原理

- **BeaconEye/EvilEye（配置提取）**：BeaconEye 是 .NET 工具，EvilEye 是 Go 替代（低版本 Windows 无 .NET 4.x 时可用）。它们扫描进程内存中的 Cobalt Strike 特征结构，定位 Beacon Config 并解析字段：Watermark、KillDate、HTTP_Post_URI、User-Agent、SpawnTo（x86/x64 rundll32）、Sleep、MaxGetSize、Port、C2Server、Host_Header 等；无需知道密钥即可读出默认配置。
- **Hunt-Sleeping-Beacons（睡眠线程检测）**：Beacon 睡眠时线程进入 `DelayExecution`，其调用栈常出现 `NtDelayExecution → SleepEx → 未知模块地址` 的异常组合；工具枚举处于 `DelayExecution` 的线程并检查调用栈，发现可疑进程与 sleep 时间。文中版本对 x86 进程检测不到，需注意架构限制。
- **Hollows_Hunter（内存植入扫描）**：扫描所有运行进程，识别替换/植入的 PE、shellcode、hook、内存 patch 等；默认 Beacon 的反射加载私有可执行内存会被标记为 suspicious。
- **Elastic YARA（静态/内存特征）**：`Windows_Trojan_CobaltStrike.yar` 包含多条规则（文中默认 Beacon 命中 `ee756db7`、`663fc95d`、`f0b627fc`、`1787eef5`、`3dc22d14`、`7f8da98a`），分别匹配字符串（`beacon.x64.dll`、`%s (admin)`、格式化串、`beacon_loader_x64`、`MSSE` 管道格式串）与代码字节（MZ/PE 头、函数序言）。
- **为什么组合有效**：配置提取不依赖静态特征；睡眠检测覆盖“休眠中”的时间窗；内存植入扫描覆盖结构和权限；YARA 覆盖字符串/代码。单一工具易被针对性规避（例如 sleep_mask 隐藏字符串、cleanup/obfuscate 去头），组合能提高发现概率。

## 触发条件

- 目标 Windows 上运行 Cobalt Strike Beacon（文中为 4.9.1 默认配置）。
- 防守方具备管理员权限/内存读取能力（BeaconEye/EvilEye、Hollows_Hunter 需读取目标进程内存）。
- 已获取对应工具（EvilEye/BeaconEye、Hunt-Sleeping-Beacons、Hollows_Hunter、YARA 及规则集）。
- 对睡眠型 Beacon，扫描时机需覆盖 sleep 窗口或多次采样；对 x86 进程注意 Hunt-Sleeping-Beacons 的限制。

## 利用步骤

1. **EvilEye/BeaconEye 配置提取**：`EvilEye.exe`（或 BeaconEye.exe）运行后自动枚举进程，输出 `beacon_x64(原始).exe (3040), Keys Found: True` 与配置字段（Watermark、HTTP_Post_URI、UserAgent、SpawnTo、Sleep、Port、C2Server 等），可直接用于封禁 C2 与写检测规则。
2. **Hunt-Sleeping-Beacons**：`Hunt-Sleeping-Beacons.exe` 输出处于 `DelayExecution` 的线程数，逐个检查调用栈；发现 `NtDelayExecution → SleepEx → 未知模块` 且 sleep 时间异常（如 60s）的进程即高度可疑；文中对 x86 进程未检出。
3. **Hollows_Hunter**：`hollows_hunter64.exe` 扫描全部进程，输出 `Detected: <pid>` 与 suspicious 列表；默认 Beacon 的反射加载内存会被标记。
4. **YARA 文件/内存扫描**：`yara64.exe "Elastic Security\Windows_Trojan_CobaltStrike.yar" -s <pid>`，先看命中规则数（默认 6 条），再用 `-s` 打印命中字符串，区分字符串型/代码型规则。
5. **交叉验证**：把 EvilEye 提取的 C2/URI/UA 与网络日志（JA3/checksum8）、进程行为（rundll32 派生、私有可执行内存）关联；对睡眠型 Beacon 多次采样。
6. **对抗评估**：对经过 strrep/magic/cleanup/obfuscate/sleepmask/Artifact Kit 处理的 Beacon 重复上述步骤，观察哪些工具/规则仍能命中（文中最终配置使四类工具均未检出，但定制 YARA 仍可命中 Artifact Kit 特征）。

## PoC

工具命令骨架（防守方，授权环境）：

```text
EvilEye.exe
Hunt-Sleeping-Beacons.exe
hollows_hunter64.exe
yara64.exe "Elastic Security\Windows_Trojan_CobaltStrike.yar" -s <pid>
```

EvilEye 输出关键字段（默认 Beacon 示例）：

```text
beacon_x64(原始).exe (3040), Keys Found: True
Watermark: 987654321
HTTP_Post_URI: /submit.php
UserAgent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MANM; MANM)
SpawnTo_x64: %windir%\sysnative\rundll32.exe
Sleep: 60000
Port: 8011
C2Server: 192.168.47.148,/dot.gif
```

YARA 命中示例：

```text
Windows_Trojan_CobaltStrike_ee756db7 3040
Windows_Trojan_CobaltStrike_663fc95d 3040
Windows_Trojan_CobaltStrike_f0b627fc 3040
Windows_Trojan_CobaltStrike_1787eef5 3040
Windows_Trojan_CobaltStrike_3dc22d14 3040
Windows_Trojan_CobaltStrike_7f8da98a 3040
```

## 变体与关联

- 变体：BeaconEye 需 .NET 4.x；低版本系统用 EvilEye（Go）替代；两者输出字段相近。
- 变体：Hunt-Sleeping-Beacons 对 x86 进程无效，可结合 ETW/线程栈工具或 64 位进程扫描补充。
- 变体：YARA 规则可替换为 GCTI/自研规则；内存扫描可用 MemProcFS/YARA 组合。
- 关联：[[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]（流量侧识别与配置提取）、[[defense-detection-tls-mitm-offload-cobaltstrike-beacon-suricata]]（TLS 中间人 + Suricata 检测）、[[pentest-c2-beacon-memory-signature-hunt-patch-evasion]]（攻击方二分定位并 patch 内存特征）、[[pentest-c2-hsb-sleep-obfuscation-evasion-ntdll-gadget-stack-dup]]（规避 Hunt-Sleeping-Beacons）。
- 边界：工具需读取进程内存，受权限/PPL/EDR 限制；睡眠混淆、cleanup/obfuscate、Artifact Kit 定制会降低命中；单次扫描可能错过 sleep 窗口。

## 检测与防御

- 检测：以多工具、多时间点组合扫描；把配置提取（C2/URI/UA）、睡眠线程调用栈、内存植入结构、YARA 字符串/代码四类信号交叉验证。
- 检测：网络侧结合 checksum8（92/93）、JA3/JA3s、Beacon 元数据解析；主机侧关注 rundll32 派生、私有 RX/RWX 内存、命名管道 `MSSE`。
- 防御：部署 EDR/内存扫描与 YARA 规则更新；限制管理员权限与进程内存读取；对高价值主机做定期内存取证与睡眠窗口采样。
- 加固：启用 PPL/ELAM、CFG/CIG、攻击面减少规则；监控 `VirtualProtect`/`VirtualAlloc` 异常与无模块归属可执行内存。
