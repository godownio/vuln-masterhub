---
id: code-analysis-reverse-anti-debug-process-name-hash-shift-xor
title: 进程名 SHIFT+XOR 哈希黑名单反分析：逐字符生成 32 位哈希比对 VMware/调试器名单，命中即退出
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: process-name-hash-shift-xor-blacklist
aliases:
- 进程名哈希反调试
- SHIFT XOR 进程名哈希
- 反分析进程黑名单
- 进程名模糊哈希
- WikiLoader 反分析检查
tags:
- windows
- anti-debug
- anti-analysis
- anti-vm
- process-enumeration
- hash
- malware
- evasion
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453
  verified_at: '2026-11-10T02:23:38+08:00'
  notes: 已对照原文与 17 张图核对：Process32Next 枚举→逐字符 SHIFT+XOR 生成 32 位哈希→与 imm32 常量比较命中即退出，与图12/13 一致；卡内列出的 13 个 cmp 立即数（0D04F981…12D92D59）逐项核对无误；文章未给出移位位数/XOR 常数完整算法，卡片如实标注无 PoC，未复算；14 个黑名单进程名与原文清单一致；原文无受影响组件版本，affected_versions 已清空。
---

## 一句话结论

样本在进入真正恶意逻辑前用 `Process32First/Next` 枚举全部进程名，对每个名字逐字符做 SHIFT（移位）与 XOR 运算生成一个 32 位简单哈希，再与样本内一串硬编码 32 位常量比较；只要命中 VMware 工具、调试器或进程监控工具（VGAuthService.exe、vmtoolsd.exe、ProcessHacker.exe、x64dbg.exe、PE-bear.exe、CFF Explorer.exe、Autoruns.exe、procexp/procexp64、Procmon/Procmon64、tcpview.exe、Dbgview.exe、portmon.exe）中的任何一个，就直接退出，不执行后续载荷。

## 原理

- **为什么要哈希进程名**：直接保存 `x64dbg.exe`、`ProcessHacker.exe`、`vmtoolsd.exe` 等明文字符串会进入 `strings` 与静态查杀的特征；把进程名映射成 32 位数值后，二进制里只有一串 `cmp reg/imm32; je exit`，可读性与可搜索性显著下降。
- **算法形态**：样本对每个进程名字符循环执行“移位 + 异或”混合（文章中描述为 SHIFT 与 XOR），得到 32 位结果；随后用一系列立即数比较（调试中可见 `0x0D04F981`、`0xE3FA84A4`、`0x7CFDD7AF`、`0xB8B9C504`、`0x69A0620E`、`0x6017EE43`、`0xCDE3F5B8`、`0xC0C5E553`、`0xE93BE2E0`、`0x149EFC55`、`0xF27FA18E`、`0x4B4FCC47`、`0x12D92D59` 等），任一相等即跳转到退出路径。具体移位位数与 XOR 常数未在分析中给出，研究者需按样本还原。
- **为什么专门选这些进程**：名单同时覆盖两类环境——VMware 增强工具（VGAuthService、vmtoolsd）用于识别虚拟机/沙箱；调试与监控工具（x64dbg、ProcessHacker、Procmon、Process Explorer、PE-bear、CFF Explorer、Autoruns、tcpview、Dbgview、portmon）用于识别分析人员。命中任一即认为“正在被分析”，直接放弃执行，增加动态分析成本。
- **与普通字符串比对的差别**：进程名不落地为明文，且比较是数值比较，静态规则很难直接写“包含 x64dbg”；只有动态调试到哈希循环、或按常量反推算法后才能映射出名单。
- **局限**：这是用户态、按进程名匹配的检查，改名工具进程、在驱动/内核层隐藏进程、或直接 patch 哈希函数/比较分支即可绕过；它也不检测内存取证、网络沙箱等不以进程名暴露的分析方式。

## 触发条件

- Windows 主机，样本已被加载并进入检查逻辑（常见于被侧加载的插件 DLL 或注入后的 shellcode）。
- 样本有权限调用 Toolhelp 进程枚举 API（普通用户通常可以）。
- 分析环境中运行了名单内的任一进程（VMware Tools、调试器、Procmon/Process Explorer 等）——命中后样本退出。
- 分析者尚未 patch 哈希逻辑或改名相关进程。

## 利用步骤（分析/复现视角）

1. 在 IDA/Ghidra 中定位 `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`、`Process32First`、`Process32Next` 调用点，跟随 `PROCESSENTRY32.szExeFile` 的使用。
2. 找到对进程名字符串的逐字符循环：典型形态是读取一个字符、执行移位与 XOR、累加到 32 位寄存器；循环结束后立即与多个立即数比较。
3. 提取全部立即数常量；对名单中的候选进程名（x64dbg.exe 等）按猜测的移位/XOR 参数重算，命中即可反推算法细节；也可直接动态调试，在比较处下断点观察每次哈希值。
4. 验证：在虚拟机内启动名单中的工具（如 ProcessHacker.exe）再运行样本，观察样本在比较命中后退出、无后续网络/注入行为；改名工具后重试，确认继续执行。
5. 分析绕过：patch 哈希函数返回固定不匹配值，或把所有 `je` 分支改为 NOP；也可在干净环境只保留必要调试工具并使用非名单名称。

## PoC

无 PoC（文章未给出移位位数与 XOR 常数的完整算法）。可用的分析思路：

```text
1) xref CreateToolhelp32Snapshot -> Process32First/Next 循环
2) 在循环体内找 “逐字符 shift/xor -> 累加” 指令序列
3) 记录循环后的 cmp reg, imm32 常量集合
4) 用候选进程名 + 猜测参数复算，命中即确认算法
```

## 变体与关联

- [[code-analysis-reverse-anti-debug-file-marker-remotedebugger-av-process-enum]]：Toolhelp32 枚举 `360tray.exe` 做安全软件检测，但比对的是明文进程名；本卡是哈希化名单。
- [[code-analysis-reverse-anti-debug-critical-process-window-title-av-detection]]：通过窗口标题与进程快照识别杀软，属同一“环境识别”大类。
- [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]、[[code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks]]：其他沙箱/模拟器识别组合。
- 变体：哈希算法可换成 CRC32、FNV、ROR13 等；比较对象可换成窗口类名、模块名、用户名；也可能同时校验哈希与明文两套名单。
- 边界：进程改名、内核隐藏、patch 分支即可绕过；名单更新依赖样本版本。

## 检测与防御

- 检测（分析侧）：内存/反汇编中出现“循环内 shift+xor + 紧随一串 `cmp reg, imm32; je`”的模式；把常量集合作为样本指纹；动态观察 `Process32First/Next` 调用后立即 `ExitProcess` 的行为。
- 检测（防御侧）：EDR 关注非安全软件进程短时间枚举全部进程后退出；对侧加载宿主（如便携应用）拉起后立即退出且无网络行为的情况提高警惕。
- 防御：分析环境隐藏/改名调试与监控工具进程；在沙箱中使用内核级进程隐藏；对样本做 patch 后再动态分析；生产环境靠行为检测而非进程名。
- 响应：把该哈希黑名单与常量作为 IOC，关联同源样本（同一加载器/家族）进行批量排查。
