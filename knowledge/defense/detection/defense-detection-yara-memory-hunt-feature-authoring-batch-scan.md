---
id: defense-detection-yara-memory-hunt-feature-authoring-batch-scan
title: Yara 内存狩猎：从汇编机器码/独有字符串提取规则特征，改 Yara 以 pid=999999 批量扫描全进程
type: scenario
domain: defense
path: defense/detection
technique: yara-memory-hunt-feature-authoring-batch-scan
aliases:
- Yara 内存扫描
- yaraplus
- pid 999999 全进程扫描
- 汇编机器码 Yara 特征
- strings64 独有字符串
- Windows_Trojan_CobaltStrike.yar 内存命中
- Get-InjectedThread 替代
tags:
- detection
- yara
- threat-hunting
- memory-scan
- windows
- cobaltstrike
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V431
  verified_at: '2026-11-09T18:44:39+08:00'
  notes: 已对照原文与 34/34 图片核对：Yara 语法（?? / A? / [4-6] / nocase/base64/xor）、41 B8 03 00 00 00 BA 02 00 00 00 B9 01 00 00 00 常量调用机器码对 PID 38756 与 exe 均命中（图 02-04）、GetCurrentProcessId 单 call 误报高（图 06）、strings64 endlessparadox（图 07/08）、Elastic Windows_Trojan_CobaltStrike.yar 对 9768/beacon_x64.exe 命中 7f8da98a 等（图 10-12）、修改 scanner.c pid==999999 GetAllProcessPids 跳过自身 yr_scanner_scan_proc 且 result==2 提示权限/EDR（图 13/14）、8776 SecurityHealthSystray 命中（图 15）均与原文一致。核对中发现卡片原写的 MSSE-server 十六进制尾部少一个 53（4D 53 45 2D），已按原文规则截图（图 11/12）修正为 4D 53 53 45 2D。卡片无文章 ID/URL/长段摘录，路径 defense/detection 合法；规则编写与批量扫描属同一 Yara 内存狩猎工作流，未视为两个独立场景。未验证点：未重编译修改版 Yara 实测；Elastic 规则集为外部依赖。
---

## 一句话结论

Yara 规则应优先使用“带常量参数的函数调用机器码、独有循环片段或独有字符串”，而不是单个 API 调用（`call rel32`）这种到处都有的字节；用 `yara64.exe <rule> <pid>` 可以直接扫描进程内存。把 Yara 源码里加一个 `pid == 999999` 分支、遍历 `GetAllProcessPids` 逐个 `yr_scanner_scan_proc`，即可一次扫描全部进程；以 System 权限运行可打开更多受保护进程，Elastic 的 `Windows_Trojan_CobaltStrike.yar` 能直接在内存中命中 Beacon。

## 原理

- **Yara 规则的三段结构**：`rule Name { strings: ... condition: ... }`，字符串既可用 `"text"` 也可用 `{ 41 B8 03 00 00 00 }` 十六进制；`??` 匹配任意字节、`A?` 半字节通配、`[4-6]` 匹配 4–6 个任意字节；`nocase`/`base64`/`xor`/`wide` 等修饰符自动处理文本变体。
- **从反汇编提取机器码特征**：对带常量参数的函数调用，编译器生成的 `mov r8d, 3; mov edx, 2; mov ecx, 1; call rel32` 是稳定字节序列（示例 `{ 41 B8 03 00 00 00 BA 02 00 00 00 B9 01 00 00 00 }`，不含 `call` 的相对偏移），在磁盘 PE 与进程内存中都能精确命中；循环体的 `cmp/jge/jmp/add` 序列同理，取其中一段即可。
- **为什么单个 API 调用不适合做特征**：`GetCurrentProcessId()` 这类调用在汇编中通常只是一个 `call qword ptr [__imp_...]`（6 字节），几乎每个正常进程都有，规则误报极高。
- **独有字符串更省力**：用 Sysinternals `strings64.exe` 导出全部 ANSI/Unicode 字符串，挑选业务/样本独有的标识（如自定义 ID、C2 域名、互斥体名、PDB 路径），一条字符串往往就能定位家族；对宽字符样本需用 `wide` 或带 `00` 的十六进制。
- **Yara 原生支持内存扫描**：`yara64.exe rule.yar <pid>` 对指定进程地址空间匹配；但官方工具一次只能扫一个 PID，无法批量狩猎。
- **批量扫描改造**：在 `scanner.c` 的 PID 解析处加 `if (pid == 999999)` 分支——调用 `GetAllProcessPids(&count)` 取全部 PID，`GetCurrentProcessId()` 跳过自身，循环 `yr_scanner_scan_proc(scanner, pids[i])`；返回 2 表示 `OpenProcess`/读取失败，通常是权限不足或 EDR 保护，需要以 System 权限运行。改造版即公开的 yaraplus 类工具。
- **命中判定**：以 Elastic `Windows_Trojan_CobaltStrike.yar` 为例，规则 `7f8da98a` 匹配 `%c%c%c%c%c%c%c%cMSSE-server` 字节序列（`{ 25 63 25 63 ... 4D 53 53 45 2D 73 65 72 76 65 72 }`），对 Beacon 进程与 beacon_x64.exe 文件都能命中；可用 ImHex 的十六进制搜索人工复核该序列。
- **局限**：Yara 仍是特征匹配；sleep mask 加密、cleanup/obfuscate、Artifact Kit 定制会改变内存字节；单次扫描可能错过睡眠窗口，需要多次采样并与配置提取/线程栈分析交叉验证。

## 触发条件

- 授权的蓝队/应急环境，Windows 主机上怀疑存在进程注入型 C2（CS/MSF/Sliver 等）或未知内存载荷；
- 防守方有目标进程的读取权限（建议 SYSTEM 权限，否则受保护进程会扫描失败）；
- 已有可用的 Yara 规则（自研或 Elastic/GCTI 规则集）且目标家族未被针对性改造；
- 扫描时机覆盖 payload 的解密/睡眠窗口，最好多次采样。

## 利用步骤

1. 在样本或内存镜像中用 x64dbg/IDA 定位目标函数，提取带常量参数调用、独有循环或独有字符串的字节序列；用 `strings64.exe <file>` 辅助找独有字符串。
2. 编写 Yara 规则，先用 `yara64.exe rule.yar <file>` 对磁盘样本验证，再用 `yara64.exe rule.yar <pid>` 对运行进程验证。
3. 获取/修改 Yara 源码或使用 yaraplus：增加 `pid == 999999` 的全进程分支，遍历 PID 列表调用 `yr_scanner_scan_proc`，跳过自身进程。
4. 以 System 权限运行批量扫描；对每个 "Scanning PID ... Fail" 记录为权限/EDR 保护导致，不当作干净。
5. 汇总命中 PID，结合进程签名、线程堆栈、网络连接与配置提取工具交叉验证后进入清除流程。

## PoC

规则与扫描命令（防守方，授权环境）：

```
rule TextExample
{
    strings:
        $text_string = { 41 B8 03 00 00 00 BA 02 00 00 00 B9 01 00 00 00 }
    condition:
        $text_string
}
```

```
yara64.exe .\test.yara 38756                 # 扫描进程内存
yara64.exe .\test.yara .\demo_foryara.exe    # 扫描磁盘文件
yara64.exe Windows_Trojan_CobaltStrike.yar 9768
yara64.exe Windows_Trojan_CobaltStrike.yar 999999   # 改造版：全进程
```

批量扫描分支最小骨架（C）：

```c
if (pid == 999999) {
    int count = 0;
    int *pids = GetAllProcessPids(&count);
    DWORD self = GetCurrentProcessId();
    for (int i = 0; i < count; i++) {
        if (pids[i] == self) continue;      // 跳过自身，减少误报
        int rc = yr_scanner_scan_proc(scanner, pids[i]);
        if (rc == 2) {
            fprintf(stderr, "Scanning %d Fail, need SYSTEM or EDR protected\n", pids[i]);
        }
    }
    free(pids);
}
```

## 变体与关联

- 变体：规则可改用 Elastic/GCTI/Signature-Base 现成规则集；也可用 MemProcFS、Hollows_Hunter、Hunt-Sleeping-Beacons 等工具互补。
- 变体：批量扫描可改成按进程名/签名筛选后逐个扫，降低对业务进程的性能影响。
- 变体：同一方法可用于磁盘文件、WebShell 源码、HTTP 日志中的漏洞利用痕迹、漏洞驱动/rootkit（Elastic 规则用 PE 结构 `int16(uint32(0x3C)+0x5c) == 0x0001` 加独有 PDB 字符串 `\amifldrv64.pdb` 定位 Amifldrv 驱动）。
- 关联：[[defense-detection-cobaltstrike-memory-hunting-toolkit]]（EvilEye/Hunt-Sleeping-Beacons/Hollows_Hunter/Elastic 规则组合）、[[defense-detection-redline-stealer-yara-pe-strings]]（PE 字符串组合规则与宽字符处理）、[[defense-incident-response-injected-thread-start-address-kill-c2-offline]]（命中后的线程级清除）、[[defense-detection-unbacked-thread-start-address-injection-bypass]]（线程起始地址 API 检测）。
- 边界：sleep mask/加密内存会让字符串规则失效；修改过的 Yara 需自行编译并验证稳定性；对全进程扫描注意性能与蓝屏风险，避免扫描关键内核/受保护进程。

## 检测与防御

- 规则维护：每次发现新家族后把独有字符串/代码片段固化为规则，并在正常软件集上做误报回归；单 API 调用、公共域名等弱特征不要单独成规则。
- 扫描策略：以 System 权限定期批量扫描高价值主机，覆盖睡眠窗口；对失败进程记录并纳入人工核查。
- 结果处置：Yara 命中只是线索，需结合进程签名、父进程、线程栈、网络连接与内存配置提取确认；确认后按线程/进程清除流程处置。
- 防御方也应知道 Yara 的边界：它不是行为检测，无法覆盖未知威胁与加密内存，必须与 EDR/ETW/流量检测组合使用。
