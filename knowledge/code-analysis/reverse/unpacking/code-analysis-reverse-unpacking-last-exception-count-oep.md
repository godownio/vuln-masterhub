---
id: code-analysis-reverse-unpacking-last-exception-count-oep
title: 末次异常法：统计异常次数 m，重载后按 m-1 次 Shift+F9，再于 code 段断点定位 OEP
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: last-exception-counting-oep
aliases:
- 末次异常法
- 最后一次异常法
- ExCounter.dll 找 OEP
- 异常计数脱壳
- Shift+F9 计数
tags:
- reverse
- unpacking
- oep
- ollydbg
- exception
- pe
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T07:52:32+08:00'
  notes: 已对照原文及图 40-48 核对：忽略异常时 Log 显示16次异常；全部不忽略后第15次Shift+F9停在INT3 0x0046E890；对.code下断点后命中OEP 0x004271B0；ExCounter 插件“第一步开始计数/第二步带我到OEP/全部重置”与图47-48一致。dup-scan 与 two-stage-section-breakpoint 互为 likely_duplicate，经对照异常计数法与段内存断点法机制/触发条件完全不同，判为并列保留、不删除。未验证点：未在本机运行 OllyDbg/样本复现，异常次数稳定性未独立复核。
---

## 一句话结论

对自解压/自解密过程中产生大量异常的壳（原文以 `bitarts_evaluation.c.exe` 为例），可统计程序运行前的异常次数 m：在 OllyDbg 中取消“忽略所有异常”，重载后反复 `Shift+F9` 忽略异常直到程序真正运行，记下次数 m；再次重载并按 m-1 次 `Shift+F9`，最后一次异常后对 code 段下断点，`F9` 即中断在 OEP。也可用 `ExCounter.dll` 插件“开始计数 → 带我到 OEP → 全部重置”自动完成。

## 原理

- **壳用异常控制流**：不少壳在自解密/自解压阶段故意触发异常（`INT3`、非法访问、除零等），由异常处理器接管并继续解压。异常次数与解压阶段强相关，最后一次异常通常发生在壳即将跳转 OEP 之前。
- **计数定位**：把异常全部设为“不忽略”后，每次 `Shift+F9` 都会跳过当前异常并继续；当程序不再因异常中断、而是真正运行（窗口出现/进程退出）时，说明异常已经处理完，记录总次数 m。重载后只忽略前 m-1 次，程序会停在最后一次异常处。
- **最后一次异常后下代码段断点**：最后一次异常处理完，壳继续解压并跳向原代码段；此时对 `.code`/`.text` 下内存/执行断点，`F9` 让程序运行，第一次执行原代码段即 OEP。
- **为什么有效**：不依赖壳的具体指令（无 `PUSHAD/POPAD` 也可），只依赖“异常次数在重载后稳定”这一确定性行为；壳每次运行路径一致，m 可复现。
- **替代计数**：先把异常设为忽略，`F9` 运行，在 OllyDbg 的 `Log` 窗口查看异常次数（原文例为 16 次），再用该次数做手工定位。
- **边界**：壳每次运行的异常次数可能因环境/随机化不同而变化；某些壳会在检测到调试器时改变异常路径；最后一次异常不一定紧邻 OEP，需再用代码段断点/单步确认；异常全部不忽略会频繁中断，耗时。

## 触发条件

- 目标为 32 位 PE，壳在自解阶段产生大量异常（原文 `bitarts_evaluation.c.exe`）。
- 使用 OllyDbg，能修改异常处理选项、使用 `Shift+F9`；可选 `ExCounter.dll` 插件。
- 异常次数在重载后可稳定复现。
- 仅用于授权逆向分析与恶意样本分析。

## 利用步骤

1. 载入样本，Options → Debugging options → Exceptions，把“忽略异常”的勾选全部去掉；`Ctrl+F2` 重载。
2. 反复按 `Shift+F9` 跳过异常，直到程序真正运行（窗口出现/退出），记录按键次数 m（原文方法）。
   或：把异常设为忽略，`F9` 运行，在 `Log` 窗口读取异常次数（原文例 16 次）。
3. `Ctrl+F2` 重载，按 m-1 次 `Shift+F9`；程序停在最后一次异常处（原文 `bitarts_evaluation.c.exe` 第 16 次异常为 `INT 3`，停在 `0x0046E890`）。
4. 在 Memory Map 中对 `.code`/`.text` 设置内存访问/执行断点。
5. `Shift+F9`/`F9` 运行，程序中断在 OEP（原文 `0x004271B0`）。
6. 确认 OEP 后 dump 并修复 IAT。
7. 插件法：把 `ExCounter.dll` 放入 OllyDbg 插件目录 → 插件 → 异常处理器 → 第一步“开始计数”（OllyDbg 重新加载）→ 第二步“带我到 OEP”→ 必要时对 code 段下断点 → 全部重置。

## PoC

```text
# 手工计数（bitarts_evaluation.c.exe，原文）
1. Options -> Debugging options -> Exceptions: 取消全部忽略
2. Ctrl+F2 重载
3. Shift+F9 直到程序运行，记录次数 m
4. Ctrl+F2 重载，Shift+F9 (m-1) 次
5. 最后一次异常: INT 3 @ 0x0046E890
6. Memory Map -> .code -> Set memory breakpoint on access
7. Shift+F9 -> 中断在 OEP 0x004271B0
```

```text
# 异常次数查看（替代方法）
Options -> Debugging options -> Exceptions: 忽略所有异常
F9 运行 -> Log 窗口查看异常次数（原文例：16 次）
```

```text
# ExCounter.dll 插件
插件 -> 异常处理器 -> 第一步：开始计数
插件 -> 异常处理器 -> 第二步：带我到 OEP
（若未准确定位，Memory Map -> CODE 段下断点）
插件 -> 异常处理器 -> 全部重置
```

## 变体与关联

- **条件记录断点**：无 PUSHAD 的 FSG 壳用条件记录断点收集 `GetProcAddress`，与末次异常法同属“不依赖标准 ESP 定律”的回退，见 [[code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep]]。
- **ESP 定律/二次断点**：异常少的壳优先用栈断点或段断点，见 [[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]、[[code-analysis-reverse-unpacking-two-stage-section-breakpoint-oep]]。
- **边界**：异常计数依赖壳行为稳定；若壳有反调试/随机延迟，m 可能变化，需要多次重载复核。
- **关联**：[[code-analysis-reverse-unpacking-ollydbg-run-trace-condition-importrec-tracer]]（OllyDbg 跟踪停止条件与 IAT 修复）。

## 检测与防御

- **检测（样本侧）**：壳可检测调试器/异常被拦截，改变异常序列；可把关键解压放在异常处理器之外，降低计数法的可预测性。
- **防御（防护方）**：异常计数只是脱壳技巧，不能替代完整保护；建议反调试、代码虚拟化与完整性校验组合。
- **注意**：修改异常选项会改变程序行为，需在快照上复现；OEP 定位后仍需 IAT 修复。
