---
id: code-analysis-reverse-anti-debug-ntdelayexecution-segmented-sleep
title: NtDelayExecution 分 20 次 1 秒延迟：绕过沙箱睡眠跳过并借 hook 开销拖出仿真窗口
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: ntdelayexecution-segmented-sleep-sandbox-evasion
aliases:
- NtDelayExecution 延迟
- 分段 sleep 反沙箱
- 20 次 1 秒
- 睡眠跳过绕过
- 沙箱超时规避
tags:
- anti-sandbox
- anti-debug
- windows
- ntdelayexecution
- sleep
- evasion
- malware
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V435
  verified_at: '2026-11-09T20:14:29+08:00'
  notes: 已对照原文与图11核对：动态解析 NtDelayExecution（GetModuleHandleA+GetProcAddress），iterations=20，LARGE_INTEGER 低/高 32 位 0xFF676980/0xFFFFFFFF 即 -10000000（1 秒），循环 20 次；『沙箱跳过长睡眠』为原文推测目的，卡内已按可能表述保留；未实测。与 delayed-conditional-trigger 卡（uptime/时间窗/网络多信号门控）不同链，不重复；dup-scan.json 早于建卡且无本篇 pair。
---

## 一句话结论

样本动态解析 `NtDelayExecution`，以负的 `LARGE_INTEGER` 间隔连续调用 20 次、每次约 1 秒，而不是一次长 sleep：沙箱/仿真器通常会自动跳过单次长睡眠，但对大量短睡眠要么逐个处理、要么被 hook 额外开销放大，最终把真正的恶意行为拖出自动化分析的时间窗口。

## 原理

- `NtDelayExecution(Alertable, &Interval)` 的 `Interval` 为负值时表示相对等待，单位 100ns；示例把 64 位值设为 `0xFFFFFFFF FF676980`（即 -10,000,000），等价 1 秒。
- 样本用 `GetModuleHandleA` + `GetProcAddress` 动态取 `NtDelayExecution`（不静态导入，增加分析难度），循环 `iterations = 20` 次调用。
- 为什么不用一次 20 秒：多数沙箱/仿真器对“长时间 sleep”有优化（直接快进或跳过），单次长延迟会被抵消；拆成 20 次 1 秒后，快进逻辑要么不生效、要么需要处理 20 次调用。此外这些 API 常被安全产品 hook 监控，每次调用都有额外开销，20 次会把总耗时进一步放大。
- 文章观察到样本在“没有任何功能理由”的情况下停滞 20 秒，判断其目的就是拖慢调试/绕过短时仿真窗口（多数在线沙箱只跑 2–5 分钟）。
- 这种延迟也可以作为条件门控：延时结束后再检查环境/解密载荷，使自动化分析在载荷落地前结束。

## 触发条件

- 样本在初始化阶段执行延迟；需要动态解析 ntdll 导出。
- 分析环境（沙箱/仿真器）有执行时间上限，并对长睡眠做跳过优化。
- 延迟调用未被强制加速或拦截。

## 利用步骤

1. 动态解析 `NtDelayExecution`（`GetModuleHandleA("ntdll.dll")` + `GetProcAddress`）。
2. 构造负的 `LARGE_INTEGER`（如 -10000000 = 1 秒）。
3. 循环 20 次调用 `NtDelayExecution(0, &interval)`，累积约 20 秒延迟。
4. 延迟结束后再执行后续恶意逻辑（解密、注入、外联），使自动化沙箱在观察到关键行为前超时。

## PoC

无 PoC（原文为样本行为分析）。核心形态：

```c
pNtDelayExecution = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
LARGE_INTEGER iv; iv.QuadPart = -10000000;   // 1 秒（相对）
for (int i = 0; i < 20; i++)
    pNtDelayExecution(0, &iv);
```

## 变体与关联

- 关联 [[code-analysis-reverse-anti-debug-delayed-conditional-trigger]]：用 uptime/时间窗/网络等条件做延迟门控；本卡是纯 API 分段延迟，侧重绕过“睡眠跳过”。
- 关联 [[pentest-c2-brc4-badger-embedded-pe-selfinject-loader]]：同类加载器用 `Sleep(60000)` 拖延沙箱；分段 sleep 是其对抗自动跳过的变体。
- 变体：`Sleep`/`WaitForSingleObject`/`NtWaitForSingleObject` 分段、随机化间隔、在延迟中插入环境检查、APC/定时器延迟执行。
- 边界：支持快进的沙箱可把多次短睡眠一并加速；hook 全部延迟调用可还原真实等待时间。

## 检测与防御

- 分析侧：在仿真器中加速/拦截所有 sleep 类调用（含 20 次短延迟），记录调用序列而不是只看总时长；在样本首次调用延迟时直接跳到后续逻辑。
- 检测：初始化阶段大量重复的 `NtDelayExecution`/`Sleep` 调用是可疑反分析特征；结合随后出现的注入/外联行为关联告警。
- 防御：沙箱应支持“时间加速 + API 调用计数”而非只依赖执行时长；对超过阈值的延迟调用直接判定可疑。
