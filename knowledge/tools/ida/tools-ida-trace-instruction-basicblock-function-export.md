---
id: tools-ida-trace-instruction-basicblock-function-export
title: IDA Trace 三种粒度：指令/基本块/函数级跟踪并导出文本供脚本处理
type: scenario
domain: tools
path: tools/ida
technique: ida-trace-instruction-basicblock-function-export
aliases:
- IDA Trace
- Tracing window
- Instruction tracing
- Basic block tracing
- Function tracing
- export trace to text file
- IDA 执行轨迹
tags:
- ida
- debugging
- trace
- instruction-tracing
- basic-block
- function-tracing
- reverse
- obfuscation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:34:27+08:00'
  notes: 已对照原文及图18-21核对：Instruction/Basic block/Function tracing 三种粒度、Tracing options 的 buffer/text file/highlight/库函数/返回指令选项、Tracing window 与 export trace to text file 均与截图一致；未复跑
---

## 一句话结论

IDA 的 `Debugger → Tracing` 提供指令级、基本块级、函数级三种执行轨迹记录；在 `Tracing options` 中设置缓冲区大小、trace 文本文件与高亮后运行程序，结束后在 `Tracing window` 查看并右键 `Export trace to text file`，即可把执行轨迹交给 Python/脚本做覆盖率、混淆还原与崩溃分析。

## 原理

- **Trace 记录的是“实际执行过什么”**：与静态反汇编不同，IDA 调试器在程序运行时记录每条指令、每个基本块或每次函数调用，能反映真实控制流（包括间接跳转、OLLVM 分发器、异常路径）。
- **三种粒度**：
  - `Instruction tracing`：逐条指令记录，最精细，适合精确定位执行序列、寄存器/内存变化点；
  - `Basic block tracing`：按基本块记录，适合观察 OLLVM 控制流平坦化后的真实块序列、覆盖率；
  - `Function tracing`：只记录函数调用，适合快速还原调用链与模块交互。
- **Tracing options**：可设置 `Trace buffer size`（轨迹缓冲区，过小会丢记录）、`Trace text file`（实时/结束时写文件）、`Stop condition`、是否跟踪库函数/调试段、是否高亮执行过的指令等；高亮能把执行路径直接画在 IDA 视图里。
- **Tracing window**：记录命中后可查看轨迹条目；右键 `Export trace to text file` 导出文本，便于用 Python 解析（去重、统计块序列、还原分发器、对齐符号）。
- **为什么有用**：OLLVM/VM 保护、间接调用、异常展开等场景静态分析难以确定真实路径；Trace 把动态事实落盘，弥补静态与动态之间的差距。

## 触发条件

- 使用 IDA 调试器（本地/远程）并能运行目标到断点或完整执行。
- 目标可被调试（无强反调试/反虚拟化），且执行路径可复现。
- 在 `Tracing options` 中设置的缓冲区足够大，磁盘可写 trace 文件。
- 需要分析的是控制流/覆盖率/调用序列，而不是单纯的静态结构。

## 利用步骤

1. 启动调试并运行到关键断点（例如输入校验前、解密函数前）。
2. 打开 `Debugger → Tracing → Tracing options`：
   - 设置 `Trace buffer size`（示例 1000000，按执行量调整）；
   - 指定 `Trace text file` 路径；
   - 勾选 `Highlight instructions in IDA views`、按需勾选 `Trace over library functions`/`Trace over debugger segments`。
3. 在 `Debugger → Tracing` 子菜单选择粒度：`Instruction tracing`、`Basic block tracing` 或 `Function tracing`。
4. 继续运行（F9）触发目标逻辑；到停止条件/断点后暂停。
5. 打开 `Debugger → Tracing → Tracing window` 查看记录；右键 `Export trace to text file` 导出。
6. 用 Python 解析文本：统计基本块序列、去重、还原 OLLVM 分发器状态、对齐函数调用，或与静态 CFG 对比找未覆盖路径。

## PoC

```text
# IDA GUI 配置（无脚本 PoC）
Debugger → Tracing → Tracing options
  Trace buffer size: 1000000
  Trace text file:   <可写路径>/trace.txt
  [x] Highlight instructions in IDA views
  [x] Trace over debugger segments
  [x] Trace over library functions
  [x] Log return instructions (Function tracing)

Debugger → Tracing → Instruction tracing / Basic block tracing / Function tracing
F9 运行 → 触发逻辑 → 暂停
Debugger → Tracing → Tracing window → 右键 Export trace to text file
```

```python
# 导出文本后的最小处理示例：统计基本块执行次数
from collections import Counter
counts = Counter()
with open("trace.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if line:
            counts[line.split()[0]] += 1
for addr, n in counts.most_common(20):
    print(addr, n)
```

原文在 IDA 中演示了三种粒度的选择与 Trace 窗口/导出；本卡未复跑。

## 变体与关联

- **变体：基本块 trace + OLLVM**：记录真实基本块序列，按分发器状态变量重组控制流，绕过平坦化；与静态 CFG 对比可发现不可达/虚假块。
- **变体：函数 trace 还原调用链**：只记录 call/return，快速定位关键函数与模块；适合大型样本/协议栈。
- **变体：指令 trace 精确定位**：配合寄存器/内存断点，定位某条指令被执行的上下文；轨迹量最大，需控制范围。
- **关联**：[[tools-ida-python-conditional-breakpoint-register]]（条件断点缩小 trace 范围）、[[tools-ida-fork-child-loop-patch-attach]]（附加子进程后 trace 其执行流）。
- **边界**：trace 缓冲区过小会丢记录；逐指令 trace 会显著拖慢程序并占用磁盘；强反调试可能检测调试器；trace 只反映本次输入路径，需多组输入覆盖分支。

## 检测与防御

- 这是逆向分析技巧，不是攻击链；用于 OLLVM/VM 保护分析、覆盖率评估、崩溃复现与协议逆向。
- 注意事项：先设停止条件/断点限定范围，避免全程序逐指令 trace 撑爆缓冲区；导出后及时压缩/清理大文件；trace 文本可能含敏感输入，注意保管。
- 对抗视角：样本若检测调试器、使用时间差/完整性校验，trace 可能失败；可结合 Frida/Unicorn 模拟执行或硬件 trace（Intel PT/ETM）替代。
