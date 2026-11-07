---
id: code-analysis-reverse-firmware-vxworks-base-jump-table
title: VxWorks 固件加载基址恢复：switch 跳转表绝对地址减文件偏移
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: vxworks-base-jump-table
tags:
- reverse
- firmware
- vxworks
- arm
- base-address
- jump-table
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:15:20+08:00'
  notes: 已对照原文与 31 张截图核对：0x8B2BE0-0xB0BEC=0x801FF4、&0xFFF000=0x801000、basefind -0x801fc0 出现 73700 次均一致；原文无受影响版本；未实际运行脚本。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-vxworks-base-jump-table/
draft: false
kb_aliases:
- 跳转表推理法
- switch 跳转表基址
- VxWorks 基址恢复
- ArmBaseFinder
- basefind
- 固件 rebase
---

## 一句话结论

ARM 架构 VxWorks 固件中，switch 跳转表里的绝对地址与它在文件中的偏移之差就是加载基址；先 `binwalk -A` 确认架构，找一个含绝对地址的跳转表，用 `绝对地址 - 文件偏移` 再按页对齐（`& 0xFFF000`）即可 rebase，单表有误差时用多个跳转表/basefind 统计最佳基址。

## 原理

- RTOS 固件通常没有 Linux 那样的固定虚拟内存布局，IDA 默认按 0 加载时，代码中的绝对地址（跳转表、函数指针表、字符串表）全部偏移，反汇编会看到非法地址或跳到函数中间。
- ARM 的 switch 常编译为 `LDR PC, [R1,R2,LSL#2]` 或 `DCD 0x...` 形式的跳转表；表中条目是运行时绝对地址，文件中的位置是偏移，两者差值即基址（再考虑页对齐/加载偏移）。
- 示例：跳转表条目 `0x8B2BE0` 在文件偏移 `0xB0BEC`，差值 `0x801FF4`；页对齐 `0x801FF4 & 0xFFF000 = 0x801000`，即加载基址。
- 编译器会为性能/对齐对跳转表做“整容”（插入无效条目、重排、混合相对/绝对跳转），单表计算可能有误差；用多个跳转表统计、取出现次数最多的偏移（basefind/ArmBaseFinder）更可靠。
- 示例 basefind 输出中 `0x801FC0` 出现 73700 次，远高于其他候选，对应页对齐基址 0x801000；rebase 后跳转目标应落在函数开头，而不是函数中间。

## 触发条件

- 目标是 ARM/Thumb VxWorks 或其他 RTOS 固件，IDA 默认 0 基址加载。
- 反汇编中存在 switch 跳转表/函数指针表，表项为绝对地址。
- 能确定表项在文件中的偏移（IDA 地址 - 默认基址）。
- 有多个跳转表可用于交叉验证，或能运行 basefind/ArmBaseFinder。

## 利用步骤

1. `binwalk -A firmware.bin` 确认架构（ARM/Thumb、大小端）。
2. 在 IDA 中搜索 `switch`/`LDR PC`/`DCD`，找含绝对地址的跳转表。
3. 选一个表项，记录其运行时绝对地址与文件偏移，计算 `base_candidate = abs - offset`。
4. 按页对齐：`base = base_candidate & 0xFFF000`（页大小按架构，常见 0x1000）。
5. 用多个表项/多个跳转表重复，统计出现次数最多的候选；或用 basefind/ArmBaseFinder 自动扫描。
6. 在 IDA 中 `Edit -> Segments -> Rebase program` 输入基址，检查跳转目标是否落在函数开头。
7. 若仍有偏差，检查 Thumb 位、大小端、加载偏移、表项是否被加密/压缩。

## PoC

```python
# 单个跳转表候选基址
abs_addr = 0x8B2BE0
file_off = 0x0B0BEC
candidate = abs_addr - file_off          # 0x801FF4
base = candidate & 0xFFF000              # 0x801000
print(hex(candidate), hex(base))

# basefind 思路：扫描所有绝对地址表项，统计 (abs - offset) 频次
from collections import Counter
counts = Counter()
# for each table entry: counts[(abs_addr - file_off) & 0xFFFFF000] += 1
# best = counts.most_common(1)[0]
```

## 变体与关联

- 变体：Thumb 函数地址最低位为 1，计算时先清最低位；大小端按架构处理。
- 变体：跳转表可能是相对偏移（PC-relative），需要不同的基址推导。
- 变体：其他 RTOS（ThreadX、FreeRTOS、RT-Thread）也可能用绝对地址表，方法通用。
- 关联：[[code-analysis-reverse-firmware-vxworks-symbol-table-base]]（符号表法）、[[code-analysis-reverse-firmware-vxworks-base-sp-bss]]（SP/BSS 法）、[[code-analysis-reverse-firmware-stm32-hal-function-identification]]（固件函数识别）。

## 检测与防御

- 检测：固件中出现大量绝对地址表、IDA 默认基址下跳转异常。
- 防御：固件加载地址随机化/位置无关代码、压缩/加密固件、剥离符号；但无法完全阻止基址推断。
- 响应：若固件被提取分析，评估敏感逻辑/密钥泄露，升级固件保护。
