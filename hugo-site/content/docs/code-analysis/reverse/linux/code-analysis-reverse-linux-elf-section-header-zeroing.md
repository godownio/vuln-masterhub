---
id: code-analysis-reverse-linux-elf-section-header-zeroing
title: ELF section header 清零仍可执行：双索引脱节造成的静态分析盲区
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: elf-section-header-zeroing-dual-index
tags:
- linux
- elf
- section-header
- program-header
- anti-analysis
- evasion
- file-format
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T19:41:53+08:00'
  notes: 已对照原文与37张图核对：e_shoff 偏移40、e_shnum 偏移60 清零、hello_nosec 仍输出 hello world、readelf -S 显示'本文件中没有节'、与 PT_NOTE 注入组合后 NOTE 一致性规则失效但程序头规则仍命中，均与原文一致；32位偏移说明正确。未验证点：PoC 未本机复跑；卡片属双视图分析盲区的通用技术总结，非独立攻击链。
url: /docs/code-analysis/reverse/linux/code-analysis-reverse-linux-elf-section-header-zeroing/
draft: false
kb_aliases:
- e_shoff 清零
- e_shnum 清零
- ELF 节表抹除
- section header 删除
- 双索引脱节
- ELF 双视图
---

## 一句话结论

ELF 内核加载器只读 program header，从不读 section header；把 ELF header 中的 `e_shoff`（偏移 40）和 `e_shnum`（偏移 60）清零后，section header table 从文件中“消失”，`readelf -S` 无节可列，但程序仍能正常运行——这使任何只依赖 section 视图的分析工具出现盲区，而 program header 仍完整描述真实加载行为。

## 原理

- **两套结构描述同一文件**：Section Header Table 由链接器/调试工具使用，列出 `.text`、`.data`、`.rodata`、`.note.*` 等 section 的名字、类型、位置与大小；Program Header Table 由内核 `execve` 使用，描述 `PT_LOAD`、`PT_DYNAMIC`、`PT_NOTE` 等 segment 的映射地址、文件偏移、权限与对齐。
- **加载路径不依赖 section**：内核在 `execve()` 中解析 ELF header 后，按 `e_phoff/e_phentsize/e_phnum` 遍历 program header，把 `PT_LOAD` 段 mmap 到内存并按 `p_flags` 设置权限，再把控制权交给 `e_entry`；整个流程不需要 section header。节表只是链接期/调试期元数据。
- **清零方法**：`e_shoff` 位于 ELF64 header 偏移 40（8 字节），`e_shnum` 位于偏移 60（2 字节）；将其置 0 即声明“没有 section header table”。`readelf -S` 会输出“本文件中没有节”，`objdump -h`、`gdb` 的 section 视图、`strip` 等也会受影响或失败。
- **为什么能成为对抗手段**：分析工具、AV/YARA 规则、人工审计往往从 section 名与 section 内容入手（例如看 `.text` 熵值、`.note.*` 是否存在、section 与 segment 是否一致）。清零 section header 后，这些工具看到的是“无节”或旧视图，而加载器执行的仍是 program header 描述的真实段；攻击者可以把恶意段藏在 program header 中，只清掉节表以降低被 section 型工具发现的概率。
- **与 PT_NOTE 劫持组合**：如果先做 PT_NOTE→PT_LOAD 注入，再把 `e_shoff/e_shnum` 清零，检测器中“NOTE section 数 > PT_NOTE 段数”的规则会失效；但依赖 program header 的规则（微型 LOAD 段、异常入口点、地址跳跃）仍然有效。
- **边界**：清零 section header 会破坏依赖节表的工具链（调试、符号化、部分链接/打包流程）；一些加固/校验工具会把“无节表”本身视为可疑；如果程序或 loader 运行期解析自身 section（少见），可能受影响。

## 触发条件

- 目标为 ELF 文件，攻击者能修改文件字节（分发阶段、构建产物、制品库等）。
- 分析方主要依赖 section header（`readelf -S`、`objdump -h`、部分 YARA/AV 规则）而不同时审计 program header。
- 目标不要求 section header 存在（大多数正常执行场景都不要求）；`strip` 后的二进制仍可保留 section header，清零是更彻底的做法。
- 若与注入组合，注入本身已改 program header，清零只是进一步降低 section 视图的可信度。

## 利用步骤

1. 读取 ELF header，确认是 64 位 ELF（`e_ident[4] == 2`）或按 32 位布局处理（32 位 `e_shoff` 偏移 32、`e_shnum` 偏移 48）。
2. 将 `e_shoff`（ELF64 偏移 40，8 字节）置 0，将 `e_shnum`（偏移 60，2 字节）置 0；可选同时把 `e_shstrndx`（偏移 62）置 0。
3. 写回文件并保持可执行权限；运行程序，确认行为不变、退出码不变。
4. 用 `readelf -S` 验证输出“本文件中没有节”；用 `readelf -l` 确认 program header 仍完整，`PT_LOAD`/入口点正常。
5. 若与 PT_NOTE 注入组合，先完成注入再清零 section header；检测时改用 program header 规则。

## PoC

原文验证代码（Python，仅用 `struct`）：

```python
import struct
d = bytearray(open('hello', 'rb').read())
struct.pack_into('<Q', d, 40, 0)   # e_shoff = 0
struct.pack_into('<H', d, 60, 0)   # e_shnum = 0
open('hello_nosec', 'wb').write(d)
```

```bash
chmod +x hello_nosec
./hello_nosec        # 仍输出 hello world
readelf -S hello_nosec  # 本文件中没有节。
```

原文观察：section header 被清零后程序照常运行；把同一操作应用到已注入 PT_NOTE 的文件后，检测器基于 NOTE section 数量的规则失效，但 `readelf -l` 仍能看到伪造的 LOAD 段与异常入口点。

## 变体与关联

- **仅清 `e_shoff`**：部分工具可能仍尝试按 `e_shnum` 读取而报错；同时清 `e_shoff/e_shnum` 最稳妥。
- **32 位 ELF**：`e_shoff` 在偏移 32（4 字节），`e_shnum` 在偏移 48（2 字节），`e_shstrndx` 在偏移 50。
- **保留 section header 但改名/改类型**：可欺骗基于 section 名的规则，但一致性检查仍可能发现；清零更彻底。
- **与注入组合**：PT_NOTE→PT_LOAD 注入见 [[code-analysis-reverse-linux-elf-pt-note-to-load-injection]]；对应检测规则见 [[defense-detection-elf-pt-note-hijack]]。
- **防御反向利用**：无节表本身可以作为可疑指标，但正常 `strip --strip-all` 也可能删除符号而保留节表；需要结合 program header 与文件来源判断。

## 检测与防御

- **不要只信 section 视图**：任何 ELF 完整性检查都应同时解析 program header，比较 section 与 segment 的一致性；对“无 section header”文件提高警惕。
- **program header 审计**：检查是否存在异常 `PT_LOAD`（微型、R+X、地址远离正常范围）、`e_entry` 是否落在正常代码段、PT_NOTE 数量与 `.note.*` section 是否匹配。
- **完整性校验**：IMA/EVM、代码签名、发布物哈希可发现任何字节修改；对分发链路做可复现构建与签名。
- **工具链加固**：在 CI/制品库中加入 `readelf -l` 解析与自定义规则，而不是仅运行 `file`/`readelf -S`；对“file 正常但 readelf -l 异常”的文件重点复核。
