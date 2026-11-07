---
id: code-analysis-reverse-linux-elf-note-ifunc-policy-tamper
title: 篡改 ELF .note.gnu.property 改变依赖该 note 的 IFUNC 分派
type: scenario
domain: code-analysis
path: code-analysis/reverse/linux
technique: elf-note-ifunc-policy-tamper
aliases:
- GNU property note 篡改
- .note.gnu.property IFUNC
- IFUNC 分派篡改
- .text 哈希绕过
- ELF 元数据投毒
tags:
- linux
- elf
- ifunc
- gnu-property
- note
- cet
- ibt
- shstk
- integrity-check
- supply-chain
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V96
  verified_at: '2026-11-05T19:59:41+08:00'
  notes: 已对照原文与21张图片核对；glibc 2.42/gcc 15.2.0环境、IBT/SHSTK note、R_X86_64_IRELATIVE addend 0x11c0、probe_value(1)由21变11、.text SHA-256一致、整文件哈希不同、__builtin_cpu_supports修复版不受影响均有截图/正文支撑；PoC未在本机复跑。
---

## 一句话结论

如果 IFUNC resolver 把 ELF 的 `.note.gnu.property` 当作运行期策略输入（例如按 IBT/SHSTK 位选择不同实现），攻击者只需修改 note 中的 4 字节 feature bitmask，就能在不改动 `.text`、`.text` 哈希完全一致的情况下改变 IFUNC 的分派结果；该手法仅对显式依赖该 note 的 resolver 成立，不是通用的 IFUNC 劫持。

## 原理

- 动态加载器的启动顺序是：映射 ELF → 解析 `PT_GNU_PROPERTY`（文件中通常为 `.note.gnu.property`）→ 处理动态重定位 → 调用 IFUNC resolver（`R_X86_64_IRELATIVE` / `STT_GNU_IFUNC`）→ 将返回的最终地址写入 GOT/调用点 → 执行 constructor → 进入 `main`。note 在 resolver 之前已被加载器消费。
- `.note.gnu.property` 的 note 记录由 `Elf64_Nhdr`（`n_namesz`/`n_descsz`/`n_type`）、按 4 字节对齐的 name（`GNU\0`）和 desc 组成；desc 是一组 property entry：`pr_type`、`pr_datasz`、`pr_data`，entry 之间按 8 字节对齐。x86_64 CET 相关属性为 `GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002`，`IBT = 0x1`、`SHSTK = 0x2`。
- 用 `-fcf-protection=full -Wl,-z,ibt -Wl,-z,shstk` 编译会让 ELF 携带该 note，`readelf -n` 显示 `x86 feature: IBT, SHSTK`。
- 若 resolver 通过 `__ehdr_start` + `PT_NOTE` 自行解析该 note 并据此返回不同实现，note 就从“描述性元数据”变成了“可篡改的策略输入”。修改 feature bitmask 不改变 `.text` 任何字节，因此只校验代码段哈希的完整性检查无法发现；整个 ELF 文件哈希会变化，完整文件校验可以发现。
- 该问题的根因是把可修改的 ELF 元数据当成可信运行期策略输入，而不是 IFUNC 机制本身。普通不读取 note 的 resolver 不会受此影响。

## 触发条件

1. ELF 含 `PT_NOTE`，`.note.gnu.property` 被映射到进程地址空间；
2. 二进制中存在 IFUNC 符号或 `R_X86_64_IRELATIVE` 重定位；
3. resolver 直接读取 note，或间接依赖加载器基于 note 形成的状态来选择实现；
4. note 数据位于可修改区域，且缺少签名、哈希或包管理校验；
5. 修改后的 note 仍保持合法 ELF note 格式，加载器不会拒绝装载。

## 利用步骤

1. 编译带 CET 标记和 IFUNC 的样本，确认 note 与重定位：`readelf -n` 看到 IBT/SHSTK，`readelf -rW` 看到 `R_X86_64_IRELATIVE`，其 addend 等于 resolver 地址。
2. 编写 resolver：解析自身 `PT_NOTE` 中的 `GNU_PROPERTY_X86_FEATURE_1_AND`，当 IBT|SHSTK 同时存在时返回 hardened 实现，否则返回 legacy 实现。
3. 用脚本定位 `.note.gnu.property`，遍历 note 与 property entry，只覆盖 feature entry 的 4 字节 bitmask（如从 `0x3` 改为 `0x0`），不重写 ELF 结构。
4. 运行原始与修改后的文件：resolver 分派结果改变（示例返回值从 21 变为 11）。
5. 用 `objcopy --dump-section .text=...` 分别导出两个文件的 `.text`，比较 SHA-256 与 `cmp`，确认完全一致；再比较整文件哈希，确认整文件已变化。
6. 供应链场景中，攻击者可在文件级篡改后保持 `.text` 校验通过，改变依赖 note 的实现选择；防御方必须校验完整文件或签名。

## PoC

resolver 读取 note 的关键逻辑（省略完整解析函数）：

```c
uint32_t f = read_feature_1_and_from_loaded_notes();   // 解析 PT_NOTE/.note.gnu.property
if ((f & (IBT | SHSTK)) == (IBT | SHSTK)) return cet_marked_impl;
return legacy_impl;
```

只改 note 的 4 字节 bitmask：

```python
# 定位 .note.gnu.property，遍历 Nhdr 与 property entry
# 命中 pr_type == 0xc0000002 且 pr_datasz >= 4 时：
struct.pack_into("<I", buf, data_off, 0)   # 0x3 -> 0x0，.text 不变
```

验证：

```bash
python3 patch_gnu_property.py ifunc_note_demo ifunc_note_clear --set-feature 0
./ifunc_note_demo        # probe_value(1)=21
./ifunc_note_clear       # probe_value(1)=11
objcopy --dump-section .text=base.text ifunc_note_demo
objcopy --dump-section .text=clear.text ifunc_note_clear
sha256sum base.text clear.text   # 两个 .text 哈希一致
sha256sum ifunc_note_demo ifunc_note_clear   # 整文件哈希不同
```

对照修复：把 resolver 改为 `__builtin_cpu_init()` + `__builtin_cpu_supports("sse2")` 选择实现，不再读取 note；再次清零 note 后返回值不变。

## 变体与关联

- 若 resolver 依赖加载器基于 note 形成的状态（例如 CET 相关分支），也可能受同类元数据篡改影响；关键仍是 resolver 是否把 note 当策略输入。
- 普通 IFUNC 劫持（同名 IFUNC + `LD_PRELOAD`）是另一条链：走符号搜索顺序覆盖并执行攻击者 resolver，与本卡的“note 篡改改变 resolver 决策”不同。
- 关联：IFUNC 符号注入、IFUNC resolver 早于 constructor 的时序绕过、供应链文件完整性校验、只校验 `.text` 的检测盲区。
- 边界：单独修改 `.note.gnu.property` 不会自动改变任意 IFUNC resolver 的优先级；必须存在 resolver 对 note 的依赖。

## 检测与防御

- 完整性校验必须覆盖整个 ELF 文件或使用签名，不能只比较 `.text` 段哈希；`.note.gnu.property` 等元数据同样属于可信计算基。
- resolver 不应读取 `.note.gnu.property` 作为运行期分支策略；CPU 能力判断应使用 `__builtin_cpu_supports`、CPUID 等受控来源，或固定构建参数。
- CI 中检查 CET 属性与 IFUNC 使用情况：`readelf -n`、`readelf -rW`、`readelf -Ws` 交叉核对 note、IRELATIVE 与 IFUNC 符号。
- 审计 resolver 是否解析 ELF 头/PT_NOTE，以及是否存在“note 位决定实现选择”的逻辑；对发布产物做整文件哈希与签名校验。
