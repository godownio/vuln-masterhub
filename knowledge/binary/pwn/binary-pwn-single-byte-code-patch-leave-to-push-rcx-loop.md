---
id: binary-pwn-single-byte-code-patch-leave-to-push-rcx-loop
title: 受限单字节代码写：把 leave 改成 push rcx; ret 形成循环 patch 并写入 shellcode
type: scenario
domain: binary
path: binary/pwn
technique: single-byte-code-patch-loop
aliases:
- transmutation
- 单字节 patch
- leave 改 push rcx
- 代码段自修改
- 循环写字节
tags:
- pwn
- self-modifying-code
- code-patch
- shellcode
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:40+08:00'
  notes: 已对照原文 transmutation 段核对：单字节写范围、leave→push rcx、改 lea 位移、jge→jo、shellcode 写入 main、恢复尾部偏移均与原文 exp 一致；未跑二进制。
---

## 一句话结论

程序只允许向 `[chall, main)` 写一个字节时，可把函数尾部 `leave; ret` 的 `leave`（0xC9）改成 `push rcx`（0x51），使 `ret` 跳到 `rcx` 指向的 `chall` 附近重新进入函数，把“一次写”变成“无限次写”；再改 `lea rcx` 位移跳过函数序言、把 `jge` 改成 `jo` 绕过上界检查，最后把 shellcode 逐字节写进 `main` 并恢复尾部即可执行。

## 原理

- 原始尾部 `leave; ret`：`leave` 等价于 `mov rsp,rbp; pop rbp`，`ret` 从栈弹返回地址。
- 把 `leave` 的 opcode 改成 `push rcx` 后，尾部变成 `push rcx; ret`：`ret` 弹出 `rcx` 作为返回地址。第一次执行时 `rcx` 正好指向 `chall` 附近，于是重新进入函数，获得下一次写机会。
- 若每次都从 `chall` 开头重新执行，会不断 `push rbp; mov rbp,rsp; sub rsp,...` 套娃；把 `lea rcx,[rip+disp32]` 的低字节位移改掉，让 `rcx` 指向函数中间已越过建栈的位置（如 `0x40114e`），即可稳定循环。
- 地址检查 `cmp ptr, main; jge fail` 只允许写 `main` 之前；把 `jge` 的 opcode 改成 `jo`（几乎不会成立），即可绕过上界，向 `main` 写。
- 有了无限次写 + 去边界，把 shellcode 逐字节写到 `main` 中 `call chall` 之后，最后恢复尾部 `leave; nop; ret`，让控制流正常返回到 shellcode。

## 触发条件

- 程序提供一次（或少量）任意地址单字节写，地址范围限制在一段代码区内。
- 尾部存在可改成 `push reg; ret` 的 `leave`，且寄存器指向可用的代码位置。
- 有可预测的 `main`/`chall` 地址或 PIE 泄露，能计算写入偏移。

## 利用步骤

1. 反汇编确认 `chall` 尾部 `leave; ret` 与地址检查 `jge fail`。
2. 第一次写：`leave` → `push rcx`，让函数结束后回到 `chall`。
3. 第二次写：改 `lea rcx` 位移低字节，使循环跳过函数序言，稳定复用同一栈帧。
4. 第三次写：`jge` → `jo`，绕过 `main` 上界。
5. 逐字节把 shellcode 写入 `main` 中 `call chall` 之后。
6. 恢复尾部为 `leave; nop; ret`，让程序返回到 shellcode，读取 flag。

## PoC

```python
# offsets relative to chall() start
OFF_LOOP_DISP_LOW = 0x26
OFF_JCC_OPCODE    = 0x30
OFF_TAIL_NOP      = 0x46
OFF_TAIL_LEAVE    = 0x47
OFF_MAIN_SHELL    = 0xAD

writes = [
    (0x51, OFF_TAIL_LEAVE),   # leave -> push rcx
    (0xDE, OFF_LOOP_DISP_LOW),# retarget rcx to 0x40114e
    (0x70, OFF_JCC_OPCODE),   # jge -> jo
]
for i, b in enumerate(shellcode):
    writes.append((b, OFF_MAIN_SHELL + i))
writes += [
    (0xC9, OFF_TAIL_NOP),     # nop -> leave (unwind)
    (0x70, OFF_JCC_OPCODE),   # one more loop iteration
    (0x90, OFF_TAIL_LEAVE),   # leave -> nop (restore tail)
]
payload = b''.join(bytes([b, off]) for b, off in writes)
```

## 变体与关联

- 尾部可改成 `push rsp; ret`、`pop rsp; ret`、`jmp rcx` 等其他单字节等价序列。
- 若只有一次写，可先改 `ret` 为 `jmp` 或利用 `call` 的返回地址。
- 关联：[[binary-pwn-elf-copy-relocation-writable-security-state]]（代码/数据段修改）、[[binary-pwn-setuid-got-plt-lazy-binding-hijack]]（GOT 劫持）。

## 检测与防御

- 启用 W^X、代码完整性/CFI，禁止代码段可写。
- 检测：代码段出现单字节修改、`leave`/`ret` 附近异常 opcode、进程执行自修改代码。
- 加固：ASLR/PIE、只读代码段、控制流保护。
