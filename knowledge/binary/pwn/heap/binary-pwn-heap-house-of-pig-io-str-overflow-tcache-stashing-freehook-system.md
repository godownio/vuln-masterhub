---
id: binary-pwn-heap-house-of-pig-io-str-overflow-tcache-stashing-freehook-system
title: House of Pig（glibc 2.31–2.34）：largebin attack 改 _IO_list_all + tcache stashing unlink 植入 __free_hook-0x10 + _IO_str_overflow 的 malloc/memcpy 覆写 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-pig-io-str-overflow-tcache-stashing-freehook
aliases:
- House of Pig
- house_of_pig
- _IO_str_overflow 利用
- _IO_str_jumps
- tcache stashing unlink 结合 IO_FILE
- __free_hook system
- io_str_overflow new_size
tags:
- pwn
- heap
- glibc231
- glibc232
- glibc233
- glibc234
- house-of-pig
- io-file
- io-str-overflow
- io-str-jumps
- tcache-stashing-unlink
- largebin-attack
- free-hook
- ctf
cve: []
severity: high
confidence: high
status: verified
affected_versions: glibc 2.31–2.33（原文『使用版本 2.31-2.34』；但 __free_hook 在 2.34 已移除、只剩符号僵尸，本链 free_hook→system 步骤在 2.34+ 失效；largebin attack 一节原文标注 2.31-2.35）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:53:48+08:00'
  notes: 已对照原文与全部 23 图核对：01-04 largebin 2.31 中间插入分支（malloc.c 3841-3848 源码、victim/fwd/bck 关系、free chunk 0x430 的 bk_nextsize=0x7fff...e170、p2-2==target）；05-11 TSU/TSU+ demo（smallbin size 0x60 fd=0x602860 bk=target-0x10、malloc.c 3670-3673 bin->bk=bck/bck->fd=bin/tcache_put、calloc 触发后 tcache 0x60[7] 链入 victim、malloc 取回 victim 得 0xaa/0xbb/0xcc/0xdd）；12 _IO_str_overflow+53 mov rdx,[rdi+0x28]；13-15 TSU 执行前后（tcache 0x100[5]→[7] 链入 __free_hook-0x10、smallbin corrupted、target-0x10/target+8 检查）；16 _IO_flush_all_lockp+255 call [rax+0x18]=_IO_str_overflow（rax=_IO_str_jumps）；17-22 _flags/_IO_write_ptr/_IO_write_base 分支、old_blen=0x46→new_size=0xF0、malloc@plt(size 0xF0)、memcpy(new_buf=__free_hook-0x10, old_buf='/bin/sh', 0x46)、free@plt(old_buf)；23 exit→dash→whoami muxuechen 的 getshell 截图。卡内链路、字段偏移（_mode 0xC0、_IO_write_ptr 0x28、_IO_write_base 0x30、_IO_buf_base 0x38、_IO_buf_end 0x40、vtable 0xD8）与原文 demo 一致。\n【修正】原文『使用版本 2.31-2.34』，但 __free_hook 在 glibc 2.34 已被移除（只剩符号僵尸），本链 free_hook→system 落点在 2.34+ 失效；已将
    affected_versions 改为 2.31–2.33 并注明原文标注、__ 一句话结论/触发条件/防御中的『2.35 后移除』一并修正为 2.34 移除。\n未验证点：未编译/运行文章 demo（其使用模拟 libc/__free_hook 地址），实际偏移需按目标 libc；frontmatter 无 sources/source_url。kb show 存在；dedup 重跑无 duplicate（related 8），最高相关为 House of Orange/Storm/largebin-mp_.tcache_bins/2.35 Botcake+Apple2、2.35 fastbin-reverse-into-tcache 等，机制/版本/落点不同；dup-scan 中与 14889 两卡、14821 House of Husk 卡均判 related，非同一链，保留并列不删。卡为 House of Pig 具名组合链（单条完整利用链、所有原语为达成同一最终危害所必需），非并列多方法，未达过粗拆分标准。
---

## 一句话结论

House of Pig 在 glibc 2.31–2.33（原文标注使用版本 2.31–2.34；但 `__free_hook` 在 2.34 已被移除，本链依赖 free_hook 的落点在 2.34+ 失效）上把三条原语串成一条链：先用 largebin attack 把 `_IO_list_all` 改成堆地址并伪造 `_IO_FILE`（vtable 指向 `_IO_str_jumps`），同时用 tcache stashing unlink 把 `__free_hook-0x10` 处伪造的 chunk 塞进 tcache；调用 `exit()` 后 `_IO_flush_all_lockp` 走到 `_IO_str_overflow`，它按 `2*(_IO_buf_end - _IO_buf_base)+100` 调 `malloc` 取出预植的 tcache chunk，再用 `memcpy` 把攻击者缓冲区中的 `system` 地址写到 `__free_hook`、把 `/bin/sh` 写到其前，最后 `free(old_buf)` 经 `__free_hook` 调用 `system("/bin/sh")`。

## 原理

- **前置条件**（原文明确）：
  1. 能通过 largebin attack 或其他方式把 `_IO_list_all` 覆盖为堆地址，并在该堆上伪造 `_IO_FILE`；
  2. 程序存在 `calloc`（House of Pig 的 tcache stashing 环节需要 calloc 绕过 tcache 进入 `_int_malloc`，且 calloc 不会取走随后要留给 IO 链的 tcache chunk）；
  3. 存在 tcache stashing unlink 原语（能伪造 smallbin chunk 的 `bk`）。
- **glibc 2.31 largebin attack**：2.30 之后在 unsorted chunk 进入非空 largebin 时新增两项检查：
  ```c
  if (fwd->bk_nextsize->fd_nextsize != fwd) malloc_printerr("largebin double linked list corrupted (nextsize)");
  ...
  if (bck->fd != fwd) malloc_printerr("largebin double linked list corrupted (bk)");
  ```
  老的单点 `bk` 覆盖不再直接可用；走“插到比 largebin 最小心 chunk 还小”的分支：
  ```c
  victim->fd_nextsize = fwd->fd;
  victim->bk_nextsize = fwd->fd->bk_nextsize;
  fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
  ```
  若 `p2->bk_nextsize = target - 0x20`，则 `target - 0x20 + 0x10 = target` 处被写入 `victim`（堆 chunk 地址），即一次“向目标写堆指针”的任意写。原文 demo 用 `p1[3] = (&target)-4`、两个不同大小的 largebin/unsorted chunk 验证 `p2-2 == target`。
- **tcache stashing unlink（TSU）**：`_int_malloc` 从小 bin 取下最后一个 chunk 后，若 tcache 未满会循环把 smallbin 中剩余 chunk 塞进 tcache。循环里只检查 `tcache->counts` 和 `tc_victim != bin`，**没有对 `tc_victim->bk` 做双向链表完整性检查**：
  ```c
  bck = tc_victim->bk;
  ...
  bin->bk = bck;
  bck->fd = bin;          // 把 main_arena 中的 bin 地址写到 bck+0x10
  tcache_put(tc_victim, tc_idx);
  ```
  - TSU+：把第二个 smallbin chunk 的 `bk` 改成 `&target - 0x10`，并在 `&target + 8` 处放一个可写地址；当 smallbin 里还有可被当作 `last(bin)` 的假节点时，假 chunk 会被 `tcache_put` 进 tcache，之后 `malloc` 返回 `target`（任意分配）；同时 `bck->fd = bin` 向 `target` 写入一个 libc 地址（main_arena 附近）。
  - 原文强调被改 `bk` 的 chunk 的 **fd 不能改**，因此通常需要先泄漏堆地址。
  - 触发 TSU 要用 `calloc` 申请同 size：malloc 在 tcache 非空时会直接返回 tcache，无法进入 smallbin 的 stashing 逻辑；calloc 不会从 tcache 取块，因此能进入 `_int_malloc` 触发 stashing，同时也不会取走刚被塞入 tcache 的假 chunk。
- **`_IO_str_overflow`（glibc 2.31 源码）**：`exit → _IO_cleanup → _IO_flush_all_lockp` 会通过伪造 FILE 的 vtable 调用 `_IO_str_overflow`：
  ```c
  int _IO_str_overflow(FILE *fp, int c) {
    int flush_only = c == EOF;
    if (fp->_flags & _IO_NO_WRITES) return flush_only ? 0 : EOF;
    ...
    pos = fp->_IO_write_ptr - fp->_IO_write_base;
    if (pos >= (size_t)(_IO_blen(fp) + flush_only)) {
      if (fp->_flags & _IO_USER_BUF) return EOF;
      else {
        char *old_buf = fp->_IO_buf_base;
        size_t old_blen = _IO_blen(fp);              // _IO_buf_end - _IO_buf_base
        size_t new_size = 2 * old_blen + 100;        // 控制 malloc 的 size
        if (new_size < old_blen) return EOF;
        new_buf = malloc(new_size);
        ...
        if (old_buf) {
          memcpy(new_buf, old_buf, old_blen);        // 攻击者数据写入 new_buf
          free(old_buf);                             // 触发 __free_hook
          fp->_IO_buf_base = NULL;
        }
        ...
      }
    }
    ...
  }
  ```
  关键点：`_IO_buf_end - _IO_buf_base` 决定 `malloc` 大小；`_IO_write_ptr - _IO_write_base` 决定能否进入分支；`_flags` 必须为 0（不能带 `_IO_NO_WRITES`/`_IO_USER_BUF`）；`_IO_buf_base` 指向攻击者布置的 `"/bin/sh"+system` 缓冲区。
- **House of Pig 完整链路**：
  1. first largebin attack 把 `__free_hook-0x8`（TSU fake chunk 的检查字段）写成堆地址，满足 TSU 条件；
  2. 在 tcache 中放 5 个 size n 的块、smallbin 中放 2 个同 size 块，篡改第二个 smallbin chunk 的 `bk = __free_hook-0x20`；
  3. `calloc(n)` 触发 TSU：假 chunk（chunk2mem = `__free_hook-0x10`）被塞进 tcache，calloc 不会取走它；
  4. second largebin attack 把 `_IO_list_all` 改成堆地址，在该堆上伪造 FILE：`_flags=0`、`_IO_write_ptr` 取大值、`_IO_write_base=0`、`_IO_buf_base` 指向 `"/bin/sh"` 缓冲区、`_IO_buf_end = buf_base + 0x46`（使 `new_size=0xF0`）、`_mode=0`、`vtable = _IO_str_jumps`；
  5. `exit()`：`_IO_flush_all_lockp → _IO_str_overflow → malloc(0xF0)` 取出 tcache 中的 `__free_hook-0x10`，`memcpy` 把缓冲区内容搬到 `__free_hook-0x10`（`system` 落在 `__free_hook`），随后 `free(old_buf)` 调用 `system(old_buf)`（old_buf = 缓冲区开头 `"/bin/sh"`）→ shell。

## 触发条件

- glibc 2.31–2.33 可用（`__free_hook` 在 2.34 已被移除、只剩符号僵尸，2.34+ 需把落点换成 House of Apple 等新链；原文标题写『使用版本 2.31-2.34』，实际以目标 libc 是否仍调用 `__free_hook` 为准）。
- 堆题具备 UAF/堆溢出/任意写，能制造 largebin 与 tcache/smallbin 的所需布局，并能泄漏 libc 与 heap。
- 程序有 `calloc` 调用点（House of Pig 的 TSU/取块设计依赖它）。
- 有可触发 `exit()` 或 stdio flush 的路径；能控制 `_IO_list_all` 与伪造 FILE 堆块。
- 存在 tcache stashing unlink 可利用的 smallbin 结构（可改写 smallbin chunk 的 `bk`，且 fd 保持合法）。

## 利用步骤

1. 泄漏 libc 与 heap 基址（unsorted bin/largebin 残留、show 等），计算 `__free_hook`、`_IO_list_all`、`_IO_str_jumps`、`system`。
2. 构造 largebin/unsorted chunk，执行第一次 largebin attack，把堆地址写到 `__free_hook-0x8`，满足 TSU 假 chunk 的可写检查。
3. 准备 TSU：tcache 对应 size 放 5 块、smallbin 放 2 块；把第二个 smallbin chunk 的 `bk` 改为 `__free_hook-0x20`。
4. 用 `calloc` 申请同 size 触发 stashing，使假 chunk（用户指针 `__free_hook-0x10`）进入 tcache。
5. 执行第二次 largebin attack，把 `_IO_list_all` 覆盖为伪造 FILE 所在的堆地址。
6. 在伪造 FILE 中布置：`_flags=0`、`_IO_write_ptr` 大值、`_IO_write_base=0`、`_IO_buf_base` 指向含 `/bin/sh` 与 `system` 指针的缓冲区、`_IO_buf_end=buf_base+0x46`、`vtable=_IO_str_jumps`。
7. 调用 `exit()` 触发 flush → `_IO_str_overflow` 的 malloc/memcpy/free，经 `__free_hook` 执行 `system("/bin/sh")`。
8. 若目标使用 seccomp/无 execve，可在第 7 步改为 `__malloc_hook=setcontext+61` 的 SROP/ORW 变体（见变体）。

## PoC

以下为文章 demo 的关键布局（demo 用固定/模拟地址演示链路，实际需按目标 libc 与堆地址替换）：

```c
// 假 FILE（堆上 chunk_2）
size_t *fake_FILE = (size_t*)chunk_2;
fake_FILE[0xC0/8] = 0;              // _mode
fake_FILE[0x28/8] = 0xfffffffffff;  // _IO_write_ptr：保证 pos >= blen
fake_FILE[0x30/8] = 0;              // _IO_write_base
fake_FILE[0xD8/8] = libc_base + 0x1E9560; // vtable = _IO_str_jumps
fake_FILE[0x38/8] = chunk_1 + 0x20;       // _IO_buf_base：/bin/sh + system
fake_FILE[0x40/8] = chunk_1 + 0x20 + 0x46;// _IO_buf_end：old_blen=0x46，new_size=0xF0
strcpy((char*)(chunk_1 + 0x20), "/bin/sh");
*(size_t*)(chunk_1 + 0x20 + 0x10) = (size_t)system;

// TSU：smallbin 第二块 bk 指向 __free_hook-0x20
*(size_t*)((size_t)(chunks[8]) + 0x8) = __free_hook - 0x20;
calloc(1, 0xF0);   // 触发 stashing，假 chunk 进入 tcache 且 calloc 不取走

// largebin attack 覆盖 _IO_list_all 为 fake FILE 地址后
exit(-1);          // flush -> _IO_str_overflow -> malloc/memcpy/free -> system("/bin/sh")
```

## 变体与关联

- 变体（原文提到）：不覆盖 `__free_hook` 为 system，而是先把 `__malloc_hook` 设为 `setcontext+61`；`_IO_str_overflow` 在 `+0x53` 处有 `mov rdx, [rdi+0x28]`，可先控制 rdx，再让后续 `malloc` 触发 `setcontext+61` 做 SROP/ORW（适合 seccomp 禁 execve 的场景）。
- 变体：用 House of Apple2/wide FILE 等新 FSOP 链替代 `_IO_str_jumps` 路径（高版本 glibc 无 `__free_hook` 时）。
- 关联：[[binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks]]（本链第一步的 largebin 双写原语）；[[binary-pwn-heap-tcache-stashing-unlink-largebin-fake-chunk-arbitrary-write]]、[[binary-pwn-heap-tcache-stashing-unlink-plus-tcache-perthread-entries]]（TSU/TSU+ 基础）；[[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]、[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（其他 IO_FILE/FSOP 链，可对比触发与 vtable 选择）；[[binary-pwn-stack-srop-mprotect-openat-shellcode-seccomp]]（SROP 变体）。

## 检测与防御

- 版本/加固：升级到移除 `__free_hook` 的更现代 glibc（2.34 起移除 malloc/free hook，只剩符号僵尸；原文标注 2.31–2.34 需按实际 libc 复核），开启 safe-linking、tcache key、更多 malloc 完整性检查；生产程序开启 Full RELRO/PIE/canary 提高前置门槛。
- 代码审计：重点寻找 UAF/堆溢出后可写已释放 chunk 的 `bk`/`bk_nextsize`、可控制的 `calloc` size、`exit`/`fflush` 路径；检查 largebin 与 smallbin 的完整性校验是否被绕过。
- 检测：监控 `_IO_list_all` 被改写为堆地址、`__free_hook`/`__malloc_hook` 非空、vtable 指向 `_IO_str_jumps` 等异常；崩溃日志中出现 largebin/smallbin double linked list corrupted 可能是在试探。
- 防御：避免在高权限服务中使用可被任意写控的堆对象；对 IO_FILE 相关全局指针做只读保护（如 glibc 的 IO 加固）；使用现代分配器/隔离堆。
