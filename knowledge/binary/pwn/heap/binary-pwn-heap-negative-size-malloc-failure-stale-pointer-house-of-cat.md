---
id: binary-pwn-heap-negative-size-malloc-failure-stale-pointer-house-of-cat
title: 负数 size 绕过长度检查导致 malloc 失败：保留悬垂指针的 UAF 与大堆 house of cat ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: negative-size-malloc-failure-stale-pointer-uaf-largebin-house-of-cat
aliases:
- easy_rw_revenge
- CISCN 2026
- 负数 size
- malloc 失败 UAF
- 悬垂指针
- house of cat
- _IO_list_all
- wide FILE ORW
- RC4 前端
tags:
- pwn
- heap
- uaf
- negative-size
- malloc-failure
- largebin-attack
- io-list-all
- house-of-cat
- orw
- seccomp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:25:06+08:00'
  notes: 已对照原文与图05/06/07/10核对：RC4 前端（srand(time)+32×rand()&0xff 生成 key）、MD5 PoW 目标 0x7C994FE632004064 截断爆破得 aaabUYkl、add 的 int size 负数绕过（size<=0x1000 有符号比较）导致 malloc 失败且原 heap 指针未覆盖形成 UAF、仅 >=0x500 大块可 UAF、show 泄 libc(0x21ace0)/heap、largebin attack 改 _IO_list_all、fake wide FILE 走 _IO_wfile_jumps+0x30→setcontext+0x3d、openat/read/write ORW 均与原文一致。注意点：正文“案例为 glibc 2.35 系列”为按偏移推断，原文未明确写版本，卡片未设 affected_versions。未验证点：无附件，PoC 未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

`add` 接口的 size 用有符号 `int` 校验，传入负数可以通过大小检查；`malloc` 收到转换后的超大 `size_t` 失败，但程序不检查返回值、也不覆盖原来的堆指针，留下悬垂指针形成 UAF；对 ≥0x500 的大块用 largebin attack 改写 `_IO_list_all`，伪造 wide FILE 经 `_IO_wfile_jumps+0x30` 到 `setcontext+0x3d`，在 seccomp 下执行 openat/read/write 读取 flag。

## 原理

- **负数 size 通过检查**：后端 `add` 的 size 参数是 `int`，校验逻辑按有符号数比较（如只检查上限）；传入 `-1` 等负值时比较通过。随后 `malloc(size)` 把负值转换成巨大的 `size_t`，分配失败。
- **失败路径留下悬垂指针**：程序没有检查 `malloc` 返回值，也没有在失败时清空该 index 原来的堆指针；原先的 chunk 仍被全局数组引用，但可能已在之前的 delete 中释放，于是形成 UAF。题目中只有 ≥0x500 的堆块能走到这条路径，因此 UAF 主要针对大块。
- **泄露**：对已释放的大块 `show`，可读出 unsorted/largebin 的 `fd`/`bk`，分别泄露 libc 与 heap 基址（案例 `main_arena` 偏移 `0x21ace0`）。
- **largebin attack 改 `_IO_list_all`**：把大块释放进 largebin，利用 `bk_nextsize` 写入 `_IO_list_all`（或 `_IO_list_all-0x20`），把 FILE 链表头指向堆上的 fake FILE。
- **house of cat / wide FILE**：伪造 `_flags`、`_mode=1`、`_wide_data`（`write_ptr > write_base`），主 vtable 设为 `_IO_wfile_jumps+0x30`，使 `exit` 时的 `_IO_flush_all_lockp` 走 wide FILE 路径并落到 `setcontext+0x3d`；该函数从 `rdx` 指向的堆上下文恢复 `rsp/rdi/rsi/rdx` 等寄存器，pivot 到堆上的 ORW 链。
- **ORW**：在 seccomp 只允许 `openat`/`read`/`write` 时，用 `openat(AT_FDCWD, "/flag", 0, ...)`、`read(fd, buf, len)`、`write(1, buf, len)` 读出 flag。
- **前端门禁**：题目前端用 RC4 加密协议，密钥由 `srand(time(NULL))` 后连续 32 次 `rand() & 0xff` 生成；客户端可用同一 libc 复现。登录后还需通过一个 MD5 PoW（目标哈希含 `\0` 字节，只需爆破部分前缀），案例解为 `aaabUYkl`，协议起始串为 `rtsp://aaabUYkl/`。
- 根因是“有符号 size 校验 + malloc 失败未处理 + 指针未清空”三者叠加；largebin/house of cat 只是把 UAF 转成控制流的后续手段。

## 触发条件

- 菜单式堆题，`add` 的 size 为有符号 `int`，校验只做单边比较或未拒绝负数。
- `malloc` 失败后程序不中止、不清空原指针，且该 index 的旧 chunk 已释放或可被释放。
- 只有较大 chunk（案例 ≥0x500）能进入该失败路径，或大块更容易构造 largebin。
- 有 `show` 可读已释放块内容，能泄露 libc/heap。
- 目标 glibc 存在 `_IO_list_all`、`_IO_wfile_jumps` 与 `setcontext`（案例为 glibc 2.35 系列），且程序退出时会走 `_IO_flush_all_lockp`。
- 前端若有加密/PoW，需要先复现密钥并通过校验。

## 利用步骤

1. 通过前端：用目标 libc 的 `srand(int(time.time()))` 和 32 次 `rand()&0xff` 生成 RC4 key，加密登录串取得 cookie；爆破 MD5 PoW 前缀（案例目标 `644000...`）得到 `aaabUYkl`，后续报文带 `rtsp://aaabUYkl/`。
2. 建立大块布局：连续 `add` 多个 0x510 chunk；用负数 size 的 `add(-1, idx)` 触发 `malloc` 失败，保留悬垂指针（案例的 `free2`）。
3. `show` 已释放块，泄露 libc（`main_arena+0x60`）与 heap。
4. 释放相邻大块进入 largebin，构造 fake chunk/`bk_nextsize`，在 largebin 插入时把 `_IO_list_all` 改写为堆上的 fake FILE 地址。
5. 在堆上布置 fake wide FILE（`_mode=1`、`_wide_data` 满足 flush 条件、vtable `_IO_wfile_jumps+0x30`）以及 `setcontext+0x3d` 的上下文和 ORW 链。
6. 触发 `delete`/`exit`，`_IO_flush_all_lockp` 命中 fake FILE，pivot 到 ORW，读取 `/flag`。

## PoC

```python
# 负数 size 触发 malloc 失败，保留悬垂指针
def free2(idx):
    s(tel("add", -1, idx, b''))   # size=-1 -> malloc 失败 -> 原指针未清空
    restart()

add(0, 0x510)
add(1, 0x510)
add(2, 0x510)
add(3, 0x510)
free2(0)
free2(2)
show(0)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
show(2)
heap = u64(p.recv(6).ljust(8, b'\x00'))
```

```python
# fake wide FILE（示意，偏移按目标 libc/结构）
fake = flat({
    0x00: b"/bin/sh\x00",
    0x08: p64(1),                       # wide->data->write_base and mode
    0x10: p64(heap_addr),               # write_ptr
    0x18: p64(libc.sym["setcontext"] + 0x3d),
    0x88: p64(fake_addr + 0x30),        # _lock
    0xa0: p64(fake_addr + 0x30),        # wide_data
    0xc0: p64(1),                       # mode
    0xc8: p64(libc.sym["_IO_wfile_jumps"] + 0x30),
    0x100: p64(fake_addr + 0x18),
}, filler=b"\x00")
```

```text
# ORW（openat/read/write）
openat(AT_FDCWD, "/flag", 0, 0)
read(fd, buf, 0x30)
write(1, buf, 0x30)
```

## 变体与关联

- 入口变体：负数 size 也可换成 `INT_MIN`、超大无符号数、整数乘法溢出等，使 `malloc` 失败或返回异常；关键是失败后指针未清空。
- 后续链变体：largebin attack 可打 `_IO_list_all`、`mp_`、`tcache_perthread_struct` 等；house of cat 可换成 free_hook/setcontext、栈 ROP 等。
- 前端变体：RC4 key 由 `srand(time)` 生成，若换成固定 key/弱随机，客户端同样可复现；MD5 PoW 若截断/含 NUL 字节，可缩小爆破空间。
- 关联：[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（同一条 largebin→_IO_list_all→wide FILE→setcontext→ORW 链，入口为 stale slot）、[[binary-pwn-heap-stale-slot-create-failure-uaf]]（另一种失败路径留下悬垂指针）、[[binary-pwn-heap-abs-intmin-length-bypass-bss-fake-chunk-tcache-got]]（有符号长度绕过）。

## 检测与防御

- 检测：菜单请求中出现负数/极大 size；`malloc` 失败后程序继续运行且该 index 仍可 `show`/`delete`；堆块被重复释放或出现 unsorted/largebin 元数据泄露；`_IO_list_all` 被改写、exit 时异常 flush。
- 防御：size 使用无符号类型并做上下界检查；检查 `malloc` 返回值，失败时清空指针并返回错误；delete 后立即把全局指针置 NULL（AWDP 修复：把有符号跳转 `jg` 改为无符号 `jnb`，拒绝负数）。
- 加固：开启 Full RELRO/PIE/Canary；seccomp 最小化；监控异常 size 与重复 free；对 FILE 结构/`_IO_list_all` 做完整性保护（高版本 glibc 的 vtable 校验）。
