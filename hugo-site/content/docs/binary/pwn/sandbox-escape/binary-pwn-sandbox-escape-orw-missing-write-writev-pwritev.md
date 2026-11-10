---
id: binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev
title: ORW 缺 write：用 writev/pwritev/pwritev2/pwrite64 等系统调用替代 write 输出 flag
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: orw-missing-write-syscall-substitution
tags:
- binary
- pwn
- shellcode
- orw
- seccomp
- sandbox-escape
- writev
- pwritev
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:35:34+08:00'
  notes: 已对照原文（无图片）核对：ORW缺W列出pwrite64 0x12、writev、逐位爆破、pwritev/pwritev2；卡内系统调用号writev=20、pwrite64=18、pwritev=296、pwritev2=328与调用约定正确，pwrite*需可seek fd的边界说明合理。原文未给writev完整shellcode，卡内如实标注无PoC。未验证点：未编写/运行shellcode。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-orw-missing-write-writev-pwritev/
draft: false
kb_aliases:
- ORW 缺 W
- seccomp 禁 write 输出
- writev 替代 write
- pwritev pwritev2
- pwrite64 写文件
- ORW 系统调用替代
---

## 一句话结论

当 seccomp 只禁 `write`（x86-64 号 1）而没有同时禁止其它输出接口时，可用 `writev`(20)、`pwritev`(296)、`pwritev2`(328) 或 `pwrite64`(18) 这些系统调用号不同的等价接口把已读入的 flag 送出；其中向 socket/stdout 输出以 `writev` 最稳，`pwrite64` 只适合可 seek 的普通文件 fd（socket/管道会返回 `ESPIPE`）。

## 原理

- **按调用号过滤的盲区**：seccomp BPF 常见写法是 `if (sys_number == 1) KILL`，它只认 `write` 这一个编号。`writev` 用分散/聚集 I/O 把多个 `iovec` 写出，`pwritev`/`pwritev2` 是带偏移的向量写，`pwrite64` 是带偏移的单缓冲区写——语义上都能把数据写到指定 fd，编号却不同。
- **writev 的调用约定**：`ssize_t writev(int fd, const struct iovec *iov, int iovcnt)`，x86-64 号 20；`struct iovec { void *iov_base; size_t iov_len; }`。只需在内存里布置一个 iovec 指向已读入的缓冲区，再 `writev(1, iov, 1)` 即可输出到 stdout/socket。
- **pwrite 系列的适用面**：`pwrite64(fd, buf, count, offset)`（号 18）直接在指定偏移写；`pwritev`(296)/`pwritev2`(328) 在 `r10` 传偏移。它们要求 fd 可 seek；对管道/TTY 会 `ESPIPE`，因此除非 fd 1 已被重定向到普通文件，否则向 stdout/socket 输出应优先选 `writev`。
- **为什么成立**：`write` 与 `writev` 在内核里最终都走到文件/socket 的写路径，seccomp 在系统调用入口按编号放行/拒绝，无法理解语义等价。只禁 `write` 等于只堵了一个入口。
- **边界**：若题目禁的是“输出能力”而非单个编号（例如把 `write`/`writev`/`sendfile`/`splice` 全部封死），则本节方法失效，只能退化为侧信道爆破（逐字节比较 + 进程挂起/退出/耗时差异），该场景已有专门卡片；此外 `writev` 的 `iovcnt` 上限与 iovec 需在可写可读内存中，shellcode 里常用栈布置。

## 触发条件

- 用户可执行 shellcode，且 flag 已经（或能够通过 `open`/`read`）读入可控缓冲区。
- seccomp 禁用 `write`，但 `writev`（或 `pwritev`/`pwritev2`/`pwrite64`）未被禁。
- 输出端 fd 1 可用；`writev` 可作用于 socket；`pwrite64` 需要 fd 1 是可 seek 的普通文件。
- 攻击者能先确认过滤器实际规则，而不是只凭题目描述猜测。

## 利用步骤

1. `seccomp-tools dump` 或读 BPF，确认 `write`=1 被禁，同时 `writev`=20 / `pwritev`=296 / `pwritev2`=328 / `pwrite64`=18 中至少一个被放行。
2. 用 `open`+`read`（或其替代接口）把 flag 读到栈/固定缓冲区。
3. 在可写内存布置 `struct iovec`：`iov_base = buf_addr`、`iov_len = 0x100`。
4. 调用 `writev(1, iov, 1)`；若目标 fd 1 是普通文件且 `pwrite64` 可用，也可 `pwrite64(1, buf, 0x100, 0)`。
5. 检查输出；若返回 `ESPIPE`，说明 fd 不可 seek，改用 `writev` 或 `sendfile`（若放行）。
6. 若所有输出接口都被禁，转侧信道方案（比较字节后用挂起/退出/耗时区分）。

## PoC

无 PoC（原文“ORW 缺 W”一节只给出系统调用清单与编号：`pwrite64` 号 0x12、`writev`、`pwritev`、`pwritev2`，并另给逐字节爆破脚本；未给出 writev 的完整 shellcode）。可套用的调用约定：

```text
writev(1, iov, 1)                 x86-64 号 20
  struct iovec iov = { buf, len };
  rax=20, rdi=1, rsi=&iov, rdx=1, syscall

pwrite64(1, buf, len, 0)          x86-64 号 18 (0x12)
  rax=18, rdi=1, rsi=buf, rdx=len, r10=0, syscall

pwritev(1, iov, 1, 0)             x86-64 号 296
pwritev2(1, iov, 1, 0, 0)         x86-64 号 328
```

说明：`pwrite64` 对 socket/管道返回 `ESPIPE`，仅当 fd 1 指向可 seek 文件时可用；`writev` 对 socket 与普通文件均适用。原文的逐字节爆破脚本属于另一种场景，已由现有卡片覆盖，不在本卡重复。

## 变体与关联

- **fd 号限制型绕过**：seccomp 放行 `write` 但只允许 fd 1/2 时，可用 `fcntl(F_DUPFD)`/`dup2` 把任意文件 fd 复制到 1 再写；这与本卡的“换系统调用号”不同，见 [[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]。
- **零拷贝输出**：`sendfile(1, fd, NULL, len)` 或 `pipe`+`splice` 可在不经过用户缓冲区的情况下把文件送到 fd；若 `write`/`writev` 均被禁而它们放行，优先用零拷贝。
- **全部输出被禁**：退化为 `cmp`+挂起/退出/耗时 oracle 的逐字节爆破，见 [[binary-pwn-sandbox-escape-orw-flag-byte-bruteforce-time-clean-oracle]] 与 [[binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle]]。
- **读也被禁**：见 [[binary-pwn-sandbox-escape-orw-missing-read-sendfile-preadv-mmap]]。
- **关联**：[[binary-pwn-sandbox-escape-chroot-openat-fd-exit-status-sidechannel]]（用 `exit(status)` 低 8 位逐字节回显的等价侧信道）。

## 检测与防御

- **检测（出题/防守）**：seccomp 策略审计时把输出能力成组检查：`write`、`writev`、`pwrite64`、`pwritev`、`pwritev2`、`sendfile`、`splice` 是否都按设计限制；运行时若看到 `writev`/`pwritev` 等不常见调用携带文件内容发往 socket，应告警。
- **防御**：白名单只允许必要的输出调用，并配合 fd 参数与目标对象检查（seccomp user notification、Landlock、只读文件系统）；不要假设禁掉 `write` 就禁掉了写出。
- **边界**：`pwrite*` 的偏移参数在 `r10`（第 4 个参数），shellcode 编写时容易写错寄存器。
