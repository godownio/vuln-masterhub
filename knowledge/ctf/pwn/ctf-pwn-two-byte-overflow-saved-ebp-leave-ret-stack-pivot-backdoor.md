---
id: ctf-pwn-two-byte-overflow-saved-ebp-leave-ret-stack-pivot-backdoor
title: 只溢出 2 字节却已泄露栈地址：改 saved ebp 低位 + 后续 leave;ret 把栈迁回缓冲区，再跳后门拿 shell
type: scenario
domain: ctf
path: ctf/pwn
technique: two-byte-overflow-saved-ebp-leave-ret-pivot-backdoor
aliases:
- 两字节溢出
- saved ebp 低位覆盖
- leave ret 栈迁移回 buf
- 泄露栈地址后改 ebp
- ret2backdoor 32 位
tags:
- pwn
- stack
- partial-overwrite
- saved-ebp
- stack-pivot
- leave-ret
- i386
- ctf
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:56:43+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文称 vuln 存在两个字节溢出并打印 buf 地址、且给了后门与 /bin/sh，但给出的 exp 实际写 pay=p32(0x080484A0)+p32(0x0804A038)*2 后 ljust(0x50) 再拼完整的 p32(stack)+p32(0x080485FA)（总长 0x58，即写满 saved ebp 与返回地址 8 字节），与卡内「只能摸到 saved ebp 最低 2 字节、PoC 用 p32(stack)[:2]」冲突；0x080485FA 究竟是 leave;ret 还是别的指令原文亦未说明，需按二进制核对 read 长度与栈布局后修正触发条件与 PoC
---

## 一句话结论

当 `read` 只比缓冲区多读 2 字节、但程序把 `buf` 的地址直接打印给你时，这 2 字节就够把 saved `ebp` 的低 16 位改成 `buf` 的地址；函数（或调用者）尾声的 `leave; ret` 于是把 `esp` 迁到 `buf`，从缓冲区里预先放好的伪栈帧继续执行——配合二进制里自带的 `/bin/sh` 字符串与后门函数，2 字节溢出就足以拿 shell。

## 原理

- **溢出只够改 2 字节**：`char buf[N]` 之后 `read(0, buf, N + 2)`，只能摸到 saved `ebp` 的最低 2 字节，返回地址完全碰不到。这种"半残"溢出单独看没用。
- **但栈地址已被泄露**：程序把 `buf` 的地址打印出来（本例 `You will input this: 0x...`），攻击者于是知道 `buf` 的完整地址；把它低 16 位替换到 saved `ebp` 上，`ebp` 就指向缓冲区（32 位进程栈空间小，同页概率高，且末尾 2 字节可直接从泄露值取）。
- **`leave; ret` 是天然的栈迁移**：`leave` = `mov esp, ebp; pop ebp`，`ret` = `pop eip`。`ebp` 一旦被改成 `buf`，`leave` 让 `esp = buf`，随后 `pop ebp` 吃掉 `buf[0..3]`，`ret` 从 `buf[4..7]` 取下一跳——完全落在攻击者写好的数据上。
- **伪栈帧省掉了二次读入**：既然 `ret` 的落点来自 `buf`，就可以在 `buf` 开头按顺序摆好「目标函数地址 / 参数指针」，无需再 `read` 一次构造长 ROP；本例二进制里同时给了后门函数与 `/bin/sh` 字符串，因此一步到位。
- **前置门槛是登录**：进入 `vuln` 前要过 `username/password` 校验，本例为可静态审计得到的硬编码凭据，不属于本题难点。

## 触发条件

- 32 位程序（`ebp` 仅 4 字节，改 2 字节即可命中栈地址）；64 位下需改 2～3 字节且依赖栈地址低位稳定。
- `read`/`recv` 的长度恰好 = 缓冲区大小 + 2（或略多，但只够到 saved `ebp`）。
- 程序泄露了栈上缓冲区地址，或泄露值与该缓冲区关系可推算。
- 函数或用其调用者的尾声存在 `leave; ret`（`-O0`、未开 `-fomit-frame-pointer`）。
- 二进制内含后门函数与 `/bin/sh` 字符串，或可用 `system@plt` + 已知字符串。

## 利用步骤

1. 逆向确认三件事：`read` 长度 = `buf` 大小 + 2；`buf` 地址被打印；尾声是 `leave; ret`。
2. 顺带确认后门函数地址与 `/bin/sh` 字符串地址（`strings -tx` / IDA 交叉引用）。
3. 先过登录校验（硬编码凭据或按相关卡逐字符爆破）。
4. 收下泄露的栈地址，取低 2 字节作为 saved `ebp` 的覆盖值。
5. 构造 payload：`[伪栈帧（目标函数地址 + 参数）][填充到 buf 大小][saved ebp 低 2 字节]`，发送长度严格等于 `read` 请求的长度。
6. 函数返回后 `leave; ret` 迁栈到 `buf`，随即跳入后门、参数指向 `/bin/sh`。

## PoC

```python
from pwn import *
elf = ELF('./short')
p = process(elf.path)

sla(b'Enter your username: ', b'admin')
sla(b'Enter your password: ', b'admin123')

backdoor = 0x080484A0          # 后门函数
binsh    = 0x0804A038          # 二进制内置 /bin/sh 字符串

p.recvuntil(b'You will input this: ')
stack = int(p.recv(10), 16)     # 泄露的缓冲区地址

pay  = p32(backdoor) + p32(binsh) + p32(binsh)   # 迁移后落地的伪栈帧
pay  = pay.ljust(0x50, b'\x00')                  # 填满 buf
pay += p32(stack)[:2]                            # 只改 saved ebp 低 2 字节
p.sendafter(b'your msg:\n', pay)                 # 发送长度须与 read 请求一致
p.interactive()
```

注：原文 exp 在填充后写的是完整的 `p32(stack) + p32(0x080485FA)`，即除 saved `ebp` 外还压了一个跳转地址；哪一条指令是 `leave;ret`、`0x080485FA` 具体是什么，需按二进制核对（本篇未读图，未逐条验证）。

## 变体与关联

- 变体：泄露的是 `saved ebp` 本身或 `argv` 指针时可直接算出栈地址，改 2 字节命中率更高。
- 变体：64 位下改 saved `rbp` 的低 2～3 字节，栈随机化只影响高位，页内偏移稳定，命中率同样很高。
- 变体：没有后门时把伪栈帧写成 `read@plt` 二次读入 + `leave;ret` 递归迁移，即经典栈迁移 ret2libc。
- 关联：[[binary-pwn-stack-pivot-leave-ret-bss]]（迁到 bss 的同类手法）、[[ctf-pwn-onebyte-ret-overwrite-backdoor-system]]（只改返回地址低字节直跳后门，比本卡更短）、[[binary-pwn-stack-32bit-srop-read-return-sigreturn]]（32 位迁移后走 SROP）。
- 边界：`read` 长度若严格等于 `buf` 大小、或改用 `fgets`/`scanf("%s")` 限制长度，该原语不存在；开启 `-fstack-protector` 且溢出能摸到 canary 时会先崩。

## 检测与防御

- 检测（CTF/审计）：`read(fd, buf, sizeof(buf) + n)`；把栈缓冲区地址经 `printf("%p")` 输出给用户；`-O0` 生成的 `leave; ret` 尾声。
- 修复：`read` 长度严格用 `sizeof(buf)`；不向用户泄露栈/堆指针；开启 `-fstack-protector-strong` 与 PIE/ASLR。
- 加固：不把后门函数与 `/bin/sh` 编进生产二进制；用 seccomp 与 `execve` 白名单限制 shell。
