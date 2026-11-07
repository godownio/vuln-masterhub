---
id: binary-pwn-stack-tls-ssl-struct-overwrite-32bit-pie-heap-spray
title: 32 位 PIE 无限堆分配占位 + TLS 栈溢出覆写 SSL 结构体函数指针
type: scenario
domain: binary
path: binary/pwn/stack
technique: tls-ssl-struct-overwrite-32bit-pie-heap-spray
aliases:
- TLS 栈溢出
- SSL 结构体覆写
- ssl_accept 函数指针
- 32 位 PIE 堆喷
- 固定地址堆占位
- easy cgi echo server
tags:
- pwn
- stack-overflow
- tls
- ssl
- 32bit
- pie
- heap-spray
- rop
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T10:19:31+08:00'
  notes: V166 指出的入库/CVE 归属问题已修复并重新 verify
---

## 一句话结论

32 位 PIE 服务提供无限堆分配时，攻击者可以用大量 `mmap`/堆块按 4KB 页把低 4GB 中的大段地址空间“喷满”，把伪造的 SSL 结构体和 ROP 链放到固定地址；TLS 监听路径的栈溢出可以覆盖栈上的 SSL 结构体，`ssl_accept` 随后调用结构体内的函数指针，控制流跳到 ROP，`mprotect` 后执行 shellcode。

## 原理

- **32 位地址空间有限**：PIE 只随机化模块基址，堆/mmap 区域仍落在低 4GB；程序提供“无限堆分配”时，攻击者可以按页申请并填充大量内存，使某个固定地址（示例 `0x7a7a7070`）几乎必然被自己的数据覆盖。即使不知道 PIE 基址，也可以按页喷满候选范围（示例 `0xf7000000`–`0xf7fff000`），提高命中率。
- **TLS 栈溢出**：TLS 服务在握手/记录解析时把长度来自客户端的数据读入栈缓冲区，长度未校验导致溢出；溢出的目标正好覆盖同栈帧中的 SSL 结构体（或 SSL 结构体指针指向的栈内存）。`ssl_accept` 在后续握手阶段会通过 SSL 结构体的函数指针表/回调调用，攻击者用伪造指针替换即可劫持控制流。
- **伪造 SSL + ROP**：攻击者构造 `fake_ssl`：填充到函数指针偏移，写入按猜测 PIE 重定位的 gadget/函数地址；后面接 ROP 链。ROP 先 `mprotect(0x7a7a7000, 0x1000, RWX)`，再跳入位于固定地址的 shellcode；shellcode 执行 `chmod`/`cat` 把 flag 写到可读取的位置。
- **为什么用堆喷而不是泄露**：32 位 PIE 爆破成本高，但“无限分配 + 固定地址”把概率问题变成必然：只要喷的页数覆盖目标地址，服务端分配/写入的数据就会落在攻击者指定的地址，fake SSL 的地址不再依赖泄露。
- **PIE 猜测**：示例对每个候选 PIE 基址生成一份 fake_ssl（函数指针按 `guess_pie` 重定位），逐页发送；服务端把每页写到固定地址，TLS 连接时使用最后/命中的那份；如果 PIE 猜错，函数指针无效会崩溃，需重试/换候选。

## 触发条件

- 32 位 PIE 服务（或地址空间受限的 64 位服务）提供大量可控堆分配/写入，能把数据放到固定地址。
- TLS/SSL 握手路径存在栈溢出，且溢出能覆盖 SSL 结构体或其中的函数指针；`ssl_accept` 在溢出后仍会调用该指针。
- 攻击者可反复连接/触发，允许按页喷满候选地址范围；目标有可执行内存或能 ROP 调 `mprotect`。
- 服务只运行一次或崩溃后可重启（示例题目“只能运行一次”，需一次命中）。

## 利用步骤

1. **确定固定目标地址**：选择一个堆/mmap 常落、且不与关键结构冲突的地址（示例 `0x7a7a7070`），准备把 fake SSL/ROP 放这里。
2. **构造 fake SSL/ROP**：按目标 SSL 结构体布局填充，覆盖函数指针槽位；ROP 链做 `mprotect(target_page, 0x1000, 7)` 后跳到 shellcode。对每个 PIE 猜测生成一份重定位后的副本。
3. **堆喷占位**：通过控制协议创建大量记录（示例 `NEW_CL` 分配 0x20010 字节、`ACTION` 触发），把内存填到目标地址附近；再逐页发送 `build_page(guess_pie)`，每页 0x1000 字节，覆盖候选 PIE 范围。
4. **触发 TLS 栈溢出**：连接 TLS 监听端口，发送构造的 TLS 记录/长度，使 `read` 溢出 SSL 结构体；`ssl_accept` 调用被替换的函数指针。
5. **ROP 执行 shellcode**：`mprotect` 把固定页改为 RWX，跳入 shellcode；shellcode 执行 `chmod 777 /tmp/flag`/把 flag 写入可下载文件。
6. **取回结果**：通过应用的留言/文件读取功能读取命令输出。

## PoC

```python
def build_page(guess_pie):
    fake_ssl  = p32(0x001ed109 + guess_pie) + b"\x00" * (0x70 - 4)
    fake_ssl += p32(0x002c07f5 + guess_pie)
    fake_ssl += p32(0x00528D10 + guess_pie - 0x34)
    fake_ssl += p32(0x61616161) * 2
    fake_ssl += p32(0xdeadbeef) * 2
    fake_ssl += p32(guess_pie + 0x0030a8db)
    fake_ssl  = fake_ssl.ljust(0x174, b"\xff")

    rop  = p32(0x00027031 + guess_pie) + p32(0x7a7a7000)
    rop += p32(0x002ab982 + guess_pie) + p32(0x00001000)
    rop += p32(0x001cc393 + guess_pie) + p32(0x00000007)
    rop += p32(0x0014493a + guess_pie) + p32(0x0000007d)
    rop += p32(0x002e0610 + guess_pie) + p32(0x00071366 + guess_pie)
    rop += b"\x81\xec\x00\x01\x00\x00..."          # shellcode: chmod/cat flag
    return (fake_ssl + rop).ljust(0x1000, b"\x00")

# 喷满候选 PIE 范围，每页写到固定地址
for i in range(guess_start + 0x21000, guess_end, 0x1000):
    s.sendall(build_page(i))

# 触发 TLS 栈溢出
tls_connect_and_recv("127.0.0.1", listener_port)
```

示例的 PIE/栈偏移、SSL 结构体偏移、gadget 地址均来自目标二进制，必须本地调试确定；本卡不执行 PoC。

## 变体与关联

- **64 位目标**：地址空间大，堆喷覆盖固定地址的成本高；可改用部分覆盖 PIE 低字节、泄露栈/堆、或利用更大的可控分配。
- **其它结构体**：任何在栈上、含函数指针且溢出后可被调用的结构（SSL、协议回调、对象虚表）都可替代 SSL 结构体。
- **不 ROP**：若固定页可写且可执行（无 NX），直接跳 shellcode；有 NX 时用 `mprotect`/`VirtualProtect` 或 ROP 调 `system`。
- **关联**：[[binary-pwn-stack-ivanti-cve-2025-0282-clientcapabilities-vtable-rop]]（栈溢出改虚表调用）、[[binary-pwn-stack-pivot-leave-ret-bss]]（栈迁移）、[[binary-pwn-heap-custom-allocator-negative-size-alignment-overflow]]（堆占位/任意写）。
- **边界**：需要无限/大量可控分配与固定地址命中；若服务限制分配大小/次数、开启 CFI/ASLR 强度更高、或 TLS 库已修复栈溢出，则不可用。

## 检测与防御

- **修复栈溢出**：TLS 记录解析严格校验长度，使用有界读取；开启栈 canary、`FORTIFY_SOURCE`、编译时数组边界检查。
- **限制分配**：对单连接/单进程的堆分配总量、记录数量、页数设上限；使用 ASLR 强度更高的 64 位构建；固定地址敏感结构不放栈上。
- **控制流保护**：CFI、`-fstack-clash-protection`、RELRO；SSL 结构体函数指针可加完整性校验（若库支持）。
- **检测**：TLS 端口出现异常长度记录/崩溃；进程在 `ssl_accept` 附近崩溃；大量固定大小分配后紧跟 TLS 连接；监控 `mprotect` RWX 与 shellcode 特征。
- **响应**：重启服务、更新 TLS 库、审计固定地址堆布局与分配接口。
