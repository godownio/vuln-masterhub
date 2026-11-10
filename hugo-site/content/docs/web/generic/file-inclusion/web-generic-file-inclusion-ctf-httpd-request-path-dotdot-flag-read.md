---
id: web-generic-file-inclusion-ctf-httpd-request-path-dotdot-flag-read
title: 自实现 HTTP 服务把请求行路径直接 fopen 且不校验 ../：POST /../flag 读取根目录 flag
type: scenario
domain: web
path: web/generic/file-inclusion
technique: custom-httpd-request-line-dotdot-traversal
tags:
- web
- ctf
- path-traversal
- arbitrary-file-read
- http-server
- input-validation
- fopen
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V292
  verified_at: '2026-11-08T08:26:25+08:00'
  notes: 已对照全文与图 02/03 核对：fopen(a2,"r") 直接打开请求路径、文件不存在走 my_404，my_recv 循环以读到 \n 为结束（故需 \n\n），原文非预期解 payload=b'POST /../flag\n\n' 可读 /flag，与卡内 PoC 一致；卡内补充的 htdocs/cwd 相对关系与“命令分支复杂校验不代表文件分支安全”均成立。原子性=请求行路径未过滤 ../ 导致任意文件读取，单原子；与同题命令协议卡为两条不同链，dup-scan 判 related 成立。原文未标版本，不设 affected_versions。未在题目环境复跑，POST/GET 方法差异原文称多数自实现服务不校验、以实际解析为准。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-ctf-httpd-request-path-dotdot-flag-read/
draft: false
kb_aliases:
- vnctf2022 classic_httpd 非预期解
- POST /../flag
- 自实现 httpd 目录穿越
- htdocs 上层 flag
- 请求行路径穿越
---

## 一句话结论

一个自实现的极简 HTTP 服务把请求行里的路径直接交给 `fopen` 一类文件函数，既不拒绝 `..` 段也不做 `realpath` + 根目录前缀校验；当 web 根是 `/htdocs`（或进程工作目录为 `/`、web 根为 `htdocs`）且 flag 在根目录时，请求 `POST /../flag\n\n` 会让 `htdocs/../flag` 解析成 `/flag`，服务端把 flag 原样返回。

## 原理

- **请求行路径直达文件打开**：服务端按 HTTP 请求行取出方法、路径和版本，未对路径做规范化或白名单，就把它传给 `fopen`/`stat`/`open`。`..` 是文件系统层的“父目录”语义，未经检查就会把访问范围带出 web 根。
- **为什么 `/../flag` 能到 `/flag`**：若程序把路径原样传给 `fopen` 且路径以 `/` 开头，内核按绝对路径解析，根目录的父目录仍是根，`/../flag` 等价于 `/flag`；若程序把 web 根前缀拼上（如 `htdocs` + `/../flag`）且进程 cwd 是 `/`，同样得到 `/flag`。文章特别提示“这种题当前目录一般都是 htdocs，flag 都在 / 根目录下”，正是这条相对关系。
- **为什么要两个换行**：服务端的读取循环以“读到内容等于 `\n` 的一行”为结束条件。请求行 `POST /../flag\n` 只结束了第一行，循环仍在等服务端读下一行；再发一个空行 `\n` 才让循环退出并进入文件处理分支。文章强调少一个 `\n` 就“一直交互不了”。
- **为什么这是非预期解**：出题人预期走的是 `submit.cgi` 的类型化命令协议（任意读/写 + GOT 劫持），但文件服务分支根本没有目录穿越检查，因此一条请求即可读 flag；这说明“命令分支做了复杂校验”并不代表同一服务器其他分支也安全。
- **与命令注入的区别**：本链只控制文件路径，没有把路径交给 shell；危害是任意文件读取，能否进一步 RCE 取决于可读文件内容（配置、密钥、源码）与目标权限。

## 触发条件

- 自实现/极简 HTTP 服务，请求行或 query 里的路径被直接用于文件打开，未做 `realpath` 规范化与 web 根前缀校验。
- 目标敏感文件（flag、配置、密钥）位于 web 根的一级或多级父目录，且服务进程对其有读权限。
- 服务端的请求读取循环需要一个空行/特定终止符才继续处理，PoC 必须补齐终止符。
- 路径若经过 URL 解码，`..` 可用 `%2e%2e%2f` 等形式表达；若服务端做了单次字符串替换，可用 `....//` 等双写变体。

## 利用步骤

1. 连接目标 HTTP 端口，先发一个正常请求确认服务端解析格式与响应行为。
2. 发送 `POST /../flag\n\n`（或 `GET /../flag\n\n`；多数自实现服务不校验方法）。第一个 `\n` 结束请求行，第二个空行结束读取循环。
3. 读取响应；若 web 根比预想深，增加 `../` 层数（如 `/../../flag`）；若路径被解码，改用 `/%2e%2e/flag`。
4. 若服务端把 web 根与路径拼接且不允许绝对路径，尝试去掉前导 `/`（`../flag`）或重复 `../` 直到越过根目录。
5. 读到 flag 后，可继续用同一原语读取 `/etc/passwd`、源码、配置、SSH 私钥等，评估能否进一步利用。

## PoC

```python
from pwn import remote

io = remote("target", 26097)
io.send(b"POST /../flag\n\n")
print(io.recvall(timeout=3))
```

```http
POST /../flag

```

（请求行与空行之间的换行即 `\n\n`；服务端读取循环收到空行后才会打开文件。）

## 变体与关联

- **编码变体**：`%2e%2e%2f`、`%2e%2e/`、`..%2f`；若服务端先检查后解码，编码可绕过 `..` 黑名单；若先解码后检查，则需双写或 `....//`。
- **拼接变体**：web 根拼接时用 `../` 逐级上跳；绝对路径可覆盖前缀（`new File(root, path)` 中 path 以 `/` 开头）；Windows 目标用 `..\` 或 `%5c`。
- **读取目标变体**：flag、`/etc/passwd`、应用源码、`.env`、数据库配置、SSH 私钥；拿到凭据后可横向或提权。
- **关联**：[[web-generic-file-inclusion-apache-cve-2021-41773-normalize-bypass]]（路径规范化绕过读文件）、[[web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal]]（双重编码 + `./../` 交替绕过黑名单）、[[web-generic-file-inclusion-nginx-alias-off-by-slash-traversal]]（nginx alias 尾斜杠穿越）、[[ctf-pwn-httpd-base64-typed-command-arb-rw-got-system]]（同题预期解，走命令协议任意读写）。
- **边界**：服务端若用 `realpath` 后校验前缀、以 `openat` + 固定 dirfd 打开、或在解码后拒绝任何 `..` 段，本链不成立；flag 不在 web 根可达范围时只能读到有限文件。

## 检测与防御

- **修复**：对请求路径先 URL 解码一次，再用 `realpath` 规范化，校验结果仍以 web 根为前缀；拒绝任何包含 `..` 段的路径；使用 `openat(dirfd, name, ...)` 并禁止绝对路径。
- **架构**：把静态文件服务交给成熟服务器（nginx/Apache）并关闭目录穿越；在容器/chroot 中运行，flag 不放在 web 根可达路径。
- **检测**：请求行/URL 中出现 `../`、`%2e%2e`、`....//`、`..%5c`；同一连接发送异常空行；访问 web 根之外的文件；响应中出现 `/etc/passwd`、flag 等敏感内容特征。
- **注意**：这是 CTF/授权环境下的验证思路；对生产系统测试需获得授权。
