---
id: ctf-pwn-command-injection-filename-shell-quote-bypass
title: C 程序命令注入文件名过滤绕过：fl''ag 引号拼接绕过 strstr(file,"flag")
type: scenario
domain: ctf
path: ctf/pwn
technique: command-injection-filename-shell-quote-bypass
tags:
- ctf
- pwn
- command-injection
- shell-quote
- waf-bypass
- strstr
- glob
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:01+08:00'
  notes: 已对照原文 filesystem 题源码与远程回显核对；修正远程额外过滤字符为 * 与 ?；PoC 未复跑。
url: /docs/ctf/pwn/ctf-pwn-command-injection-filename-shell-quote-bypass/
draft: false
kb_aliases:
- fl''ag 绕过
- fl""ag 绕过
- strstr flag 过滤绕过
- system cat 文件名注入
- shell 引号删除
- filesystem 命令注入
---

## 一句话结论

C 程序把用户输入的文件名拼进 `system("cat " + file)`，先用 `strstr(file,"flag")` 拦截含 `flag` 的文件名、再用字符黑名单拦截 `|;{([$&`；由于过滤发生在 shell 解析之前，输入 `fl''ag` 或 `fl""ag` 时原字符串不含连续的 `flag`，但 `/bin/sh -c` 会做引号删除并拼成 `flag`，从而读取 flag。

## 原理

- 程序流程：主循环读取文件名到全局 `file`（最多 10 字节，去掉换行），输入 `quit` 退出，否则创建线程执行 `cat`。`cat` 先 `strstr(file,"flag")`，命中则拒绝；否则检查字符黑名单 `|;{([$&`；通过后把 `file` 追加到以 `"cat "` 开头的缓冲区，调用 `system()`。
- `strstr` 是纯字符串子串匹配，不理解 shell 语法。`fl''ag` 的字节序列是 `f l ' ' a g`，其中没有连续子串 `flag`，因此 `strstr` 返回 NULL；黑名单也不包含单引号/双引号，因此检查通过。
- `system()` 把命令交给 `/bin/sh -c`。POSIX shell 的词法规则会把相邻的引号段与无引号段拼接为一个词，空引号不产生字符；`fl''ag` 解析为 `f` + 空串 + `l` + 空串 + `ag` = `flag`。最终执行 `cat flag`，读取 flag。
- `fl""ag` 同理；`fl*` 利用路径名展开，但部分远程环境会额外过滤 `*` 和 `?`，此时引号拼接更稳。`fl'a'g`、`fl\ag`（反斜杠转义）也是等价变体。
- 过滤层与使用层不一致是根因：检查的是“原始文件名字符串”，实际执行的是“shell 解析后的命令”；只要能在不出现被禁子串的情况下让 shell 还原出目标词，就能绕过。
- 该程序还会先 `system("ls")` 列出目录，可用于确认 `flag` 文件名；`file` 只有 10 字节，payload 需短小（`fl''ag` 仅 7 字节）。

## 触发条件

- C/C++ 程序把用户输入拼接进 `system()`/`popen()` 等 shell 调用，且没有使用参数数组或正确转义。
- 过滤在 shell 解析之前做子串/字符检查（如 `strstr(...,"flag")`、黑名单 `|;{([$&`），未禁止引号、反斜杠、通配符等 shell 元字符。
- 目标 shell 为 POSIX sh/bash，支持引号删除与路径名展开；目标文件在当前工作目录或可用相对路径访问。
- 输入长度限制足够容纳引号拼接后的 payload（本例 10 字节）。

## 利用步骤

1. 运行/连接程序，观察 `system("ls")` 的输出，确认 `flag` 文件存在。
2. 尝试直接输入 `flag`，确认被 `strstr` 拦截并返回 “Sorry, I just won't show you this file”。
3. 输入 `fl''ag`（或 `fl""ag`）绕过子串检查；shell 解析后执行 `cat flag`，输出 flag。
4. 若远程额外过滤 `*`/`?`，不要用 `fl*`；若单引号被过滤，尝试双引号、反斜杠转义或 `fl'a'g`。
5. 若 10 字节限制更紧，可用 `fl''ag` 的最短形式；必要时用 `?`/`[]` glob（若未被过滤）。

## PoC

```python
from pwn import *

io = remote("target", 9999)
io.recvuntil(b"which file do you want to read")
io.sendline(b"fl''ag")
print(io.recvall(timeout=3).decode(errors="ignore"))
```

手工交互：

```text
which file do you want to read:
fl''ag
flag{...}
```

shell 解析等价于：

```sh
cat fl''ag    # -> cat flag
```

## 变体与关联

- 变体：`fl""ag`、`fl'a'g`、`fl\ag`、`f''lag`、`fl''a''g`；只要原始串不含连续 `flag`，shell 还原后是 `flag` 即可。
- 变体：用 `*`/`?`/`[]` 做路径名展开（`fl*`、`fl????`），但需确认远程未过滤这些字符；用 `$IFS`/`${IFS}` 替代空格（若空格被过滤）。
- 变体：命令名本身被拦时用 `c''at`、`t''ac`、`/bin/c''at`；路径被拦时用 `./fl''ag`、绝对路径或 glob。
- 关联：[[web-php-rce-shell-exec-quote-concat-glob-flag]]（PHP `shell_exec` 黑名单下 `c''at /f*` 的同类原理）、[[web-php-rce-command-space-blacklist-tab-passthru]]（空白/关键字绕过）、[[web-generic-sqli-keyword-double-write-bypass]]（另一类“检查表示与执行表示不一致”）。
- 边界：程序使用 `execve` 参数数组、对输入做 `escapeshellarg` 级别转义、在 shell 解析后做白名单，或完全禁止引号/反斜杠/通配符时，本手法失效；输入长度不足会截断 payload。

## 检测与防御

- 不要用 `system()`/`popen()` 拼接用户输入；使用 `execve`/`posix_spawn` 的参数数组，文件名作为单个 argv 元素，不经过 shell。
- 若必须用 shell，使用严格的参数转义（如 `shlex.quote` 的等价实现），并对文件名做白名单/固定映射；不要用 `strstr` 黑名单。
- 过滤应在 shell 解析之后做，或直接拒绝引号、反斜杠、通配符、`$`、`;`、`|`、`&` 等元字符；但根本仍是避免 shell。
- 文件权限最小化：Web/服务进程不应与 flag 同权限可读；flag 放在独立目录并限制访问。
- 检测：程序输入中出现 `''`、`""`、`\`、`*`、`?`、`$IFS` 等 shell 元字符；`system`/`sh -c` 子进程命令与用户输入不一致；异常 `cat flag`/`ls` 调用。
