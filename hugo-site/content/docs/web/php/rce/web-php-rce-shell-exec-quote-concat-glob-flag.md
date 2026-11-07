---
id: web-php-rce-shell-exec-quote-concat-glob-flag
title: PHP shell_exec 黑名单绕过：c''at 引号拼接 + /f* 通配符读取 flag
type: scenario
domain: web
path: web/php/rce
technique: php-shell-exec-quote-concat-glob-waf-bypass
tags:
- php
- rce
- command-injection
- waf-bypass
- shell-quote
- glob
- lfi
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:45:12+08:00'
  notes: 已对照原文与3张图核对：robots.txt暴露表情文件名→include报错确认LFI→php://filter读源码→spell进入shell_exec，黑名单含system/exec/passthru/shell_exec/popen/proc_open、flag及cat/tac/nl/more/less/head/tail/sort/uniq/strings/od/xxd/hexdump/grep/awk/sed/cut/rev/base64/env；payload c''at%20/f* 利用shell引号删除与glob展开，与原文一致。未验证点：未对题目环境实际发请求（CTF题无组件版本，未设置versions）；frontmatter无sources/source_url。
url: /docs/web/php/rce/web-php-rce-shell-exec-quote-concat-glob-flag/
draft: false
kb_aliases:
- 拯救芙莉莲
- c''at /f*
- PHP 命令注入引号拼接
- shell 引号删除绕过
- glob 通配符绕过 flag 关键字
- shell_exec 黑名单绕过
---

## 一句话结论

PHP 页面把 `$_GET['spell']` 直接交给 `shell_exec`，但先用 `stripos` 黑名单拦截 `cat`、`flag` 等字面量；由于 WAF 检查的是 shell 解析前的原始字符串，而 `/bin/sh -c` 会在之后做引号删除和路径名展开，传入 `c''at /f*` 即可让 shell 实际执行 `cat /flag`，同时 payload 中不出现连续的 `cat` 或 `flag`。

## 原理

- **入口是 LFI 源码泄露**：`robots.txt` 暴露了一个表情符号命名的 PHP 文件；访问时报 `include()` 错误，说明存在文件包含。用 `php://filter/convert.base64-encode/resource=<文件名>` 读取源码，得到 `shell_exec($spell)` 及其黑名单逻辑。
- **过滤发生在错误的抽象层**：代码对 `$spell` 做 `stripos` 子串匹配，拦截危险函数名、`flag` 以及 `cat/tac/nl/...` 等命令；但 `$spell` 随后才交给 `shell_exec`，由 `/bin/sh -c` 进行词法解析。WAF 看到的是原始文本，shell 看到的是解析后的命令，两者对同一字符串的理解不同。
- **引号删除**：POSIX shell 会把相邻的引号段和无引号段拼接成一个词，空引号不产生字符。`c''at` 的解析过程是 `c` + 空字符串 + `at`，结果为 `cat`；但原始字符串是 `c''at`，不包含连续子串 `cat`，所以 `stripos($spell, 'cat')` 为 false。
- **路径名展开（glob）**：`/f*` 由 shell 展开为 `/flag`（或 `/f` 开头的匹配项），payload 中没有字面量 `flag`，所以第二层 `stripos($spell, 'flag')` 也为 false。
- **等价性**：最终执行的命令是 `cat /f*`，shell 展开后读取 `/flag`；`shell_exec` 返回命令输出，页面直接 echo，flag 回显。
- **为什么其他黑名单没拦住**：`cat` 的字符被引号拆开，`flag` 被 glob 拆开；`shell_exec` 这个函数名本身不出现在 payload 中，危险函数黑名单只检查 `$spell` 内容，不检查 `shell_exec` 的调用。

## 触发条件

- 存在一个把用户输入直接传给 `shell_exec`（或 `system`/`exec`/`popen`）的 PHP 入口，且回显命令输出。
- 前置黑名单对原始请求字符串做 `stripos`/正则匹配，拦截命令名或目标文件名，但没有做 shell 级别的规范化/解析。
- 目标 shell 为 POSIX sh/bash，支持引号拼接和 glob；`/flag` 位于可读路径且匹配 `f*`。
- 能访问入口（可能需要先通过 LFI 读源码确认黑名单与参数名）。

## 利用步骤

1. 目录扫描发现 `robots.txt`，从中得到隐藏 PHP 文件名。
2. 触发文件包含错误，确认 `?file=` 参数存在 LFI；用 `php://filter/convert.base64-encode/resource=<file>` 读取源码。
3. 从源码确认 `spell` 参数进入 `shell_exec`，并列出黑名单：危险函数、`flag`、`cat/tac/nl/more/less/head/tail/sort/uniq/strings/od/xxd/hexdump/grep/awk/sed/cut/rev/base64/env`。
4. 构造 `c''at /f*`：引号拆开 `cat`，glob 代替 `flag`；URL 编码空格后发送 `?spell=c''at%20/f*`。
5. 页面回显命令输出，得到 flag。

## PoC

```http
GET /%EF%BC%9C(%C2%B4%E2%8C%AF%20%CC%AB%E2%8C%AF%60)%EF%BC%9E.php?spell=c''at%20/f* HTTP/1.1
Host: <target>
```

核心 payload：

```text
?spell=c''at%20/f*
```

shell 解析后等价于：

```sh
cat /f*
# 展开为 cat /flag
```

原文实测可直接回显 flag；本卡不执行 PoC。

## 变体与关联

- **引号变体**：`c""at`、`c'a't`、`c\at`（反斜杠转义）都能让 shell 得到 `cat`，而原始字符串不含 `cat`。
- **glob 变体**：`/f*`、`/fl*`、`/f????`、`/???g` 等；也可用 `?` 拆开被拦的关键字。
- **命令替代**：若 `cat` 被更严格地拦截，可用 `tac`、`nl`、`less` 等未被拦的命令，或用 `cp /f* /tmp/x` 后再读；但本题这些也被列在黑名单里，所以优先用引号拼接。
- **与文件包含组合**：LFI 只用于读源码，真正的 RCE 是 `shell_exec`；若目标无回显，可写文件/反弹 shell。
- 关联：[[web-php-rce-command-space-blacklist-tab-passthru]]（Tab/IFS + 通配符绕过）、[[web-php-rce-command-injection-blacklist-base64-tee-webshell]]（黑名单 + 字符集白名单绕过）、[[web-php-rce-four-char-command-length-bypass]]（长度限制绕过）。

## 检测与防御

- **不要用 shell**：PHP 中避免 `shell_exec/system/exec/popen/proc_open`；必须执行命令时使用参数数组（如 `proc_open` 的数组形式）并配合白名单，而不是拼接字符串。
- **正确转义**：若无法避免，使用 `escapeshellarg()` 对每个参数转义、`escapeshellcmd()` 仅作补充；不要依赖黑名单。
- **WAF 层**：黑名单要在 shell 规范化之后判断，或直接拦截引号、反斜杠、`;|&$()`、通配符等元字符；但根本仍是应用层不使用 shell。
- **LFI 修复**：禁止用户控制 `include` 路径，使用固定白名单/映射表，关闭 `allow_url_include`，限制 `php://filter` 等包装器。
- **检测**：Web 日志中出现 `c''at`、`/f*`、`$IFS`、`${IFS}` 等 shell 绕过特征；PHP 进程异常执行 `cat /flag`、`sh -c` 子进程；对 `shell_exec` 调用做审计。
- **权限**：Web 进程以最小权限运行，flag 文件不应与 Web 进程同权限可读；即使 RCE 也提高读取成本。
