---
id: web-php-rce-regex-backslash-escape-command-injection
title: PHP 正则黑名单双重转义：在关键字中插入反斜杠（ca\t /fl\ag）绕过 cat/flag 过滤
type: scenario
domain: web
path: web/php/rce
technique: php-regex-backslash-escape-command-injection
aliases:
- 反斜杠绕过命令注入黑名单
- PHP preg_match 转义绕过
- ca\t /fl\ag
- 正则黑名单双解析
- 命令注入关键字拆分
tags:
- php
- command-injection
- regex
- blacklist-bypass
- escaping
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:19:39+08:00'
  notes: 已对照原文核对：老刘的小店黑名单代码、双层转义说明与 ca\t /fl\ag payload 一致；原文未展示成功回显，且对最终 pattern 的描述较粗，卡片已标注需以实际 pattern 验证，保留。
---

## 一句话结论

当命令执行接口用 PHP `preg_match` 黑名单过滤 `cat`、`flag`、`|`、反斜杠等关键字时，若正则写在双引号字符串里且反斜杠数量没有按“PHP 字符串解析 + PCRE 解析”两层正确计算，开发者以为过滤了 `\`、实际可能只过滤了字面量 `|` 或制表符；攻击者在关键字中插入反斜杠（`ca\t /fl\ag`），黑名单看不到连续的 `cat`/`flag`，而 shell 会把 `\t`、`\a` 还原成 `t`、`a`，最终执行 `cat /flag`。

## 原理

- PHP 双引号字符串会先做一层转义解析：`\\` → `\`，`\\\\` → `\\`，`\n` → 换行，`\t` → 制表符。随后 `preg_match` 再把字符串当 PCRE 解析：`\|` 是字面量 `|`，`\\` 是字面量 `\`。
- 黑名单常见写法把多个转义混在一起（如 `...|\\|\\\\|\n|\t|...`），开发者意图是同时过滤“反斜杠”“双反斜杠”“换行”“制表符”。经过两层解析后，实际 pattern 可能变成只匹配字面量 `|`/空分支/真实制表符，单个反斜杠并**没有**被有效拦截；具体结果取决于原代码的引号类型与反斜杠个数，必须以目标实际 pattern 验证。
- 即使反斜杠最终被过滤，也可以利用“过滤的是真实制表符 `\t` 而不是两字符序列 `\t`”的差异：payload 里的 `\t` 是两个字符（反斜杠 + t），不会命中真实制表符分支；而 shell 会把它解释为 `t`。
- shell（bash/sh）的反斜杠是转义符：`ca\t` 执行时等价 `cat`，`/fl\ag` 等价 `/flag`；因此可以在任意关键字中间插入 `\` 来打断黑名单的子串匹配，只要最终 shell 收到的字符串能被还原为原命令。
- 该技巧属于“过滤层与执行层解析不一致”的典型：黑名单看到的是带反斜杠的原始字符串，shell 看到的是去掉转义后的命令。若接口用 `system($_GET['id'])` 直接把参数交给 shell，反斜杠不会被 PHP 额外处理（`$_GET` 已是字符串），正好保留给 shell 解析。

## 触发条件

- 存在命令执行 sink（`system`/`exec`/`shell_exec`/`passthru` 等），且参数未经 `escapeshellarg`/白名单。
- 前置黑名单用 `preg_match` 在 PHP 字符串中编写，包含反斜杠/制表符/关键字等转义；实际 pattern 未有效拦截 `\` 或拦截的是错误字符。
- 目标 shell 会把反斜杠当转义符（sh/bash）；Windows cmd 的反斜杠语义不同，本技巧主要适用于 Unix shell。
- 反斜杠在 HTTP 参数中可能需要 URL 编码为 `%5c`，避免被中间层处理。

## 利用步骤

1. 确认命令注入点与黑名单行为：先发送正常命令（如 `id`）和含被禁关键字（`cat /flag`）的请求，观察是否被拦截。
2. 用 `\` 拆分关键字：`ca\t /fl\ag`、`c\at /fl\ag`、`cat /fl\ag` 等；逐步确认哪些组合能通过黑名单。
3. 若 `\` 本身被拦截，检查黑名单是否真的匹配反斜杠：尝试 `%5c`、双写 `\\`、制表符/`$IFS` 等替代分隔方式（不同变体）。
4. 通过后观察命令输出；若回显被限制，改用 `> /tmp/x` 写文件、`curl`/`wget` 外带或时间盲注。
5. 记录实际生效的 payload 与黑名单行为，便于在同类 PHP 代码审计中复用。

## PoC

```text
GET /vuln.php?id=ca\t /fl\ag HTTP/1.1
```

URL 编码形式（反斜杠 = %5c）：

```text
GET /vuln.php?id=ca%5ct%20/fl%5cag HTTP/1.1
```

等价的 shell 还原过程：

```bash
# 黑名单看到的字符串
ca\t /fl\ag
# shell 执行时反斜杠转义
cat /flag
```

说明：PoC 是原文 `?id = ca\t /fl\ag` 的复现形式，未在原文目标上复跑；是否命中取决于目标黑名单的实际 pattern 与引号/反斜杠数量，建议在本地用相同 pattern 先验证。

## 变体与关联

- **其他分隔**：`c''at` 引号拼接、`c"at"`、`$IFS`/Tab 替代空格、`/f*` 通配符；见 [[web-php-rce-shell-exec-quote-concat-glob-flag]]、[[web-php-rce-command-space-blacklist-tab-passthru]]。
- **正则本身被绕过**：`.htaccess` 把 `pcre.backtrack_limit` 置 0 让 `preg_match` 返回 false；见 [[web-php-rce-htaccess-pcre-backtrack-limit-bypass]]。
- **编码层绕过**：Base64 + 管道 `base64 -d | sh`；见 [[web-php-rce-command-injection-blacklist-base64-tee-webshell]]。
- **边界**：黑名单改成白名单/`escapeshellarg`、参数不经过 shell（如 `proc_open` 数组形式）、Windows cmd 解析反斜杠方式不同、或应用层先做 `stripslashes` 时，本技巧不成立。

## 检测与防御

- 防御：不要用黑名单；使用白名单命令/参数，或对每个参数 `escapeshellarg`/`escapeshellcmd`；尽量用 `proc_open` 数组形式避免 shell 解析。
- 代码审计：检查 PHP 字符串中的正则转义是否按两层解析；用实际运行时的 pattern（`var_dump($pattern)`）确认过滤意图，而不是只看源码。
- 检测：命令参数中出现反斜杠、引号、`$IFS`、Tab、通配符等拆分特征；同一 IP 多次尝试不同拆分；命令执行子进程出现 `cat /flag` 等。
- 响应：发现命令执行后隔离主机、保存请求日志与进程记录、排查 Webshell/持久化。
