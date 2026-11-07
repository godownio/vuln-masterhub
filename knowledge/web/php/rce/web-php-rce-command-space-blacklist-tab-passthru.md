---
id: web-php-rce-command-space-blacklist-tab-passthru
title: 命令执行黑名单同时过滤函数名与空格：passthru 替代 + Tab/IFS + 通配符
type: scenario
domain: web
path: web/php/rce
technique: command-filter-tab-passthru-bypass
aliases:
- Tab 绕过空格过滤
- IFS 空格绕过
- passthru 替代 system
- 命令关键字黑名单绕过
- Tab（%09）命令分隔
tags:
- php
- rce
- command-injection
- blacklist-bypass
- tab
- ifs
- passthru
- glob
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:43+08:00'
  notes: 已对照原文 ezpop 源码与图23核对：黑名单 /flag|system|tail|more|less|php|tac|cat|sort|shell|nl|sed|awk| /i 同时含关键字与空格；payload 用 passthru('ls\t/')、passthru('strings\t/f*')，序列化串中为 %09 真实 Tab；图23 回显 flag。Tab/IFS/通配符原理准确。PoC 未在本机执行。
---

## 一句话结论

当命令执行点用正则同时黑名单 `system/cat/flag` 等关键字和普通空格时，可换用未被禁的 `passthru`、用 Tab（ASCII 9，URL 中 `%09`）代替空格、用 `strings` 替代 `cat`、用通配符 `/f*` 替代 `flag`，从而继续执行命令并回显。

## 原理

- Linux shell 的 `IFS`（Internal Field Separator）默认包含空格、Tab 和换行；它们都是合法的参数分隔符。正则只黑名单了普通空格字符，没有覆盖 Tab/换行，因此 `ls<TAB>/` 与 `ls /` 等价。
- `system`、`cat`、`flag` 等被黑名单命中，但 PHP 还有 `passthru`、`shell_exec`、`proc_open`、反引号等等价执行函数；`passthru` 与 `system` 一样直接把命令输出写到响应。
- 命令中的目标词也可替换：`cat` → `strings`/`nl`/`tac`/`head`；`flag` → `/f*` 通配符（shell 展开为 `/flag`），避免出现完整关键字。
- 这些变形都发生在“数据”层：黑名单按字面量匹配请求/代码字符串，而 shell 在更晚的阶段才解释 Tab、通配符和命令名，检查与执行之间存在语义差。
- 该手法适用于任何把用户输入拼进 `system/exec/shell_exec` 等命令执行点的场景，不限于某个 CMS。

## 触发条件

- 存在命令执行/代码执行入口，且用户输入能进入 shell 命令；
- 黑名单覆盖了常用函数名/命令名和字面空格，但未归一化 Tab、换行、`${IFS}`、通配符；
- 目标函数（如 `passthru`）未被 `disable_functions` 禁用；
- 命令回显可观察（`passthru`/`system` 直接输出）。

## 利用步骤

1. 用 `system('id')` 探测，确认被黑名单拦截。
2. 换 `passthru('id')`，确认函数名未被过滤且能回显。
3. 需要空格时改用 Tab（URL `%09`、PHP 双引号字符串中的 `\t`、或 `$IFS`/`${IFS}`）；需要换行时用 `%0a`。
4. 目标词被过滤时用同义命令（`strings`、`nl`、`tac`）或通配符（`/f*`）。
5. 逐步读取目标文件或执行命令。

## PoC

```php
// 假设注入点会 eval 或直接拼接进 system/passthru
passthru('ls<TAB>/');
passthru('strings<TAB>/f*');
```

在 HTTP 请求中 Tab 写作 `%09`：

```text
?cmd=passthru('ls%09/');
?cmd=passthru('strings%09/f*');
```

若命令字符串经过 PHP 双引号解析，也可写成：

```php
$cmd = "passthru('ls\t/');";      // \t 解析为真实 Tab
```

实际 shell 收到的命令：

```bash
ls	/
strings	/f*
```

原文在 POP 链的 `eval` sink 中用 `passthru('ls\t/')` 与 `passthru('strings\t/f*')` 绕过 `flag|system|...| ` 正则，成功回显根目录与 flag。

## 变体与关联

- 变体：空格过滤可用 `${IFS}`、`$IFS`、`<`（重定向分隔）、换行 `%0a`、Tab `%09`。
- 变体：函数过滤可用 `shell_exec`、`proc_open`、反引号、`popen`、`pcntl_exec` 等替代；命令过滤可用同义命令、路径通配符、变量拼接。
- 关联：[[web-php-rce-seacms-search-template-code-execution]]（WAF 函数黑名单用大小写/同义函数绕过）；[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（用字符串拼接绕过函数名检测）。
- 边界：若 WAF 对 Tab/换行做归一化、黑名单覆盖所有等价函数、或 `disable_functions` 全面禁用命令执行，本手法失效。

## 检测与防御

- 检测：请求中出现 `%09`、`%0a`、`${IFS}`、`$IFS`、反引号、`passthru`、`shell_exec`、`proc_open`；命令字符串中出现通配符与短命令组合。
- 检测：Web 进程拉起 shell 并执行 `ls`、`strings` 等命令；响应中出现目录列表或文件内容。
- 防御：不要拼接用户输入执行 shell；使用参数化 API（如 `proc_open` 数组形式）并做白名单。
- 加固：`disable_functions` 覆盖 `system`、`passthru`、`shell_exec`、`exec`、`proc_open`、`popen`；WAF 先做空白字符/控制字符归一化，再匹配关键字；最小权限运行 Web 进程。
