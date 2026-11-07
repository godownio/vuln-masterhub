---
id: web-generic-auth-php-md5-array-strict-comparison-bypass
title: PHP md5 严格比较 + 数组参数类型混淆：a[]=1&b[]=2 让 null === null 成立
type: scenario
domain: web
path: web/generic/auth
technique: php-md5-array-strict-comparison-bypass
aliases:
- md5 数组绕过
- a[]=1&b[]=2
- md5(array) 返回 null
- null === null
- PHP 严格比较绕过
- MD5 不同输入相同哈希
tags:
- web
- php
- auth
- md5
- type-juggling
- array
- strict-comparison
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:37:15+08:00'
  notes: 已对照原文polar.php源码、图22 payload与响应核对：a[]=1&b[]=2使md5(array)返回null，null===null通过严格比较，响应头X-Powered-By PHP/7.2.33；无CVE、无sources/source_url；未对真实站点发送请求。
---

## 一句话结论

当校验逻辑要求“两个输入不相等，但 `md5($a) === md5($b)`”时，在 PHP 7.x 提交 `a[]=1&b[]=2` 即可：两个参数被解析为不同数组，满足 `!=`；`md5()` 收到数组会告警并返回 `null`，两次调用都得到 `null`，`null === null` 为真，于是绕过严格比较；案例服务端为 PHP 7.2.33。

## 原理

- 目标代码形态：
  ```php
  if ($_POST['a'] != $_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
      // 通过
  }
  ```
- **数组解析**：PHP 会把 `a[]=1&b[]=2` 解析为 `$_POST['a'] = ['1']`、`$_POST['b'] = ['2']`。两个数组内容不同，`!=` 为真。
- **md5 类型错误**：`md5()` 的签名要求 `string`；在 PHP 7.x 传入数组会触发 `Warning: md5() expects parameter 1 to be string, array given` 并返回 `null`。两次调用都返回 `null`，`null === null` 为真。
- **为什么严格比较也失效**：`===` 比较的是“值 + 类型”，但两边都不是字符串，而是同一个 `null` 值；严格比较并不能阻止“函数在错误输入下返回同一个错误值”。
- **PHP 8 边界**：PHP 8.0+ 对内置函数参数类型更严格，`md5(array)` 会抛出 `TypeError`（fatal），该 payload 不再成立；需要确认目标版本或改用其它类型混淆/碰撞路径。
- 案例服务端 `X-Powered-By: PHP/7.2.33`，关闭了错误显示（`error_reporting(0)`），所以警告不可见；提交后页面回显“MD5 不错不错”并进入下一关。

## 触发条件

- 目标运行 PHP 7.x（或对 `md5(array)` 仍返回 `null` 的版本），且错误显示关闭/不影响流程。
- 校验把用户输入直接传给 `md5()`/`sha1()` 等字符串函数，没有 `is_string`/`is_array` 检查。
- 比较使用 `===`/`!==`，但比较的是函数返回值而不是原始输入；两边的错误返回值相同。
- 参数以表单/JSON 传入且支持数组语法（`a[]=1`、`a[0]=1`）。

## 利用步骤

1. 确认 PHP 版本（响应头 `X-Powered-By`、报错页、`phpinfo`）与错误显示设置。
2. 构造两个不同数组参数：`a[]=1&b[]=2`；也可用 `a[0]=x&b[0]=y`。
3. 提交到校验接口，观察是否通过“不同输入”与“md5 相等”两重检查；若页面提示哈希不正确，检查是否被 `is_string`/`is_array` 拦截。
4. 通过后继续后续流程（案例直接拿到 flag/session）。
5. 若目标为 PHP 8，改用真正的 MD5 碰撞对、魔术哈希（仅 `==`）、或其它逻辑缺陷；不要假设数组技巧可用。

## PoC

```http
POST /polar.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

a[]=1&b[]=2
```

```php
<?php
// 本地验证（PHP 7.x）
var_dump(md5(['1']));   // Warning + NULL
var_dump(md5(['2']));   // Warning + NULL
var_dump(md5(['1']) === md5(['2'])); // bool(true)
```

案例提交后回显“MD5 不错不错”，随后可执行后续命令注入步骤拿到 flag。本卡不针对真实站点执行。

## 变体与关联

- 函数可换成 `sha1()`、`hash('md5', $x)`、`crc32()` 等；只要错误输入返回同一个 `null`/`false`，严格比较都可能成立。
- 参数可以是数组、对象（若函数不接受对象会抛错/告警）、`null`；PHP 版本决定行为。
- 若代码用 `==` 而非 `===`，还可使用 `0e` 魔术哈希（240610708/QNKCDZO）或 `md5([]) == md5(null)`。
- 关联：[[web-generic-auth-php-md5-magic-hash-pair-double-verify]]（`==` 魔术哈希）、[[ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash]]（对象/数组类型混淆与魔术哈希）、[[web-php-deserialization-double-md5-weak-compare-pop-chain]]（弱比较 POP 链）。
- 边界：PHP 8+ 会抛 `TypeError`；若应用启用严格类型/参数过滤、或先 `is_string` 校验，数组技巧失效；真正的 MD5 碰撞需要二进制碰撞对，不是本卡的范围。

## 检测与防御

- 对所有哈希输入先做 `is_string()` 校验；拒绝数组/对象/`null`，或在入口层统一参数类型。
- 使用 `hash_equals()` 比较哈希，避免类型混淆；不要用 `md5` 做安全校验，改用 `password_hash`/HMAC。
- 开启错误日志但关闭回显，避免把 `Warning` 暴露给攻击者；同时不要把“函数返回 null”当作合法哈希。
- 监控表单中出现 `a[]=`、`b[]=` 等数组参数、异常 `Warning: md5() expects parameter` 日志；对认证接口做参数结构校验。
