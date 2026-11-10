---
id: web-generic-auth-php-trim-comparison-null-byte-bypass
title: PHP 认证判断括号错位 + trim 空字节绕过：auth=%00 使 trim 后为空，绕过 user_pass 比对
type: scenario
domain: web
path: web/generic/auth
technique: php-trim-comparison-paren-null-byte-auth-bypass
aliases:
- trim 括号错位
- wp_automatic_trim
- auth=%00 绕过
- 空字节 trim 绕过
- PHP 空密码比对绕过
- login required invalid login 绕过
tags:
- web
- php
- auth-bypass
- null-byte
- trim
- code-audit
- wordpress
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T09:15:32+08:00'
  notes: 已对照原文成因段与 img01 源码核对：wp_automatic_trim 定义(is_null返回空串否则 trim)、三道检查的括号错位 wp_automatic_trim(auth == 空串)、auth 与 current_user.user_pass 的 trim 比较、md5(trim(q.user_pass)) != integ 均与原文一致。PHP 语义复核正确：auth=%00(裸 NUL) 经 stripslashes 不变，NUL 与空串比较为 false→trim(false) 得到空串(falsy) 不退出；trim(NUL) 为空串 与未登录空 user_pass 的 trim(null) 空串相等；integ=md5(trim(q)) 可自算。卡片明确该原语需未登录 user_pass 为空、最终危害取决于 sink，边界描述准确。原文未给版本，affected_versions 已 clear。与 0e/magic-hash/str_replace 等既有认证绕过卡机制不同，非重复；与批内 CVE 卡(原语 vs 完整链)已互相链接。
---

## 一句话结论

当 PHP 代码把比较表达式写进 trim 之类的过滤函数（如 `if (trim($auth == ''))`），函数实际收到的是布尔值而不是字符串：非空 `$auth` 使比较为 false、`trim(false)` 得到空串，第一个“必须登录”检查永远不会触发；再用 `auth=%00`，NUL 会被 `trim()` 默认字符集吃掉、得到空串，与未登录用户的空 `user_pass` 相等，从而同时绕过“login required”和“invalid login”两个判断，直接把后续 `$q` 送进 SQL 等危险 sink。

## 原理

- **括号错位改变了求值顺序**：`if (wp_automatic_trim($auth == ''))` 的意图是“auth 为空则拒绝”，但括号让 `$auth == ''` 先求值成布尔值，再传给 trim。`trim(false)` 在 PHP 中把 false 转成空串并返回 `''`（falsy），`trim(true)` 返回 `'1'`（truthy）。因此：`$auth` 非空 → 比较 false → 检查不退出；`$auth` 为空 → 比较 true → 反而退出。检查逻辑被反转/失效。
- **NUL 被 trim 默认字符集吃掉**：PHP `trim()` 默认删除 `" \t\n\r\0\x0B"`，其中 `\0` 就是 NUL。攻击者提交 `auth=%00`，`stripslashes` 后仍是 NUL 字节；`trim("\0")` 返回 `''`，与未登录用户 `$current_user->user_pass`（null/空串）经 trim 后的 `''` 相等，第二个“invalid login”检查也被绕过。
- **空密码是前提**：未登录时 `wp_get_current_user()` 得到的用户对象 `user_pass` 为空；如果代码把 `$auth` 与 `$current_user->user_pass` 比较，攻击者只需要让 `$auth` trim 后也为空即可。若当前用户已登录且 `user_pass` 非空，该绕过不成立。
- **完整性校验也可满足**：第三个检查通常是 `md5($q . $current_user->user_pass) == $integ`；未登录时 `user_pass` 为空，攻击者只需计算 `integ = md5(trim($q))`，把 `integ` 与 `q` 一起提交，即可通过“防篡改”检查。
- **为什么这是通用模式**：很多 PHP 代码用 `trim($x)` 做空值/相等判断；一旦比较、`empty()`、`is_null()` 等被写进 trim 的参数，或 trim 后被与空值比较，就可能出现“非空输入却 trim 为空”的绕过。NUL、空格、制表符都能让 `trim($x)` 变空，而 `%00` 在多数 WAF/日志中不显眼。
- **边界**：PHP 8 对 `trim(null)` 有 deprecation 但结果仍是 `''`；如果代码使用 `trim($auth) === ''` 严格比较且未登录 `user_pass` 非空、或对 `%00` 做了拒绝，绕过不成立。该原语只负责通过认证判断，最终危害取决于后续 sink（SQL 执行、文件操作、命令执行等）。

## 触发条件

- PHP 应用中存在把比较表达式/布尔值传给 `trim()` 的认证判断，或 `trim($input)` 与空字符串/空 `user_pass` 做宽松比较。
- 未登录用户的密码字段为空（如 WordPress `$current_user->user_pass`），使 `trim($auth) == trim($user_pass)` 可用空串满足。
- 请求体允许 NUL 字节（`%00`）或仅含空白的值，且中间件没有拒绝/转义。
- 认证判断之后紧接危险 sink（如 `$wpdb->get_results($q)`、`include`、`eval`、`system`），否则只是一个无危害的逻辑绕过。

## 利用步骤

1. 代码审计：搜索 `trim(`、`wp_automatic_trim(`、`empty(` 等过滤函数，重点看参数里是否包含 `==`、`!=`、`empty`、`is_null` 等比较/判断表达式。
2. 还原判断逻辑：把比较表达式按 PHP 优先级展开，确认传入过滤函数的是布尔值还是字符串；用本地 PHP 片段验证 `trim(false)`、`trim(true)`、`trim("\0")` 的实际结果。
3. 构造绕过：在请求中给认证参数发送 `%00`（或空格/制表符），确认第一个“空值拒绝”不触发、第二个“与空 user_pass 比较”通过。
4. 通过完整性校验：若后续有 `md5($q . user_pass)` 类检查，按 `user_pass` 为空计算 `integ=md5(trim($q))` 并一起提交。
5. 验证下游 sink：确认绕过后的参数确实进入 SQL/文件/命令执行；若只是返回错误页，说明 sink 前还有其它校验。
6. 报告时给出最小 PoC（只发 `%00` 与必要的完整性字段），说明根因是括号错位 + trim 字符集，而非“弱口令”。

## PoC

最小 PHP 复现（模拟插件逻辑）：

```php
<?php
function wp_automatic_trim($str) {
    return is_null($str) ? '' : trim($str);
}
$auth = $_POST['auth'] ?? '';
$current_user = new stdClass();
$current_user->user_pass = null;   // 未登录用户

if (wp_automatic_trim($auth == '')) {        // 非空 auth -> false -> trim(false)='' -> 不退出
    echo 'login required'; exit;
}
if (wp_automatic_trim($auth) != wp_automatic_trim($current_user->user_pass)) {
    echo 'invalid login'; exit;             // auth="\0" -> trim 后 '' == '' -> 不退出
}
echo 'auth bypassed';
```

```http
POST /vulnerable.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

auth=%00
```

## 变体与关联

- **变体（空字符集）**：`auth=%20`（空格）、`%09`（Tab）、`%0B`（垂直制表）等所有被 `trim()` 默认删除的字符都可以让 `trim($auth)` 为空；NUL 只是最隐蔽的一种。
- **变体（比较位置）**：`if (trim($a != $b))`、`if (empty(trim($x)))`、`if (strlen(trim($x)) == 0)` 等写法需分别判断求值顺序；`trim` 之外的 `htmlspecialchars`、`intval`、`str_replace` 等也可能出现类似的“先比较后过滤”问题。
- **关联**：[[web-generic-sqli-wordpress-automatic-csv-unauth-cve-2024-27956]]（本原语作为 CVE-2024-27956 的认证绕过步骤）、[[web-generic-auth-php-loose-comparison-token-0e-bypass]]（PHP 宽松比较/0e 绕过）、[[web-generic-auth-php-md5-array-strict-comparison-bypass]]（MD5 比较的类型绕过）。
- **边界**：若 `$current_user->user_pass` 对未登录用户不是空值、或代码使用 `hash_equals`/严格比较/显式长度检查，原语失效；若请求层把 `%00` 截断或拒绝，需要改用空白字符。

## 检测与防御

- **代码审计/修复**：把 `if (trim($auth == ''))` 改为 `if ($auth === '')` 或 `if (strlen($auth) === 0)`；不要把比较表达式作为 trim/过滤函数参数；对认证值使用 `hash_equals` 严格比较。
- **输入处理**：拒绝或规范化 NUL 字节（`%00`）与控制字符；校验 `Content-Type` 与参数编码；WAF 规则可匹配 `%00`/裸 NUL，但不能只依赖 WAF。
- **检测信号**：认证接口收到 `auth=%00`、`auth=%20` 等仅含空白/NUL 的参数后返回成功；同一接口在无会话时访问成功；日志中出现 NUL 字节或异常编码。
- **纵深防御**：认证判断后不要直接拼接危险 sink；SQL 使用 `$wpdb->prepare`/参数化，文件/命令操作使用白名单；对未登录用户对象做显式空值处理。
