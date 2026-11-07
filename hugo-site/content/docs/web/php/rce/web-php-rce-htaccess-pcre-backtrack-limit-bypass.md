---
id: web-php-rce-htaccess-pcre-backtrack-limit-bypass
title: .htaccess 将 pcre.backtrack_limit 置 0 使 preg_match 返回 false 绕过正则黑名单
type: scenario
domain: web
path: web/php/rce
technique: htaccess-pcre-backtrack-limit-regex-bypass
tags:
- php
- apache
- htaccess
- pcre
- waf-bypass
- preg-match
- logic-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:38:53+08:00'
  notes: 已对照原文与图18-20核对：源码 !preg_match("/[a-z0-9]/i", $preg) && $preg == "Pr0x1ma"；上传 php_value pcre.backtrack_limit 0 + pcre.jit 0 后 POST preg=Pr0x1ma 返回 success，与卡片一致。该卡为逻辑校验绕过原语，最终危害依赖后续业务 sink，原文未进一步利用；已在卡片利用步骤中如实限定。原文测试环境 PHP 8.5.0RC3/Apache 2.4.65，非受影响区间，未设置 versions。PoC 未在本机执行。
url: /docs/web/php/rce/web-php-rce-htaccess-pcre-backtrack-limit-bypass/
draft: false
kb_aliases:
- pcre.backtrack_limit
- pcre.jit 0
- preg_match 返回 false
- 正则回溯限制绕过
- 反向正则校验绕过
---

## 一句话结论

当应用把“正则没有匹配”作为放行条件（`!preg_match(...)`）时，可在 `.htaccess` 里把 `pcre.backtrack_limit` 设为 0、`pcre.jit` 设为 0，使 `preg_match()` 因回溯超限返回 `false`；`!false` 为真，任意本应被拦截的输入都能通过校验。

## 原理

- PHP 的 `preg_match()` 返回三种值：匹配为 `1`、不匹配为 `0`、出错（包括超过 `pcre.backtrack_limit`/递归限制、JIT 栈耗尽）为 `false`。
- 应用常见写法 `if (!preg_match("/[a-z0-9]/i", $input)) { /* 认为输入干净 */ }` 只区分“非 1”，把错误 `false` 也当成“没有危险字符”。当回溯限制为 0 时，任何需要回溯的匹配都直接失败返回 `false`，于是校验被绕过。
- `pcre.backtrack_limit`、`pcre.jit` 均为 `PHP_INI_ALL` 级别，mod_php 下可通过 `.htaccess` 的 `php_value` 修改；关闭 JIT 可避免 JIT 路径先于解释器返回其他结果。
- 前提是攻击者能写入 `.htaccess` 且所在目录 `AllowOverride` 允许 `FileInfo`/`Options` 等（或等价地能改 PHP 配置）。

## 触发条件

- Apache + mod_php，`.htaccess` 可写且生效；
- 应用用 `preg_match()` 的否定结果做放行判断，且没有显式判断 `=== 1`；
- 被校验的值仍需满足后续业务条件（本例同时还要求 `$preg == "Pr0x1ma"`），攻击者直接提交该值即可。

## 利用步骤

1. 确认可写 `.htaccess` 并能影响 PHP 配置（页面行为变化、`phpinfo` 或报错）。
2. 写入把 PCRE 限制归零的配置。
3. 提交原本会被正则拦截的输入，观察逻辑放行。
4. 结合具体业务达成越权/包含/命令执行。

## PoC

`.htaccess`：

```apache
php_value pcre.backtrack_limit 0
php_value pcre.jit 0
```

目标逻辑：

```php
$preg = $_POST['preg'];
if (!preg_match("/[a-z0-9]/i", $preg) && ($preg == "Pr0x1ma")) {
    echo "success";
}
```

请求：

```http
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

preg=Pr0x1ma
```

`preg_match` 因回溯限制返回 `false`，`!false` 成立，回显 success。

## 变体与关联

- 同类配置项：`pcre.recursion_limit`、`pcre.jit=0`；也可用 `ini_set()` 注入或 `.user.ini`（PHP_INI_PERDIR 范围内）。
- 代码层同类缺陷：`preg_match` 结果未与 `1` 比较；`strpos` 返回 0/false 混淆；`filter_var` 失败与 false 混淆。
- 与 `.htaccess` handler 覆盖、auto_prepend 等卡片同属“可写 .htaccess 即扩大攻击面”。
- 边界：如果代码写 `preg_match(...) === 1`、或用白名单正向校验，该手法失效；`AllowOverride None` 时无法改配置。

## 检测与防御

- 代码中正则校验必须写 `preg_match($re, $s) === 1` 或 `!== 1` 时拒绝，不能把 `false` 当“未匹配”。
- 不要用“没有匹配危险字符”作为安全边界，改用允许字符白名单与类型校验。
- 生产环境 `AllowOverride None`，禁止上传 `.htaccess`；监控 `.htaccess` 中出现 `pcre.`、`php_value`、`php_flag`。
- 在 `php_admin_value` 中固定 PCRE 限制，避免用户级配置覆盖；对 `preg_last_error()` 做错误处理。
