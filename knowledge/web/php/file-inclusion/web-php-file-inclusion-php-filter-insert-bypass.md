---
id: web-php-file-inclusion-php-filter-insert-bypass
title: php://filter 在 filter 与 resource 之间插入编码过滤器，绕过 ter/res 关键字黑名单读源码
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-filter-wrapper-blacklist-insert-bypass
aliases:
- php://filter 黑名单绕过
- ter/res 拦截绕过
- convert.iconv 读取源码
- php 伪协议读取 gift.php
- filter 与 resource 之间插入过滤器
tags:
- php
- file-read
- php-filter
- wrapper
- waf-bypass
- blacklist
- source-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:47:36+08:00'
  notes: 已对照原文 gift.php 源码与图19核对：黑名单含 ter/res 且禁用 base64/string/rot13/quoted/zlib，放行 php://filter；payload php://filter/read=convert.iconv.UTF-8.UTF-7/resource=gift.php 在 filter 与 resource 之间插入过滤器打断 ter/res，并成功读回 gift.php 源码，与图19一致。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

当黑名单用 `ter/res` 这样的连续子串封堵 `php://filter/resource=`，同时又放行 `php://filter` 时，在 `filter` 与 `resource` 之间插入任意合法过滤器（如 `read=convert.iconv.UTF-8.UTF-7`）即可打断该子串，仍用 `file_get_contents()` 读回源码。

## 原理

- 应用把 `php://filter/resource=目标` 当作危险模式，黑名单里放的是 `ter/res`（覆盖 `filter/resource` 中 `filter` 尾部到 `resource` 头部的连续片段），而不是分别封禁 `filter` 与 `resource`。
- `php://filter` 的语法允许在 `filter` 与 `resource` 之间写一个或多个过滤器，例如 `php://filter/read=convert.iconv.UTF-8.UTF-7/resource=gift.php`。
- 插入过滤器后，字符串中不再出现连续的 `ter/res`：`filter` 后接 `/read=...`，`resource` 前是过滤器名，黑名单检查通过；而 PHP 的流包装器仍按语法解析出 `resource=gift.php` 并读取文件。
- `convert.iconv.UTF-8.UTF-7` 是合法过滤器，且不在 `base64`/`rot13`/`zlib`/`quoted` 等被禁编码过滤器之列；对以 ASCII 为主的 PHP 源码，转换后内容仍基本可读，足以泄露源码。
- 之所以成立：黑名单匹配的是“固定拼接形态”，而包装器语法允许多种等价写法；过滤器只检查了一个特定子串，没有按语法解析 URL。

## 触发条件

- 存在把用户输入传给 `file_get_contents`/`include` 等且允许 `php://` 包装器的入口；
- 校验使用 `FILTER_VALIDATE_URL` 或类似 URL 格式检查，`php://filter/...` 能通过；
- 黑名单只封禁了 `filter/resource` 的连续写法或常用编码过滤器，未封禁 `convert.iconv`；
- 目标文件可被 Web 进程读取（如与入口同目录的 `gift.php`）。

## 利用步骤

1. 先用 `php://filter/resource=index.php` 等确认包装器可用与黑名单反馈（本例会返回 waf）。
2. 在 `filter` 与 `resource` 之间插入 `read=convert.iconv.UTF-8.UTF-7`，提交 `file=php://filter/read=convert.iconv.UTF-8.UTF-7/resource=gift.php`。
3. 从响应中读取源码，定位后续利用点（本例源码中泄露了 `eval($_POST['m1xian'])` 与无参 RCE 校验）。
4. 若 `convert.iconv` 也被封禁，换其它未被禁的过滤器（如 `convert.base64-*` 之外的 `string.*`、`dechunk` 等，按黑名单调整）。
5. 结合源码中的新入口继续利用。

## PoC

```http
POST / HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

file=php://filter/read=convert.iconv.UTF-8.UTF-7/resource=gift.php
```

服务端校验的关键黑名单片段与等价逻辑：

```php
$blacklist = ['file','phar','zip','data','glob','expect','ftp','etc','proc',
              'base64','string','rot13','quoted','zlib','input','ter/res',
              'eval','system','exec','shell_exec','popen','passthru','echo'];
foreach ($blacklist as $keyword) {
    if (stripos($file, $keyword) !== false) { return false; }
}
if (filter_var($file, FILTER_VALIDATE_URL)) {
    echo @file_get_contents($file);
}
```

## 变体与关联

- 插入位置变体：`filter/read=convert.iconv.X.Y/resource=`、`filter/write=.../resource=`、多个过滤器串联；只要打断 `ter/res` 即可。
- 编码过滤器变体：`convert.iconv.UTF-8.UTF-16`、`convert.iconv.GBK.UTF-8` 等；被禁 `base64`/`rot13`/`zlib` 时优先考虑 iconv 家族。
- 关键字黑名单常见缺口：只封 `filter/resource` 不封 `filter/read=.../resource`；只封小写不封大小写混写；只封 `php://` 不封 `php://filter`。
- 关联：[[web-php-file-inclusion-iconv-ignore-dirty-byte-waf-bypass]]（iconv 归一化差异绕过）；[[web-php-file-inclusion-filter-chain-fileless-rce]]（filter 链构造 RCE）；[[web-php-rce-no-param-get-defined-vars]]（本例源码泄露后接的无参 RCE）。
- 影响边界：本例读取源码并据此获得后续 RCE；单独看是源码泄露，但常作为完整利用链的前置。

## 检测与防御

- 检测：请求中出现 `php://filter` 且 `filter` 与 `resource` 之间有 `read=`/`write=`/`convert.`；`ter/res` 黑名单命中日志后紧接 200 响应；Web 日志中对同目录 PHP 源码的读取。
- 修复：不要对用户输入使用 `file_get_contents`/`include`；必须读取时使用固定文件白名单与规范化后的真实路径，禁止 `php://` 等包装器。
- 缓解：按 URL 语法解析并校验 scheme/host/path，而不是匹配子串；同时封禁 `php://filter` 整体与 `convert.iconv`；限制 Web 进程对源码目录的读取权限。
