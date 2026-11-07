---
id: web-generic-file-upload-ueditor-default-whitelist-xml-xss
title: UEditor 默认 fileAllowFiles 白名单包含 .xml，上传脚本文件导致同源存储型 XSS
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-whitelist-dangerous-extension
aliases:
- UEditor 任意文件上传
- UEditor uploadfile XSS
- fileAllowFiles 白名单过宽
- 上传 xml 存储型 XSS
- 富文本编辑器上传点
tags:
- web
- file-upload
- ueditor
- whitelist
- xss
- stored-xss
- xml
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:48:45+08:00'
  notes: 已对照原文与图 01-06 核对：controller.php 按 action 分发、fileAllowFiles 默认含 .xml、Uploader 仅按扩展名 in_array 校验、curl 上传 xss.xml 返回 SUCCESS 并访问后弹窗，均与原文一致；原文未说明服务端 MIME/浏览器类型，卡内已标注执行条件与影响边界；shell.php;.jpg 未验证链已如实排除。
---

## 一句话结论

UEditor 的 `controller.php?action=uploadfile` 使用 `config.json` 中的 `fileAllowFiles` 作为唯一类型校验，而该默认白名单包含 `.xml`、`.md`、`.txt` 等可承载浏览器脚本的类型；攻击者上传内容可控的 `xss.xml` 后访问其同源 URL，即可在受害浏览器中执行脚本，形成存储型 XSS。

## 原理

- 上传入口 `controller.php` 直接按 `$_GET['action']` 分发，`action=uploadfile`（也是未知 action 的 default 分支）加载 `action_upload.php`，并由 `Uploader.class.php` 处理文件。
- `Uploader::checkType()` 仅做 `in_array($this->getFileExt(), $this->config["allowFiles"])`；`getFileExt()` 用 `strrchr($this->oriName, '.')` 取原始文件名最后一个点后的部分。服务端不校验 MIME、不校验文件魔数、不解析文件内容。
- UEditor 默认 `fileAllowFiles` 同时包含图片、压缩包、Office 文档和 `.txt`、`.md`、`.xml`。其中 `.xml` 是浏览器可以当作标记文档直接渲染的类型：文档里的 `<script>` 或事件属性会按 HTML/XML 规则被解析，而不是像图片那样被当作二进制。
- 上传目录位于站点静态资源路径下（如 `/static/ueditor/php/upload/file/...`），文件从同源 URL 直接访问，没有 `Content-Disposition: attachment` 隔离，脚本因此拿到同源执行上下文。
- 之所以成立：应用把“扩展名在白名单内”等同于“文件安全”，但白名单本身混入了可执行前端语义的类型；同源托管又消除了跨域隔离。

## 触发条件

- 目标站点暴露 UEditor 的 `controller.php`（常见路径 `/static/ueditor/php/controller.php`、`/ueditor/php/controller.php`），且 `uploadfile` 动作对匿名或低权限用户开放；
- `config.json` 的 `fileAllowFiles` 仍包含 `.xml`（默认配置即如此），或包含 `.html`、`.svg` 等浏览器可渲染类型；
- 上传目录可被 Web 直接访问，且服务器对 `.xml` 返回可渲染的 MIME（`text/xml`、`application/xml`）或按 `text/html` 兜底；
- 目标浏览器会执行 XML 文档中的脚本（不同浏览器/版本行为存在差异，需实测）。

## 利用步骤

1. 从泄露的目录树、静态资源探测或 `/ueditor/php/controller.php?action=config` 确认 UEditor 路径与 `fileAllowFiles`。
2. 准备内容可控的 XML/XHTML 文件，扩展名使用白名单内的 `.xml`。
3. 以 `action=uploadfile`、表单字段名 `upfile`（默认 `fileFieldName`）提交 multipart 请求。
4. 从响应 JSON 的 `url` 字段取得落地地址（文件名常按 `{time}{rand:6}` 规则生成）。
5. 诱导受害者或管理员访问该同源 URL，脚本在站点源下执行；可进一步读取同源页面、窃取会话相关数据或发起带凭据请求。

## PoC

```bash
curl -X POST "http://target/static/ueditor/php/controller.php?action=uploadfile" \
  -F 'upfile=@xss.xml;type=text/xml'
```

`xss.xml` 最小内容示例（实际能否执行取决于浏览器对 XML 的脚本处理与服务端 MIME）：

```xml
<?xml version="1.0"?>
<html xmlns="http://www.w3.org/1999/xhtml">
<body><script>alert(document.domain)</script></body>
</html>
```

成功响应形如：

```json
{"state":"SUCCESS","url":"/static/ueditor/php/upload/file/20260605/1749100000000.xml","title":"xss.xml","original":"xss.xml","type":".xml","size":135}
```

访问响应中的 `url` 验证脚本是否执行。若 XML 未被浏览器执行，可检查服务器是否将该后缀按 `text/html` 返回，或改用白名单中其他可渲染类型测试。

## 变体与关联

- 变体：白名单存在 `.html`/`.svg`/`.htm` 时直接上传 HTML/SVG；`catchimage` 动作抓取远程图片，可测试 SSRF；`uploadscrawl` 走 base64 写入，字段名与路径格式不同。
- 关联：[[web-generic-file-upload-weak-suffix-bypass]]（白名单/后缀校验本身可被改名绕过）；[[web-generic-file-upload-extension-zero-check]]（完全不校验扩展名时可直接落地脚本）；XSS 同源利用见 `web/generic/xss`。
- 影响边界：文章演示的是上传 `xss.xml` 后弹窗成功，但未说明服务端返回的 MIME 与浏览器类型，因此“必然执行”不成立；若服务器对 `.xml` 强制下载或浏览器不执行 XML 内脚本，危害退化为任意文件托管/信息泄露。
- 注意区分：原文提出的 `shell.php;.jpg` 分号解析 webshell 链并未验证，仅在特定服务器（如部分 IIS/Apache 配置）下可能成立，不应按已验证结论使用。

## 检测与防御

- 检测：上传目录出现 `.xml`、`.html`、`.svg` 等非业务必需类型的新文件；同一来源短时间对 `controller.php?action=uploadfile` 的批量请求；访问日志中对刚上传文件的直接浏览。
- 防御：收紧 `fileAllowFiles`，移除 `.xml`、`.md` 等可渲染/可执行类型；服务端增加文件头魔数与内容解析校验；上传文件重命名为随机无后缀名称；上传目录使用独立域名或 `Content-Disposition: attachment`、`X-Content-Type-Options: nosniff` 隔离；删除未使用的 UEditor 示例/测试目录。
