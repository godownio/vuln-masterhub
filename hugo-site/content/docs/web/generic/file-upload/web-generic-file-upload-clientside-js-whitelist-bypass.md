---
id: web-generic-file-upload-clientside-js-whitelist-bypass
title: 仅前端 JavaScript 校验上传后缀，禁用脚本、改包或断点修改白名单均可绕过
type: scenario
domain: web
path: web/generic/file-upload
technique: client-side-validation-bypass
tags:
- web
- file-upload
- client-side
- javascript
- burp
- whitelist-bypass
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:17+08:00'
  notes: 已对照原文与图02/03/07/10/11/13核对：checkfilesuffix 仅在浏览器端按 whitelist 校验，禁用 JS、Burp 改 filename、断点向 whitelist 加 .php 三种方式均可上传并连接蚁剑。卡中 curl 直接构造 multipart 与原文一致。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-clientside-js-whitelist-bypass/
draft: false
kb_aliases:
- 前端校验绕过
- JS 白名单绕过
- 禁用 JavaScript 上传木马
- 改包上传 php
- 断点修改 whitelist
---

## 一句话结论

上传页面的后缀白名单只写在浏览器端 JavaScript 的 `onsubmit` 回调里时，服务端不会再次校验；禁用 JS、用代理改 multipart 文件名或调试器篡改白名单变量，都能把 `.php` 等脚本送到后端落盘。

## 原理

- 页面表单使用 `<form ... onsubmit="return checkfilesuffix()">`，只有回调返回 `true` 才提交。校验函数从 `document.getElementsByName("file")[0].value` 取文件名，按最后一个点截取后缀，再与数组 `[".jpg",".png",".gif",".jpeg"]` 比较。
- 这段逻辑运行在浏览器内，属于“客户端输入过滤”，不是安全边界。任何不执行该 JS、或在执行前修改其输入的客户端都能跳过。
- 服务端收到 multipart 请求后直接按 `$_FILES` 中的文件名与临时文件保存，没有独立的白名单/内容校验，因此前端放行与否不影响最终落盘。
- 三种绕过分别对应三个信任假设：禁用 JS 假设“校验一定执行”；代理改包假设“请求一定由页面表单产生”；断点修改变量假设“白名单数组不可变”。三者都只影响客户端。

## 触发条件

- 上传接口的扩展名校验仅存在于前端 JS，抓包可见请求体中没有服务端签发的类型凭证。
- 服务端按用户文件名保存，且上传目录可被 Web 访问。
- 上传目录中的脚本后缀会被中间件解析（如 PHP + Apache）。

## 利用步骤

1. 查看页面源码，确认 `onsubmit` 调用前端校验函数，并读出白名单与取后缀方式。
2. 任选一种方式绕过：
   - 浏览器开发者工具设置中停用 JavaScript，再直接选择 `shell.php` 上传；
   - 先把木马命名为 `123.jpg` 通过前端校验，在 Burp 中把 multipart 的 `filename="123.jpg"` 改为 `filename="123.php"` 后放行；
   - 在“源代码”面板给校验函数下断点，上传 `x.php`，暂停时把 `whitelist` 数组追加 `".php"`，继续执行。
3. 从响应 HTML 的 `<img src="./upload/xxx.php">` 或上传成功提示中取得落地路径。
4. 访问该路径确认脚本执行，再用蚁剑等客户端连接。

## PoC

绕过前端最直接的方式是根本不经过浏览器，直接用 curl 构造 multipart：

```bash
curl -s -X POST 'http://target/upload.php' \
  -F 'file=@shell.php;filename=shell.php;type=image/jpeg' \
  -F 'submit=Upload'
```

`shell.php` 内容为最小一句话：

```php
<?php eval($_POST['cmd']); ?>
```

若页面还要求其他字段，按抓包结果补齐即可。成功时响应 HTML 会回显 `./upload/shell.php` 形式的路径。

## 变体与关联

- 变体：校验函数改用 `file.type`（MIME）或 `accept` 属性时，同样只影响浏览器，改包即可；若 JS 还计算文件大小/尺寸，也可在代理中改 `Content-Length` 或直接换文件。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]（服务端也只信 Content-Type）；[[web-generic-file-upload-weak-suffix-bypass]]（服务端仅按文件名后缀弱校验）。
- 边界：本卡只覆盖“前端校验、后端零校验”的组合；若后端还有独立白名单，需要继续用服务端侧绕过手法。

## 检测与防御

- 检测：上传请求的文件名后缀与 `Content-Type` 不匹配；同一会话短时间内出现被拒绝后缀的提交；上传目录出现脚本文件并被直接访问。
- 防御：把扩展名白名单、MIME/魔数校验和内容检测全部放到服务端；前端校验只作为体验优化；上传文件重命名为随机名并存储在 Web 根目录之外，或由独立域名/静态服务下发；对上传目录禁用脚本解析。
