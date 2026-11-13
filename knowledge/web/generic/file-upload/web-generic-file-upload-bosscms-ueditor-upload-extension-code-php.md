---
id: web-generic-file-upload-bosscms-ueditor-upload-extension-code-php
title: BossCMS ueditor 附件上传白名单取自可配置 upload_extension：加入 .php 后经 code 分组校验落盘 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: bosscms-ueditor-upload-extension-code-php-upload
aliases:
- BossCMS 任意文件上传
- BossCMS ueditor 上传 php
- upload_extension 添加 php
- ueditor uploadfile code 分组
- BossCMS 编辑器附件上传
tags:
- web
- php
- bosscms
- cms
- ueditor
- file-upload
- webshell
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V638
  verified_at: '2026-11-13T02:11:33+08:00'
  notes: 已对照原文全文与 61 张本地图核对：安装页仅显示 V1.3.0（安装环境版本，affected_versions 已 clear）；白名单取自可配置 upload_extension、extension.json code 分组、uploadfile() 传 code 分组、上传 .php 后 /upload/code/202211/152319429.php phpinfo 复现均属实；示例落盘 URL 已按截图修正；站点设置入口并入本卡、admin 鉴权缺陷另卡关联；dedup 为 new 非同链。未复跑。
---

## 一句话结论

BossCMS 的 ueditor 附件上传最终调用 `upload::files($file, $path, 'code|zip|word|excel|powerpoint|audio|text|pdf')`，允许后缀取自站点“安全设置”里可编辑的 `upload_extension` 配置；当管理员（或利用未授权访问的后台设置）把 `.php` 加入允许上传类型后，后缀同时命中白名单和 `extension.json` 的 `code` 分组，附件上传即可把 PHP 文件写入 `upload/code/` 并被执行，形成任意文件上传 getshell。

## 原理

- **白名单来源可控**：`system/basic/class/upload.class.php` 的 `files()` 中，`$extension = json::decode($G['config']['upload_extension'])`，而 `upload_extension` 是后台“安全设置”页面（safe 模块）里的一个可编辑列表（textarea，提交为 JSON 数组，如 `["jpg",".png",...,".php"]`）。上传校验的第一层就是“上传文件后缀是否在这个配置列表里”。
- **分组校验依赖调用方传入的 type**：`extension.json` 把后缀按 `code/zip/word/photo/excel/movie/...` 分组，`code` 组内包含 `.php`。`files()` 在 `$type` 非空时按 `|` 拆出被允许的分组，若上传后缀属于其中某个分组，就把 `$type` 置空放行（`in_array($ext,$extension) && (!$type || ($type && !$in))`）。
- **只有附件上传传入了 code 分组**：`system/extend/ueditor/php/ueditor.class.php` 中，`uploadimage()` 调 `upload::files(..., 'photo')`，`uploadvideo()` 调 `... 'movie'`，而附件上传 `uploadfile()`（约 246/270 行）调 `... 'code|zip|word|excel|powerpoint|audio|text|pdf'`。因此同一份白名单下，图片上传传 `.php` 会被拒，附件上传传 `.php` 则因 `code` 分组在 type 中而通过。
- **落盘与执行**：`files()` 校验通过后 `move_uploaded_file` 到 `ROOT_PATH.upload/code/年+月/随机名.php`，返回可直接访问的 URL；Web 服务器对 upload 目录下 `.php` 正常交给 PHP-FPM 解析，访问即执行。
- **鉴权不构成阻碍**：ueditor 控制器继承 admin 类，而 `admin::init()` 未登录时只 `header()` 跳登录页、不 `exit/die`，请求仍会走到 `uploadfile()`（见关联卡），所以附件上传接口可在不带有效会话的情况下调用。

## 触发条件

- 站点“安全设置 → 允许上传类型”中存在 `.php`（默认列表不含 php，但该列表可在后台编辑；结合 admin 鉴权缺陷也可未授权修改）。
- 目标可达 `/system/extend/ueditor/php/controller.php`（或编辑器附件弹窗 `dialogs/attachment/attachment.html`）。
- upload 目录（至少 `upload/code/`）对 Web 服务器可解析 PHP；`file_uploads` 开启、大小不超过 `upload_maxsize`。
- 需要走附件上传入口（`action=uploadfile`/附件弹窗），走图片上传不会命中 code 分组。

## 利用步骤

1. 进入后台“安全设置”，在“允许上传类型”中加入 `php` 并保存；若 admin 鉴权可绕过（见关联卡），直接抓保存请求在未登录状态提交。
2. 打开任意带编辑器的功能点（如站点设置里的富文本编辑器），点“上传附件/在线附件”，选择 `.php` 文件上传；或直接构造附件上传请求。
3. 从响应 JSON 的 `url` 字段取得落盘路径，例如 `../upload/code/202211/152319429.php`。
4. 访问该 URL，PHP 代码执行；如需稳定控制可换成一句话/冰蝎等载荷。

## PoC

附件弹窗上传（multipart，字段名以弹窗表单为准；核心是 `upfile` 文件和形如 `uploadfile` 的提交）：

```http
POST /system/extend/ueditor/dialogs/attachment/attachment.html HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="upfile"; filename="x.php"
Content-Type: application/octet-stream

<?php phpinfo();?>
------X--
```

响应回显落盘地址：

```json
{"state":"SUCCESS","url":"..\/upload\/code\/202211\/152319429.php"}
```

随后 `GET /upload/code/202211/151910429.php` 即执行。（原文用 phpinfo 验证；此处不复跑。）

## 变体与关联

- 同一 sink 还有“站点设置里上传”的入口，源码追踪同样落到 `ueditor.class.php` 的 `uploadfile()` → `upload::files(..., 'code|...')`，与附件弹窗是同一漏洞的不同入口。
- 与 `admin::init` 的 header 无 exit 缺陷组合后，整个链可未授权完成（先未授权改允许类型，再未授权上传）；见 `web-generic-auth-bosscms-admin-init-header-no-exit`。
- 与库内其它 ueditor 卡（filePathFormat 目录穿越、.NET catchimage、默认 fileAllowFiles 含 xml）机制不同：本卡是“站点配置的可编辑白名单 + code 分组放行 php”。

## 检测与防御

- 服务端固定允许后缀集合，不把可执行后缀开放为后台可配置项；`code` 这类分组不应参与 Web 可访问目录的上传校验。
- upload 目录禁止 PHP 解析（Nginx `location ~ \.php$ { deny all; }` 或独立静态域），上传文件统一重命名并剔除可执行后缀。
- 审计 `upload_extension` 配置是否被非管理员修改；监控编辑器上传接口出现 `.php` 后缀的请求。
- 修复鉴权：未登录跳转后必须 `exit/die`，避免上传接口被未授权调用。
