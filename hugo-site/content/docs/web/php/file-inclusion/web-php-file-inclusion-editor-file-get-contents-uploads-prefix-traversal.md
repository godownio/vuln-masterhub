---
id: web-php-file-inclusion-editor-file-get-contents-uploads-prefix-traversal
title: PHP 编辑器 file_get_contents("uploads/$file")：../ 穿越读取任意文件
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-editor-file-get-contents-uploads-prefix-traversal
tags:
- php
- file-inclusion
- path-traversal
- arbitrary-file-read
- file_get_contents
- uploads
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T12:35:37+08:00'
  notes: 已对照 editor.php 源码(图20：uploads/ 前缀 + file_get_contents 无过滤)与图16/12 的 ../../../../etc/passwd、init.sh 读取核对；api.key 请求在图17 返回 400、原文亦写无权限，已在卡内补注该 PoC 未读出；未复现。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-editor-file-get-contents-uploads-prefix-traversal/
draft: false
kb_aliases:
- editor.php 任意文件读取
- file_get_contents uploads 前缀穿越
- PHP 路径穿越读取
- dev.ouija.htb editor
- file=../../../../etc/passwd
---

## 一句话结论

内部站点的 `editor.php` 在 `isset($_GET['file'])` 时执行 `$url = "uploads/$filename"; echo file_get_contents($url);`，只在前面拼了 `uploads/` 前缀，没有 `realpath`、白名单或 `..` 过滤；提交 `file=../../../../etc/passwd` 即可跳出 uploads 目录读取服务器任意文件，本例用它读取 `init.sh`、`app.js` 与 `/etc/passwd`。

## 原理

- `file_get_contents` 按传入路径直接访问文件系统，不限制目录；`uploads/` 前缀只是字符串拼接，`../` 会逐级上跳，前缀目录再深也挡不住。
- 代码没有 `basename()`、`realpath()`、`str_contains($file, '..')` 或允许目录检查；读失败时还可能把错误信息/内容回显到页面。
- 该端点位于 dev 子域，前端 HAProxy 用 ACL 阻止外部访问；本例先通过 HAProxy 请求走私到达内部（见关联卡），再利用 editor 读文件，形成“ACL 绕过 + 任意文件读取”的链。
- PHP 的 `file_get_contents` 也支持 `php://filter`、`http://` 等包装器；若 `allow_url_fopen` 开启，还可能读取远程资源（但本场景以本地路径穿越为主）。

## 触发条件

- PHP 应用存在把用户输入拼进 `file_get_contents`/`readfile`/`fopen` 等文件读取函数的端点。
- 输入被拼到某个目录前缀后（如 `uploads/`），但没有规范化/白名单。
- Web 进程对目标文件有读权限；目标文件路径可通过 `../` 或绝对路径到达。
- 端点可访问（可能需要通过认证/代理绕过，本例通过请求走私）。

## 利用步骤

1. 找到编辑器/预览/下载端点，确认参数名（本例 `file`）。
2. 提交 `file=../../../../etc/passwd`，观察是否返回 `/etc/passwd` 内容；根据 `uploads/` 所在深度调整 `../` 数量。
3. 读取应用源码/配置（本例 `init.sh`、`app.js`）、密钥、日志、SSH 私钥等。
4. 若 `file_get_contents` 回显被截断，可改用 `php://filter/convert.base64-encode/resource=...`（需要输入允许该包装器）或分段读取。
5. 记录请求与响应作为证据。

## PoC

```http
GET /editor.php?file=../../../../etc/passwd HTTP/1.1
Host: dev.ouija.htb
```

```http
GET /editor.php?file=../../../../opt/auth/api.key HTTP/1.1
Host: dev.ouija.htb
```

注：原文该 api.key 请求返回 `400 Bad Request`，`/opt/auth/api.key` 实际未读出（权限/路径原因），此处仅作穿越到 `/opt` 的请求示例；成功读出的文件是 `init.sh`、`app.js` 与 `/etc/passwd`（原文截图）。

响应 HTML 的 `<textarea>` 中即文件内容（原文截图）。

```php
// 漏洞代码结构（原文）
if (isset($_GET['file'])) {
    $filename = $_GET['file'];
    $url = "uploads/$filename";
    echo file_get_contents($url);
}
```

## 变体与关联

- **其他包装器**：`php://filter/convert.base64-encode/resource=../../../../etc/passwd` 可避免二进制/编码问题；`data://`、`http://` 取决于 `allow_url_fopen`。
- **绝对路径**：若前缀后允许 `/`，可直接用 `/etc/passwd`；若过滤 `..`，尝试 URL 编码、双重编码、`....//` 等。
- **日志/临时文件**：结合日志注入或上传临时文件，可把文件读取升级为代码执行（`file_get_contents` 只读不执行，需配合 include）。
- 关联：[[web-generic-http-smuggling-haproxy-cve-2021-40346-content-length-overflow]]（本例绕过前端 ACL 到达 editor）、[[web-nodejs-fs-readfile-proc-symlink-filter-bypass]]（同一靶机的另一条任意文件读取链）。

## 检测与防御

- **代码**：使用 `basename()` 或固定文件 ID 映射；用 `realpath()` 规范化后检查是否位于允许目录内；拒绝 `..`、绝对路径、空字节与危险包装器；读取失败不要回显完整路径/内容。
- **配置**：`open_basedir` 限制到 Web 根；关闭不需要的 `allow_url_fopen`/包装器；编辑器/预览端点加认证与权限校验。
- **检测**：请求参数中出现 `../`、`%2e%2e`、`php://filter`、`/etc/passwd`、`id_rsa` 等；一次请求返回多行系统文件内容；dev/internal 站点的异常访问（结合请求走私检测）。
