---
id: web-generic-file-inclusion-bosscms-backup-download-id-traversal-readfile
title: BossCMS 数据备份下载 id 直拼 SYSTEM_PATH/backup/sql/：../../ 穿越 readfile 下载 mysql.ini.php 泄露数据库凭据
type: scenario
domain: web
path: web/generic/file-inclusion
technique: bosscms-backup-download-id-path-traversal-readfile
tags:
- web
- php
- bosscms
- cms
- file-download
- arbitrary-file-read
- path-traversal
- credential-leak
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V638
  verified_at: '2026-11-13T02:11:52+08:00'
  notes: 已对照原文与截图核对：backup::download() 中 id 直拼 SYSTEM_PATH.'backup/sql/'、is_file+readfile 属实；id=../../basic/ini/mysql.ini.php 穿越下载 mysql.ini.php 泄露数据库凭据的抓包与响应属实（响应体在卡中按惯例脱敏为占位符）；affected_versions 已 clear（原文仅安装环境版本）。未复跑。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-bosscms-backup-download-id-traversal-readfile/
draft: false
kb_aliases:
- BossCMS 任意文件下载
- BossCMS 数据备份下载穿越
- backup download id 路径穿越
- readfile 下载 mysql.ini.php
---

## 一句话结论

BossCMS 后台“数据备份 → 备份列表 → 下载”的 `download()` 把 `$_GET['id']` 直接拼到 `SYSTEM_PATH.$this->sql`（`system/backup/sql/`）后面，仅用 `is_file()` 判存在就 `readfile()` 输出；提交 `id=../../basic/ini/mysql.ini.php` 即可穿越下载网站 `system/` 下的数据库配置文件，泄露数据库主机、账号、密码与库名。

## 原理

- **路径拼接**：`system/admin/safe/backup.class.php`（`class backup extends admin`，`$sql='backup/sql/'`）的 `download()` 中 `$file = SYSTEM_PATH.$this->sql.$_GET['id']`；`SYSTEM_PATH` 为 `ROOT_PATH.system/`。
- **校验缺位**：`id` 未做 `..`、绝对路径或 basename 过滤，只有 `is_file($file)` 存在性判断；`../` 会把读取点带出备份目录，且 `is_file` 对穿越后的真实路径同样返回真。
- **输出方式**：命中后设置 `Content-Type: application/octet-stream`、`Content-Disposition: attachment` 等头并 `readfile($file)`，文件内容原样回显在响应体。
- **凭据价值**：`system/basic/ini/mysql.ini.php` 以 PHP 数组/INI 形式保存数据库连接信息（host/port/user/password/database/prefix），拿到后可尝试直连数据库或复用口令横向。
- **鉴权**：backup 类继承 admin，`admin::init()` 未登录只 `header()` 跳转不退出，未授权也可调用（原文 PoC 带后台 Cookie，但结合鉴权缺陷可去掉）。

## 触发条件

- 目标可达 `/admin/?mold=safe&part=backup&func=download`。
- 目标文件在 `SYSTEM_PATH` 相对路径可达范围内（`../` 可继续向上越过站点根）。
- 目标文件对 PHP 进程可读；`open_basedir` 等限制之外。

## 利用步骤

1. 先通过目录遍历接口（如 ueditor `listfile`）确认 `system/` 下文件名，常见为 `basic/ini/mysql.ini.php`、备份 SQL 等。
2. 构造 `id`：从 `system/backup/sql/` 出发 `../../basic/ini/mysql.ini.php`。
3. 请求下载接口，响应体即目标文件内容（带 attachment 头）。
4. 用泄露的数据库账号密码尝试连接数据库，或寻找配置文件中的其它密钥。

## PoC

```http
GET /admin/?mold=safe&part=backup&func=download&id=../../basic/ini/mysql.ini.php HTTP/1.1
Host: target
```

响应头：

```http
Content-Type: application/octet-stream
Content-Disposition: attachment;filename = ../../basic/ini/mysql.ini.php
Accept-Ranges: bytes
```

响应体（结构示意，值为原文实验环境）：

```php
<?php
return <<<INI
host     = 127.0.0.1
port     = 3306
user     = <db_user>
password = <db_password>
database = <db_name>
prefix   = <table_prefix>
INI;
```

## 变体与关联

- `id` 可继续增加 `../` 读 Web 根之外的文件（需知道相对路径），等价于任意文件下载。
- 与 `admin::init` 的 header 无 exit 缺陷组合可未授权下载；配合 ueditor `listfile` 目录遍历可先列目录再下载。
- 与库内 CMS 备份下载卡（JFinalCMS、CMSV6 等）同类：参数拼路径 + 只判存在 + `readfile`；本卡的过滤只是“无过滤”，sink 为 `readfile`。

## 检测与防御

- 用 `basename()` 限制 `id` 只能是备份文件名，或先查备份表/白名单再按固定目录拼接。
- 下载前 `realpath()` 校验文件仍在备份目录内，拒绝 `..` 与绝对路径。
- 移动数据库配置文件到 Web 根之外并收紧权限；修复鉴权跳转不退出问题。
- 监控 `func=download` 参数中出现 `../` 的请求。
