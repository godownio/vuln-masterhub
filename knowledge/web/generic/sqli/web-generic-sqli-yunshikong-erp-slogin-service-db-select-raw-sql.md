---
id: web-generic-sqli-yunshikong-erp-slogin-service-db-select-raw-sql
title: 云时空ERP /slogin/service?service=db.select 未授权原始 SQL 执行：params 内 sql 直入 executeQuery，非 SELECT 还走 {call} 拼接
type: scenario
domain: web
path: web/generic/sqli
technique: erp-slogin-service-db-select-raw-sql-unauth
aliases:
- service=db.select
- LoginServiceDispatcher SQL 注入
- DBServiceImpl.select
- 云时空 ERP SQL 注入
- 未授权通用 SQL 查询接口
- db.uniqueValue
tags:
- web
- sqli
- java
- erp
- unauth
- shiro
- servlet
- json
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T16:57:48+08:00'
  notes: 已对照原文与图01-05核对：shiroFilterChainDefinitions中/slogin/service*=anon(图01)、web.xml映射LoginServiceDispatcher(图02)、service=db.select分发(图03)、sql字段startsWith SELECT直入executeQuery/否则'{call '+sql+'}'走CallableStatement registerOutParameter(1,-10)(图04)、Burp实测返回用户JSON(图05)均一致。修正:包名emsem->emscm(图02实为com.ysk360.emscm.form)、删除无原文依据的mssql标签。与Artery ERP workflow.sqlResult为同设计模式不同产品/端点，非同链；dup-scan无相关pair。原文未标受影响版本。
---

## 一句话结论

云时空 ERP 的 Shiro 配置把 `/slogin/service*` 设为 `anon`，该路径由 `LoginServiceDispatcher` 处理；当 `service=db.select` 时，`DBServiceImpl.select` 从请求 JSON 中取出 `sql` 字段，仅判断是否以 `SELECT` 开头就直接 `executeQuery(sql)`，未做参数化与过滤，未登录攻击者可查询任意业务数据；代码中非 SELECT 分支还会把输入拼进 `{call <sql>}` 交给 CallableStatement，构成第二个注入面。

## 原理

- **入口暴露**：`shiroFilterChainDefinitions` 定义 `/slogin/service* = anon`，Shiro 对该路径不做认证；`web.xml` 把 `/slogin/service` 映射到 `com.ysk360.emscm.form.LoginServiceDispatcher`，因此未登录请求可直达 servlet。
- **服务分发**：`LoginServiceDispatcher#service` 读取请求参数 `service`，非空时按值分发：`db.uniqueValue` → `DBServiceImpl.uniqueValue`，`db.select` → `DBServiceImpl.select`。这类“用参数选择后端方法”的通用服务入口常被遗漏鉴权。
- **原始 SQL 执行**：`select(request, response)` 用 `FormUtils.toJsonParam(request)` 把请求参数转成 JSON，取 `sql` 字段；`_sql = sql.trim().toUpperCase()`，随后：
  - `_sql.startsWith("SELECT")` → `db.getStatement().executeQuery(sql)`，`sql` 原样进入数据库；
  - 否则 → `db.getCallStmt("{call " + sql + "}")`，`registerOutParameter(1, -10)` 后 `execute()`——同样是把可控字符串拼接进存储过程调用。
- 仅检查前缀既不构成白名单也无法阻止注入：`SELECT` 语句内可继续写 UNION/子查询/函数；非 SELECT 分支的 `{call}` 拼接则可能执行存储过程。
- 响应会把 `ResultSet` 的列名与数据组装成 JSON 返回，攻击者可完整读取查询结果。

## 触发条件

- 目标使用该 ERP 版本，Shiro 配置中存在 `/slogin/service* = anon`；
- `web.xml` 将 `/slogin/service` 映射到 `LoginServiceDispatcher`；
- 后端 `DBServiceImpl.select` 可达且数据库账号具备相应查询权限。

## 利用步骤

1. 未登录访问 `POST /slogin/service?service=db.select`；
2. 请求体使用表单参数 `params`，其值为 JSON 字符串，如 `params={"sql":"select ..."}`；
3. 服务端返回 JSON 结果集，可构造任意 `SELECT` 查询（如读取 `sys_user` 表的账号与口令字段、数据库版本等）；
4. 若目标数据库/驱动允许，可尝试非 SELECT 分支的 `{call ...}` 形式（原文代码可见该分支，但未给出该分支的实际回显验证，置信度低于 SELECT 分支）；
5. 结合返回的列名继续做 UNION/多表查询，扩大数据读取范围。

## PoC

```http
POST /slogin/service?service=db.select HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

params={"sql":"select * from sys_user"}
```

原文截图显示该请求返回 200 与包含用户数据的 JSON（用户名列被部分打码）。非 SELECT 分支示意：`params={"sql":"proc_name(...)"}` 会被拼成 `{call proc_name(...)}`。

## 变体与关联

- 同入口的其他方法：`service=db.uniqueValue` 走 `DBServiceImpl.uniqueValue`，应检查是否同样拼接执行 SQL；
- 同类通用 FormService/`service=` 分发入口：与库内 Artery ERP `workflow.sqlResult` 未授权 SQL 注入（`/formservice?service=workflow.sqlResult`，JSON `sql` → `executeQuery`）属于同一设计模式的不同产品/端点，参数包装（`params` JSON）与非 SELECT 的 `{call}` 分支是本例差异；
- 常见变体：关键字前缀/黑名单绕过、通过注释/大小写/编码构造 SELECT 开头，或直接利用非 SELECT 分支。

## 检测与防御

- 禁止把用户输入作为 SQL 文本执行：通用查询服务改为固定查询模板 + 参数绑定，或直接下线 `db.select` 这类调试/通用接口；
- Shiro 配置最小化 anon 列表，定期审计 `/slogin/service*` 等匿名路径并做未授权访问测试；
- 对 `service` 分发器增加登录与角色校验，限制 `DBServiceImpl` 仅被内部可信调用；
- WAF/数据库审计监控 `executeQuery` 入参中的 UNION、子查询、系统表名与存储过程调用特征。
