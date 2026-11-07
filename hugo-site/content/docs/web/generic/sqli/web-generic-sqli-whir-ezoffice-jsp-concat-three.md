---
id: web-generic-sqli-whir-ezoffice-jsp-concat-three
title: 万户OA 三处 JSP 拼接 SQL 注入：statDate/numId/RecordID 直入查询
type: scenario
domain: web
path: web/generic/sqli
technique: whir-ezoffice-jsp-string-concat-sqli
tags:
- web
- sqli
- java
- oa
- whir
- ezoffice
- jsp
- string-concat
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:24+08:00'
  notes: 已对照原文与 img24-28 核对：checkwork_httprequest.jsp 的 statDate（及同文件其他分支）、govdocumentmanager_judge.jsp 的 numId、DocumentSave.jsp 的 RecordID 均为字符串拼接进入 executeQuery；原文未给出实际注入回显，未复跑。
url: /docs/web/generic/sqli/web-generic-sqli-whir-ezoffice-jsp-concat-three/
draft: false
kb_aliases:
- 万户OA SQL 注入
- ezOFFICE checkwork_httprequest.jsp 注入
- govdocumentmanager_judge.jsp 注入
- DocumentSave.jsp 注入
- statDate numId RecordID 拼接
---

## 一句话结论

万户OA 多处老式 JSP 直接把请求参数拼接进 SQL：`checkwork_httprequest.jsp` 的 `statDate`/`userId`、`govdocumentmanager_judge.jsp` 的 `numId`、`DocumentSave.jsp` 的 `RecordID` 均未经预编译进入查询/更新语句；配合鉴权绕过可未登录执行任意 SQL，读取业务数据或进一步提权。

## 原理

- 系统部分代码使用 Hibernate 封装（`Dbutil extends HibernateBase`），但大量老 JSP 仍用自写 JDBC/`DbOpt`/`DBAccess` 直拼：
  1. `hospital/checkwork/checkwork_httprequest.jsp`：`statDate = request.getParameter("statDate")`，`userId = session.getAttribute("userId")`；`sql = "select count(id) from oa_checkwork_monthcheck where monthsets='" + statDate + "' and status='1' and checkerid=" + userId + ""`，`DbOpt.executeQueryToStr(sql)` 执行。同文件的 `checkdisplayname` 分支把 `disname` 拼进 `classdisplayname='...'`，`checkchecker` 分支把 `baseId`/`checkerId`/`scopeIds` 拼进 `where id<>...`。
  2. `govoffice/gov_documentmanager/govdocumentmanager_judge.jsp`：`numId = request.getParameter("numId")`，`numStr = "select keyValue from gov_senddocumentNum where id=" + numId`，随后 `stmt.executeQuery(numStr)`；同文件还把 `field2`、`recordId` 拼进 `strSql`。
  3. `DocumentSave.jsp`：`mRecordID = request.getParameter("RecordID")`，`mysql = "SELECT RecordID from pdfDocument Where RecordID=" + mRecordID + ""`，`DbaObj.ExecuteQuery(mysql)`；随后 update 语句同样拼接 `RecordID='...'`。
- 这些 JSP 位于 `/defaultroot/` 下，未登录时被 `SetCharacterEncodingFilter` 拦截，但可用其三种鉴权绕过（特征路径穿越、XFF 白名单、`.jsp;.js`）直接访问。
- 数据库支持 Oracle/SQL Server/MySQL；拼接点未做类型转换/转义，字符串/数字上下文均可注入。

## 触发条件

- 目标为万户OA/ezOFFICE，相关 JSP 存在且可访问。
- 能使用任一鉴权绕过路径到达 JSP（见关联卡）。
- 数据库账户有对应查询/更新权限；错误/回显可用于判断注入结果。
- `checkwork_httprequest.jsp` 需 `type=checkStatDate`（或其他分支参数）进入拼接分支。

## 利用步骤

1. 用鉴权绕过前缀访问 JSP，如 `/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../hospital/checkwork/checkwork_httprequest.jsp`。
2. 传 `type=checkStatDate&statDate=1'` 等测试闭合，观察报错/计数变化。
3. 按数据库类型构造布尔/时间/UNION 注入；数字型参数（numId/RecordID）直接拼 `and 1=1`、`union select ...`。
4. 读取用户表、配置表、口令哈希等；若账户高权限，可尝试堆叠/存储过程（视数据库与驱动）。
5. 记录请求、响应差异与数据库类型证据；控制数据读取范围。

## PoC

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../hospital/checkwork/checkwork_httprequest.jsp?type=checkStatDate&statDate=1%27 HTTP/1.1
Host: target
```

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../govoffice/gov_documentmanager/govdocumentmanager_judge.jsp?numId=1 HTTP/1.1
Host: target
```

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../DocumentSave.jsp?RecordID=1 HTTP/1.1
Host: target
```

原文仅给出路由、参数与代码拼接点，未给出完整注入 payload/回显；实际按目标数据库调整闭合与注释符。

## 变体与关联

- 变体：同一 JSP 的其他分支（`checkdisplayname`、`checkchecker`、`field2`/`recordId`）也拼接；可逐个测试。
- 变体：鉴权绕过可换成 `X-Forwarded-For: localhost` + `/xfservices/GeneralWeb../../...` 或 `/admin.jsp;.js`。
- 关联：鉴权绕过 [[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]；通用 JSP 拼接注入 [[web-generic-sqli-fe-system-jdbc-concat-treexml-editflow]]、[[web-generic-sqli-jhsoft-tasktreejson-id-concat]]。
- 边界：相关 JSP 被删除/改为预编译、数据库低权限且无回显时，危害受限；原文未提供实际注入结果。

## 检测与防御

- 检测：请求参数出现单引号、`and`/`or`、`union`、`sleep`、`waitfor delay` 等；同一 IP 对多个 JSP 参数高频探测；数据库错误信息回显。
- 修复：所有 JSP 改用 `PreparedStatement`/参数绑定；数字型参数先做类型转换与白名单；避免在 JSP 中写 SQL。
- 加固：清理老 JSP 入口或统一迁移到框架；数据库账户最小权限；关闭详细错误回显；WAF 仅作辅助，不能替代参数化。
