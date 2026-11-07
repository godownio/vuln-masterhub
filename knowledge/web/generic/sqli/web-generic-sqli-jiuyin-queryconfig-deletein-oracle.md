---
id: web-generic-sqli-jiuyin-queryconfig-deletein-oracle
title: 九垠赢系统 QueryConfig/DeleteIn 参数拼接导致 Oracle 删除型 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: dotnet-oracle-delete-in-concat-sqli
aliases:
- 九垠赢 SQL 注入
- QueryConfig DeleteIn 注入
- SYS_CXZDPZ 删除注入
- DeleteInQueryConfig
- Oracle delete in 拼接注入
tags:
- dotnet
- aspnet
- oracle
- sql-injection
- delete-injection
- code-audit
- webinvoke
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 九垠赢系统 前端 6.8.0.46149 / 后端 6.8.0.8666（原文标记）
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:08:10+08:00'
  notes: 已通读原文并逐张核对23张图：web.config DAL=WRM.OracleDAL、dnSpy 中 QueryConfig.DeleteIn(pCode) 将 pCode 直拼 delete from SYS_CXZDPZ/SYS_CXPZ where CXBM in(...)、BLL DeleteIn(pIDs)→GetCodeForID→dal.DeleteIn、API SystemDataService.DeleteInQueryConfig 的 WebInvoke POST System/QueryConfig/DeleteIn 与 sys 父路由、api/web.config FrontServicePort=9003，均与卡一致；实测 POST /sys/System/QueryConfig/**** {"Code":"-99999||dbms_utility.sqlid_to_sqlhash(user)"} 返回 ORA-13797/ORA-06512，与卡内 PoC 一致。文内'完整路由/sys/System/DialogConfig/xxxxx'为原文笔误，卡按实际请求用 QueryConfig 正确。受影响版本原文明确（前端6.8.0.46149/后端6.8.0.8666），已设置。frontmatter 无 sources/source_url；未在本机复跑，未测试破坏性 payload。
---

## 一句话结论

`WRM.OracleDAL.QueryConfig.DeleteIn(string pCode)` 把外部传入的 `pCode` 直接拼进 `delete from SYS_CXZDPZ where CXBM in(<pCode>)` 与 `SYS_CXPZ` 两条 DELETE 语句，BLL 与 API 一路透传到 `POST /sys/System/QueryConfig/DeleteIn` 的 `Code` 参数；攻击者可构造 `-99999||dbms_utility.sqlid_to_sqlhash(user)` 等 Oracle 表达式触发错误回显，证明 SQL 注入，且可进一步改写 WHERE 条件删除全部数据。

## 原理

- DAL 层 `DeleteIn` 使用 `StringBuilder.Append("delete from SYS_CXZDPZ where CXBM in(" + pCode + ")")` 和同样形式的 `SYS_CXPZ` 语句，最后交给 `OracleHelper.ExecuteSqlTran` 执行；`pCode` 没有任何参数化/转义。
- BLL 层 `WRM.BLL.QueryConfig.DeleteIn(string pIDs)` 先调用 `QueryConfig.dal.GetCodeForID(pIDs, true)` 生成 `codeForID`，再传给 DAL；`GetCodeForID` 只做 ID 到代码的映射/加引号，并不消除 SQL 元字符，攻击者仍可闭合 `in(...)`。
- API 层 `WRM.API.SystemDataService.DeleteInQueryConfig(string Code)` 标注了 `[WebInvoke(Method="POST", UriTemplate="System/QueryConfig/DeleteIn", BodyStyle=WrappedRequest, ResponseFormat=Json)]`，父级路由为 `sys`，完整路径为 `/sys/System/QueryConfig/DeleteIn`；请求体 JSON 的 `Code` 直接进入 BLL。
- 由于语句是 DELETE 且 `pCode` 位于 `in()` 内，注入可改变 WHERE 条件（如闭合括号后接 `OR 1=1`），造成整表/多表删除；Oracle 还可用 `dbms_utility.sqlid_to_sqlhash`、`utl_inaddr.get_host_address`、`dbms_xmlgen` 等函数做错误回显/OOB 数据外带。
- 原文 POC 用 `-99999||dbms_utility.sqlid_to_sqlhash(user)` 触发 `ORA-13797: 指定了无效的 SQL ID` 与 `ORA-06512: 在 SYS.DBMS_UTILITY`，说明数据库实际执行了注入表达式，而不是简单语法错误。

## 触发条件

- 目标为受影响版本的九垠赢系统，后端 API 通过 9003 端口暴露（原文 `FrontServicePort=9003`；将端口改为 9003 后才适用该 POC）。
- `/sys/System/QueryConfig/DeleteIn` 路由可达；原文 POC 未携带认证头即返回 200/数据库错误，说明该接口在测试环境可未授权访问（实际环境需确认认证/网络边界）。
- 数据库为 Oracle，且连接账号对 `SYS_CXZDPZ`/`SYS_CXPZ` 有 DELETE 权限（业务账号通常有）。
- 注入点为 DELETE，测试时务必使用只读/报错函数，避免误删生产数据。

## 利用步骤

1. 确认 API 端口（默认/配置 9003）与路由：`POST /sys/System/QueryConfig/DeleteIn`。
2. 发送 JSON：`{"Code":"<payload>"}`，`Content-Type: application/json`。
3. 先用无误删风险的表达式验证注入：`-99999||dbms_utility.sqlid_to_sqlhash(user)`，观察响应是否出现 Oracle 错误（ORA-13797/ORA-06512）。
4. 进一步用 `dbms_xmlgen`/`utl_inaddr` 等做错误回显或 DNSLog 外带；若目标是数据删除，可构造 `-99999) OR 1=1--` 之类的 WHERE 改写（**仅在授权测试环境，且明确知道会删除数据时使用**）。
5. 记录注入点与 DB 账号权限，评估是否能读取其他表或执行 PL/SQL 包。

## PoC

```http
POST /sys/System/QueryConfig/DeleteIn HTTP/1.1
Host: 127.0.0.1:9003
Content-Type: application/json

{"Code":"-99999||dbms_utility.sqlid_to_sqlhash(user)"}
```

```text
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"status":"error","code":"-1","msg":"数据删除出现异常,请稍后再试。异常 ORA-13797: 指定了无效的 SQL ID。\nORA-06512: 在 \"SYS.DBMS_UTILITY\", line 1298"}
```

说明：该 payload 只让数据库求值一个函数并报错，不修改数据；破坏性 payload 不在此列出。

## 变体与关联

- 变体：同一 `DeleteIn` 会依次执行 `SYS_CXZDPZ` 与 `SYS_CXPZ` 两条 DELETE，注入可在第一条报错/成功后影响第二条。
- 变体：`GetCodeForID(pIDs, true)` 的映射逻辑若对输入做了部分拼接，可尝试用逗号、引号、括号闭合绕过；具体取决于 `pIDs` 的预期格式。
- 变体：Oracle 错误回显被关闭时，改用时间盲注（`dbms_pipe.receive_message`/`dbms_lock.sleep`）或 DNSLog（`utl_inaddr.get_host_address`）外带。
- 关联：[[web-generic-sqli-error-based-extraction]]（错误回显提取）、[[web-generic-sqli-dnslog-oob-exfiltration]]（OOB 外带）、[[web-generic-sqli-mssql-stacked-xp-cmdshell]]（对比：MSSQL 堆叠语句）。
- 边界：若 DAL 使用绑定变量、或 API 层对 `Code` 做了严格数字/逗号白名单，本注入不成立；原文 POC 仅证明函数求值，未展示数据提取/删除的实际结果。

## 检测与防御

- 检测：API 访问日志中出现 `/sys/System/QueryConfig/DeleteIn` 且 `Code` 含 `||`、`dbms_`、`utl_`、`OR 1=1`、注释符等；数据库审计出现 `DELETE ... WHERE ... IN (...)` 异常语法/错误；应用返回 ORA- 错误。
- 修复：DAL 改用 Oracle 绑定变量/参数化查询，`IN` 列表按元素逐个绑定；对 `Code` 做严格格式校验（仅允许预期 ID/代码字符集与长度）；BLL/API 层加白名单。
- 加固：数据库账号最小权限，禁止业务账号对系统配置表执行无条件 DELETE；关闭详细数据库错误回显（`customErrors=On`、统一错误页）；限制 9003/API 端口的网络访问与认证；WAF 仅作补充。
