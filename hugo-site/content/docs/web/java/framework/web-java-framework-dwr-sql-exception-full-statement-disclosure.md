---
id: web-java-framework-dwr-sql-exception-full-statement-disclosure
title: DWR 未授权方法调用触发 SQL 异常：BadSqlGrammarException/MySQLSyntaxErrorException 回显完整 SQL 语句与表列名
type: scenario
domain: web
path: web/java/framework
technique: dwr-sql-exception-statement-schema-disclosure
tags:
- java
- dwr
- sql-exception
- information-disclosure
- error-leak
- schema-leak
- spring-jdbc
- mysql
- recon
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:49:14+08:00'
  notes: 已对照原文与图07/08/09核对：getUnApprovedUnitItemResourceListById传string:88888/77777/666666/1999999触发org.springframework.jdbc.BadSqlGrammarException，localizedMessage回显bad SQL grammar[SELECT fgir.*,...]（07）；getApprovedUnitItemResourceCountById传resource_module_id:1122222触发MySQLSyntaxErrorException Unknown column 'fgir.resource_module_id' in 'on clause'并回显SELECT COUNT(*)（08）；SRC判存在信息泄露已确认（09）。卡明确其为信息泄露而非注入、WAF使注入未打通，与原文总结一致。dedup除自身外候选均related（DWR debug/exec、typed-param注入、JDBC反序列化），非同链；dup-scan与16515 related。未验证点：未复跑请求；原文未给版本，未设affected_versions；frontmatter无sources/source_url。
url: /docs/web/java/framework/web-java-framework-dwr-sql-exception-full-statement-disclosure/
draft: false
kb_aliases:
- DWR SQL 异常回显
- BadSqlGrammarException 泄露完整 SQL
- MySQLSyntaxErrorException Unknown column
- DWR 报错信息泄露表列
- dwr.engine.remote.handleException
---

## 一句话结论

通过 DWR 的 `plaincall` 未授权调用暴露的业务方法并传入任意/类型不匹配的参数，若方法内部把参数拼进 SQL，DWR 会把未捕获的 `BadSqlGrammarException`、`MySQLSyntaxErrorException` 以 `dwr.engine.remote.handleException` 回调原样返回给客户端，其中 `localizedMessage` 携带**完整 SQL 语句**、`message` 携带数据库报错（如 `Unknown column 'fgir.resource_module_id' in 'on clause'`），从而在无法直接注入（WAF 拦截）时仍能获得数据库类型、表别名、列名和查询结构。

## 原理

- DWR 的默认异常处理会把服务端抛出的异常序列化成 JS 回调 `dwr.engine.remote.handleException("<batchId>","<callId>",{javaClassName:"...", localizedMessage:"...", message:"..."})`，目的是让前端能展示错误；只要应用没有把 DWR 的异常转换关掉、也没有全局异常处理器把它改写成通用错误页，异常细节就会直接到达匿名请求者。
- Spring JDBC 的 `BadSqlGrammarException` 在 `getMessage()`/`localizedMessage` 中会带上前置的 SQL：`PreparedStatementCallback; bad SQL grammar [<完整 SQL>]`；MySQL JDBC 驱动对语法/列名错误抛 `com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException`，`message` 为 `Unknown column '...' in 'on clause'` 或 `You have an error in your SQL syntax...`。两者叠加正好把「SQL 文本 + 表别名 + 列名 + 数据库类型」三样一起泄露。
- 触发不需要合法业务参数：`getUnApprovedUnitItemResourceListById` 这类方法按其方法名猜参数，传 `string:88888`、`string:77777` 等任意值即可让 SQL 里的条件/关联失败；把参数值换成一个并不存在的列名（原文用 `resource_module_id` 作为参数名传入）会直接得到 `Unknown column`。这也说明方法内部没有做参数白名单。
- 这类回显是「注入前置情报」而非注入本身：原文在发现参数被代入 SQL 后尝试构造注入，但敏感关键字被 WAF 拦截，最终只以信息泄露定级；因此在有 WAF 的场景，SQL 异常的稳定回显比盲注更值得先拿 schema。
- 之所以算独立问题而不是普通 SQLi：攻击者没有改变 SQL 语义，只是让正常查询以异常结束，泄露的是应用自身的查询文本与数据库结构；它的危害是信息泄露与后续精准注入的跳板。

## 触发条件

- 目标为 Java + Spring JDBC/MyBatis 应用，且存在可匿名/低权限调用的 DWR 方法，方法参数最终进入 SQL（拼接或作为列名/表名参与查询）。
- DWR 返回的是未包装的异常：`dwr.xml` 未配置异常转换过滤、无全局 `@ControllerAdvice`/`HandlerExceptionResolver` 统一改写错误，或当前环境为开发/调试配置。
- 请求方能构造合法 DWR 报文（`plaincall` 或 `exec` 均可），并按方法名/参数个数传入任意值。
- 数据库错误信息未被应用层吞掉（部分框架会包装成业务错误码，此时泄露面收窄）。

## 利用步骤

1. 从 `/dwr/interface/*.js` 或 `/dwr/test/<类>` 取得类名、方法名与参数个数。
2. 对疑似查数据库的方法（`get*List`、`get*ById`、`get*Count`、`find*`）先传合法形态的值观察响应是否为数据行或异常。
3. 依次传入不同数量/类型的任意参数（`string:`、`number:`），让查询在语法/列名/类型转换处失败，读取响应里的 `javaClassName`、`localizedMessage`、`message`。
4. 从 `bad SQL grammar [ ... ]` 中提取完整 SQL：表名/别名、JOIN 条件、WHERE 列、排序字段；从 `Unknown column` 中确认实际列名与别名映射。
5. 把得到的表列信息用于后续注入或越权查询；若 WAF 拦注入关键字，保留异常回显作为信息泄露提交，并记录可复现的最小请求。
6. 换方法重复，逐步拼出目标库的表结构。

## PoC

```http
POST /dwr/xxx/dwrtest.findByUserId.dwr HTTP/1.1
Host: target
Content-Type: text/plain
Content-Length: 352

callCount=1
windowName=
c0-scriptName=GlobalController
c0-methodName=getUnApprovedUnitItemResourceListById
c0-param0=string:88888
c0-param1=string:77777
c0-param2=string:666666
c0-param3=string:1999999
c0-id=0
batchId=1
instanceId=0
page=%2FDwrProject%2Fdwr%2Ftest%2Fdwrtest
scriptSessionId=<任意>
```

```text
# 响应（节选，表名/列名原文打码）
s0.suppressed=1;
dwr.engine.remote.handleException("1","0",{
  SQLException:s0,cause:s0,
  javaClassName:"org.springframework.jdbc.BadSqlGrammarException",
  localizedMessage:"PreparedStatementCallback; bad SQL grammar [SELECT fgir.*, f... e, fm... i, ...]",
  ...
});
```

```text
# 第二个方法：Unknown column 泄露列名与完整 COUNT 查询
javaClassName:"com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException"
message:"Unknown column 'fgir.resource_module_id' in 'on clause'"
localizedMessage:"PreparedStatementCallback; bad SQL grammar [SELECT COUNT(*) \n\tFROM fl... resource... ]"
```

## 变体与关联

- 变体：`dwr.engine.remote.handleException` 也出现在 `exec` 端点；返回格式可能是 XML（`xml=true`）或 JS 回调，解析时按 `javaClassName`/`localizedMessage` 提取即可。
- 变体：MyBatis 场景常见 `org.mybatis.spring.MyBatisSystemException`/`PersistenceException`，同样可能携带 SQL 与参数映射信息；PostgreSQL/Oracle 的错误消息会给出不同的列名/语法提示。
- 关联：`[[web-java-framework-dwr-plaincall-interface-js-unauth-config-leak]]` 提供枚举方法与构造报文的入口；`[[web-generic-sqli-dwr-typed-param-injection-point]]` 是在同一注入点上继续做盲注/时间注入的后续利用。
- 边界：全局异常处理器返回统一错误码、DWR 配置了 exception converter 过滤、数据库账号无权限导致错误被包装时，无法获得 SQL 原文，只能靠响应差异判断；异常回显本身不构成注入。

## 检测与防御

- 检测：响应体出现 `dwr.engine.remote.handleException`、`javaClassName`、`BadSqlGrammarException`、`MySQLSyntaxErrorException`、`bad SQL grammar [`；同一 DWR 方法被传入大量非常规参数并短时间重复请求。
- 修复：DWR 层关闭异常细节回传（配置异常转换/统一异常包装），全局异常处理器对外只返回通用错误码；生产关闭 `debug`。
- 加固：业务方法参数做类型/长度白名单，SQL 使用预编译与列名映射白名单；数据库账号最小权限；WAF 对异常堆栈特征与 `bad SQL grammar` 响应告警。
