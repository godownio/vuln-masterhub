---
id: web-generic-sqli-java-identifier-table-order-by-injection
title: JDBC/MyBatis 标识符位置注入：表名与 ORDER BY 列名无法预编译时的拼接注入
type: scenario
domain: web
path: web/generic/sqli
technique: identifier-position-sqli
tags:
- sqli
- java
- jdbc
- mybatis
- order-by
- identifier-injection
- whitelist
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:45:08+08:00'
  notes: 已对照原文核对：JDBC占位符不能绑定FROM表名/ORDER BY列名、拼接即标识符注入，白名单防御与原文一致；原名称为综述，卡片为可复用技术整理。原文无组件受影响版本，未设versions；未执行PoC
url: /docs/web/generic/sqli/web-generic-sqli-java-identifier-table-order-by-injection/
draft: false
kb_aliases:
- 表名注入
- ORDER BY 注入
- order by 列名注入
- 标识符位置 SQL 注入
- 不可预编译关键字注入
- from 表名拼接注入
---

## 一句话结论

表名、列名、`ORDER BY` 字段属于 SQL 结构而不是数据值，JDBC 占位符 `?` 不能绑定它们；一旦把用户输入直接拼进这些位置，输入无需逃逸引号就会被当作 SQL 语法解析，形成标识符位置注入。

## 原理

预编译把 SQL 语句结构与参数数据分开：`?` 只替换“值”的位置，数据库在预编译阶段已经确定语句功能，参数内容始终按数据字面量处理。但 `FROM` 后面的表名和 `ORDER BY` 后面的列名是语句模板的一部分，`?` 不能出现在这些语法位置，`prepareStatement("SELECT * FROM ?")` 会直接报错。

开发者为了让表名/排序列可配置，只能改成字符串拼接：

```java
String sql = "SELECT * FROM " + tableName + " WHERE username = 'Alice'";
String sql = "SELECT * FROM users ORDER BY " + orderByColumn;
```

拼接发生在 SQL 解析之前，用户输入因此进入语法层，而不是值层。这里不需要闭合引号：`ORDER BY` 后可直接接表达式、子查询或函数；表名位置可接 `UNION SELECT`、括号子查询等，具体可用语法取决于拼接点前后的 SQL 结构。因为数据库把整段当成合法语句执行，布尔/时间/报错盲注都可在此建立。

## 触发条件

- 表名、列名、排序字段、`GROUP BY` 字段等标识符来自请求参数、配置或数据库元数据，且未做白名单校验；
- 代码为支持动态表/动态排序，把标识符拼进 SQL 模板并交给 `Statement`（或 MyBatis `${}` 等文本替换）；
- 参数位置不是值上下文，常规的引号转义/预编译参数无法覆盖；
- 攻击者能控制该标识符输入。

## 利用步骤

1. 定位动态表名或排序参数：请求中出现 `table=`、`orderBy=`、`sort=`、`column=`、`sortField=` 等，响应排序结果随参数变化。
2. 判断上下文：表名位置先尝试同义合法表名，确认参数确实进入 `FROM`；排序位置用 `ORDER BY 1`、`ORDER BY 2` 递增，观察报错边界判断列数。
3. 构造盲注/报错表达式：MySQL 可用 `IF(条件,SLEEP(2),0)`、`(SELECT ...)`、`extractvalue()`/`updatexml()`；表名位置可尝试括号子查询或 `UNION SELECT`。
4. 用布尔差异或响应时间确认可执行，再按常规 SQL 注入提取数据。
5. 在 MyBatis 中对照 `${tableName}`、`${sortColumn}` 的文本替换点，确认污点从 Controller 到 Mapper 未被白名单截断。

## PoC

```sql
-- 原始语句
SELECT * FROM users ORDER BY <input>

-- 排序位置布尔/时间盲注（MySQL）
<input> = IF(SUBSTR(database(),1,1)='a',SLEEP(2),0)
<input> = (SELECT 1 FROM (SELECT SLEEP(2))x)

-- 表名位置拼接（示意，需按前后语法调整）
<input> = users UNION SELECT 1,username,password FROM admin
```

```java
// 不安全：标识符直接拼接
String sql = "SELECT * FROM " + tableName + " WHERE username = 'Alice'";
Statement st = con.createStatement();
st.executeQuery(sql);

// 安全：业务白名单，只允许已知表名/列名
Set<String> allowed = Set.of("users", "orders", "products");
if (!allowed.contains(tableName)) throw new IllegalArgumentException("invalid table");
String sql = "SELECT * FROM " + tableName + " WHERE username = ?";
PreparedStatement ps = con.prepareStatement(sql);
ps.setString(1, "Alice");
```

## 变体与关联

- 排序位置变体：`ORDER BY` 后接 `IF()`、`CASE WHEN`、子查询、`extractvalue()` 报错；也可用 `ORDER BY 1,2,...` 判断列数后接 `UNION`。
- 标识符种类：表名、列名、`GROUP BY`、`HAVING` 中的动态字段、动态 schema 名，均不可用 `?` 绑定。
- MyBatis 对应写法为 `${tableName}` / `${sortColumn}`（见 MyBatis `${}` 卡片）；Hibernate 原生 SQL 与 HQL 中同样是字符串拼接。
- 关联：普通值位置的 JDBC `Statement` 拼接注入；白名单缺失是两类场景共同根因。

## 检测与防御

- 防御：对标识符使用业务白名单（固定集合或正则 `^[A-Za-z0-9_]+$` 且再比对已知集合），绝不把原始输入直接拼接；不要用引号包裹表名/列名来“修复”，那只会改变语法而不阻止注入。
- 预编译只用于值位置；标识符位置必须走白名单映射（如前端传 `sort=name`，后端映射到固定列名）。
- 检测：审计 SQL 字符串中出现 `FROM " +`、`ORDER BY " +`、`GROUP BY " +` 等拼接；检查 MyBatis `${}` 是否用于表名/排序字段；对排序参数变化引发的响应时间/报错差异做监控。
- 测试：对 `orderBy`/`table` 参数做布尔与时间盲注探测；确认白名单外的值被拒绝而不是被转义后仍执行。
